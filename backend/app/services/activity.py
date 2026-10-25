"""Registro de atividades exibido na tela Logs.

Três categorias:
  * acao    — o que o usuário fez (verificar, cadastrar IOC, exportar, salvar configurações...);
  * api     — cada chamada às APIs das fontes: endereço, parâmetros, código HTTP, tempo
              de resposta e o começo da resposta recebida;
  * sistema — início e encerramento do servidor.

Segurança: os cabeçalhos das requisições (onde ficam as chaves) nunca são gravados, e
qualquer valor de chave de API configurada que apareça no texto é mascarado.

Durante uma requisição os registros ficam em memória (flask.g) e são gravados ao
final dela, numa transação própria, sem misturar com as alterações da rota.
"""

import json
import time
from urllib.parse import urlsplit

from flask import g, has_request_context

from ..extensions import db
from ..models import AppLog
from . import settings

KEEP = 5000  # registros mantidos; os mais antigos são apagados
SNIPPET = 3000  # caracteres guardados de cada resposta das APIs
MASK = "•••"


def _secrets():
    values = []
    for pid in settings.PROVIDER_IDS:
        try:
            value = settings.get(f"{pid}_api_key")
        except Exception:  # fora de contexto do app
            value = None
        if value and len(value) >= 6:
            values.append(value)
    return values


def scrub(text, secrets=None):
    """Mascara chaves de API que apareçam no texto."""
    text = str(text)
    for secret in secrets if secrets is not None else _secrets():
        text = text.replace(secret, MASK)
    return text


def _entry(category, action, message, level, source, status, duration, details):
    secrets = _secrets()
    return AppLog(
        category=category,
        action=action[:60],
        message=scrub(message, secrets)[:2000],
        level=level,
        source=(source or "")[:40],
        status_code=status,
        duration_ms=duration,
        details_json=scrub(json.dumps(details, ensure_ascii=False, default=str), secrets) if details else None,
    )


def log(category, action, message, level="info", source="", status=None, duration=None, details=None):
    entry = _entry(category, action, message, level, source, status, duration, details)
    if has_request_context():
        g.setdefault("activity_logs", []).append(entry)
    else:
        db.session.add(entry)
        db.session.commit()


def flush():
    """Grava os registros da requisição (chamado no fim de cada requisição)."""
    entries = g.pop("activity_logs", None) if has_request_context() else None
    if not entries:
        return
    db.session.add_all(entries)
    db.session.commit()
    last = entries[-1].id or 0
    if last and last % 100 == 0:  # de vez em quando, apaga os mais antigos
        AppLog.query.filter(AppLog.id <= last - KEEP).delete(synchronize_session=False)
        db.session.commit()


def action(area, message, level="info", **details):
    log("acao", area, message, level=level, source=area, details=details or None)


# --- Chamadas às APIs das fontes ------------------------------------------------

def _body(response):
    text = getattr(response, "text", None)
    if text is None:
        try:
            text = json.dumps(response.json(), ensure_ascii=False)
        except Exception:
            text = ""
    return str(text)


def api_call(provider_id, method, url, kwargs, started, response=None, error=None):
    duration = int((time.perf_counter() - started) * 1000)
    parts = urlsplit(url)
    request = {"method": method.upper(), "url": f"{parts.scheme}://{parts.netloc}{parts.path}"}
    if kwargs.get("params"):
        request["params"] = kwargs["params"]
    if kwargs.get("json") is not None:
        request["body"] = kwargs["json"]
    if kwargs.get("data") is not None:
        request["body"] = kwargs["data"]
    target = f"{request['method']} {parts.netloc}{parts.path}"

    if error is not None:
        log("api", "chamada", f"{target} → falha de conexão ({error.__class__.__name__}) em {duration} ms",
            level="erro", source=provider_id, duration=duration,
            details={"requisicao": request, "erro": str(error)[:500]})
        return

    status = getattr(response, "status_code", None)
    headers = getattr(response, "headers", None) or {}
    body = _body(response)
    if status and status < 300 or status == 404:
        level = "info"
    elif status == 429:
        level = "aviso"
    else:
        level = "erro"
    log("api", "chamada", f"{target} → HTTP {status} em {duration} ms", level=level, source=provider_id,
        status=status, duration=duration,
        details={
            "requisicao": request,
            "resposta": {
                "status": status,
                "tipo": headers.get("Content-Type") or headers.get("content-type"),
                "tamanho": len(body),
                "limite": {k: v for k, v in headers.items()
                           if "ratelimit" in k.lower() or "rate-limit" in k.lower() or k.lower() == "retry-after"},
                "conteudo": body[:SNIPPET] + ("…" if len(body) > SNIPPET else ""),
            },
        })
