"""Print da página pública de cada fonte (ex.: abuseipdb.com/check/<IP>).

Como funciona:
  * a captura é feita só quando o usuário pede (botão "Print da página"), então
    equivale a ele mesmo abrir a página uma vez — respeitando os limites de
    visualização dos planos gratuitos;
  * o IOC Check abre a página numa janela visível do Edge (ou Chrome), com um
    perfil próprio guardado em instance/navegador;
  * se o site exibir uma verificação humana (CAPTCHA/Cloudflare), o IOC Check
    NÃO tenta contorná-la: espera o próprio usuário resolvê-la na janela e, quando
    a página real carrega, tira o print e fecha a janela. Os cookies ficam no
    perfil, então as próximas capturas costumam passar direto. O usuário também
    pode fazer login no site nessa janela, se quiser o print da versão logada.
"""

import hashlib
import io
import json
import shutil
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from flask import current_app

from ..models import QueryLog, iso, utcnow
from . import settings

# Só abrimos páginas das próprias fontes (o link vem do resultado da verificação)
ALLOWED_HOSTS = {
    "www.virustotal.com",
    "www.abuseipdb.com",
    "threatfox.abuse.ch",
    "www.hybrid-analysis.com",
    "urlscan.io",
    "ipinfo.io",
}
# Sinais das telas de verificação humana (Cloudflare e afins), em português e inglês.
# Usamos frases específicas para não confundir com páginas normais que citam "captcha".
BLOCK_TITLES = ("um momento", "just a moment", "attention required", "checking your browser")
BLOCK_PHRASES = ("confirme que é humano", "executando verificação de segurança", "verify you are human",
                 "performing security verification", "checking your browser", "verificando seu navegador")
HUMAN_WAIT_SECONDS = 180  # tempo para o usuário resolver a verificação na janela
MAX_HEIGHT = 2400  # páginas muito longas são cortadas para o print continuar legível
VIEWPORT = {"width": 1366, "height": 900}

# Esconde (sem aceitar nem recusar) avisos de cookies fixos que cobririam o conteúdo no print
HIDE_COOKIE_BANNERS = """() => {
    for (const el of document.querySelectorAll('body *')) {
        const style = getComputedStyle(el);
        if ((style.position === 'fixed' || style.position === 'sticky') && /cookie/i.test(el.innerText || '')
            && el.innerText.length < 1500) {
            el.style.setProperty('display', 'none', 'important');
        }
    }
}"""

_lock = threading.Lock()


class CaptureError(Exception):
    pass


class CaptureBusy(CaptureError):
    pass


def _dir(name):
    # CAPTURE_ROOT permite apontar para outra pasta (os testes usam uma temporária)
    path = Path(current_app.config.get("CAPTURE_ROOT") or current_app.instance_path) / name
    path.mkdir(parents=True, exist_ok=True)
    return path


def _slug(provider):
    return "".join(c if c.isalnum() else "-" for c in provider.lower()).strip("-")


def files(log_id, provider):
    """Arquivos do print, guardados por consulta do histórico + fonte."""
    base = _dir("capturas") / f"h{int(log_id)}_{_slug(provider)}"
    return base.with_suffix(".png"), base.with_suffix(".json")


def legacy_files(indicator, provider):
    """Formato antigo (por indicador), usado só para migrar prints já existentes."""
    key = hashlib.sha1(indicator.encode("utf-8")).hexdigest()[:16]
    base = _dir("capturas") / f"{key}_{_slug(provider)}"
    return base.with_suffix(".png"), base.with_suffix(".json")


def _parse(moment):
    try:
        return datetime.fromisoformat(str(moment).rstrip("Z"))
    except ValueError:
        return None


def _ttl():
    """Os prints valem pelo mesmo tempo do cache (Configurações → Prazos, padrão 24h)."""
    return timedelta(hours=settings.get("cache_ttl_hours"))


def info(log_id, provider):
    """Metadados do print desta fonte nesta consulta (ou None)."""
    png, meta = files(log_id, provider)
    if not png.exists() or not meta.exists():
        return None
    data = json.loads(meta.read_text("utf-8"))
    data["image"] = f"/api/capture/{log_id}.png?provider={provider}"
    captured = _parse(data.get("captured_at"))
    if captured:
        expires = captured + _ttl()
        data["expires_at"], data["expired"] = iso(expires), expires <= utcnow()
    return data


def captures_for(log_id, providers):
    return {p: c for p in providers if (c := info(log_id, p))}


def reuse_recent(log_id, indicator, providers):
    """Como o cache: um print da mesma página tirado dentro do prazo é reaproveitado.

    O arquivo é copiado para a consulta nova, então o histórico dela fica completo
    mesmo que a consulta antiga seja excluída. A data original da captura é mantida
    e o prazo continua contando a partir dela.
    """
    cutoff = utcnow() - _ttl()
    previous = (QueryLog.query.filter(QueryLog.indicator == indicator, QueryLog.id != log_id,
                                      QueryLog.queried_at >= cutoff)
                .order_by(QueryLog.id.desc()).limit(100).all())
    for provider in providers:
        if info(log_id, provider):
            continue
        for old in previous:
            data = info(old.id, provider)
            captured = _parse(data.get("captured_at")) if data else None
            if captured and captured >= cutoff:
                src_png, src_meta = files(old.id, provider)
                dst_png, dst_meta = files(log_id, provider)
                shutil.copyfile(src_png, dst_png)
                meta = json.loads(src_meta.read_text("utf-8"))
                meta["reused_from"] = meta.get("reused_from") or old.id
                dst_meta.write_text(json.dumps(meta, ensure_ascii=False), "utf-8")
                break
    return captures_for(log_id, providers)


def delete_for(log_ids):
    """Apaga os prints das consultas removidas do histórico."""
    folder = _dir("capturas")
    for log_id in log_ids:
        for path in folder.glob(f"h{int(log_id)}_*"):
            path.unlink(missing_ok=True)


def clear_all():
    for path in _dir("capturas").glob("*"):
        if path.is_file():
            path.unlink(missing_ok=True)


def is_allowed(url):
    parts = urlsplit(str(url or ""))
    return parts.scheme == "https" and parts.hostname in ALLOWED_HOSTS


def is_challenge(title, body):
    title, body = (title or "").lower(), (body or "")[:3000].lower()
    return any(t in title for t in BLOCK_TITLES) or any(p in body for p in BLOCK_PHRASES)


def _blocked(page):
    try:
        return is_challenge(page.title(), page.inner_text("body"))
    except Exception:  # página ainda carregando
        return True


def _launch(playwright):
    """Abre o navegador instalado (Edge, depois Chrome) com o perfil do IOC Check."""
    profile = str(_dir("navegador"))
    errors = []
    for channel in ("msedge", "chrome", None):
        try:
            return playwright.chromium.launch_persistent_context(
                profile, channel=channel, headless=False, viewport=VIEWPORT, locale="pt-BR",
            )
        except Exception as exc:  # navegador ausente: tenta o próximo
            errors.append(f"{channel or 'chromium'}: {exc.__class__.__name__}")
    raise CaptureError("Nenhum navegador compatível encontrado (Edge ou Chrome). " + "; ".join(errors))


def _crop(png_bytes):
    from PIL import Image

    image = Image.open(io.BytesIO(png_bytes))
    if image.height <= MAX_HEIGHT:
        return png_bytes
    buffer = io.BytesIO()
    image.crop((0, 0, image.width, MAX_HEIGHT)).save(buffer, format="PNG")
    return buffer.getvalue()


def capture(log_id, provider, url):
    """Abre a página da fonte, espera ela liberar e salva o print. Bloqueia até terminar."""
    if not is_allowed(url):
        raise CaptureError("Endereço não permitido para captura")
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise CaptureError("Componente de captura não instalado: execute o iniciar.bat novamente "
                           "ou 'pip install playwright'") from None
    if not _lock.acquire(blocking=False):
        raise CaptureBusy("Já existe uma captura em andamento; aguarde ela terminar")

    try:
        with sync_playwright() as playwright:
            context = _launch(playwright)
            try:
                page = context.pages[0] if context.pages else context.new_page()
                page.goto(url, wait_until="domcontentloaded", timeout=45000)
                deadline = time.time() + HUMAN_WAIT_SECONDS
                needed_human = False
                while True:
                    try:
                        page.wait_for_load_state("networkidle", timeout=8000)
                    except Exception:
                        pass
                    if not _blocked(page):
                        break
                    needed_human = True
                    page.bring_to_front()
                    if time.time() > deadline:
                        raise CaptureError("A verificação do site não foi concluída a tempo. "
                                           "Tente de novo e clique em \"Confirme que é humano\" na janela que abrir.")
                    time.sleep(2)
                time.sleep(2)  # tempo para gráficos e fontes terminarem de desenhar
                page.evaluate(HIDE_COOKIE_BANNERS)
                png = _crop(page.screenshot(full_page=True))
                title = page.title()
                final_url = page.url
            finally:
                context.close()
    finally:
        _lock.release()

    image_path, meta_path = files(log_id, provider)
    image_path.write_bytes(png)
    meta = {"provider": provider, "url": final_url, "title": title, "captured_at": iso(utcnow()),
            "needed_human": needed_human}
    meta_path.write_text(json.dumps(meta, ensure_ascii=False), "utf-8")
    return info(log_id, provider)
