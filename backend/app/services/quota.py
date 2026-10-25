"""Controle de cota das fontes externas.

Todas as chaves usadas são de planos gratuitos, que têm limites rígidos
(o VirusTotal, por exemplo, aceita 4 consultas por minuto e 500 por dia).
Este módulo:

  1. conta as chamadas feitas a cada fonte, por minuto e por dia (UTC);
  2. lê os cabeçalhos de limite que cada API devolve (consumo real da conta);
  3. pausa a fonte quando ela responde "limite atingido" (HTTP 429), até o
     horário indicado em Retry-After, em vez de continuar insistindo.

Os contadores ficam no banco (tabela provider_quota), então sobrevivem a
reinicializações do servidor.
"""

import json
from datetime import datetime, timedelta, timezone

from ..extensions import db
from ..models import ProviderQuota, iso, utcnow

# Limites dos planos gratuitos. Onde a fonte não publica um número (fair use),
# usamos um limite próprio conservador.
FREE_LIMITS = {
    "virustotal": {"minute": 4, "day": 500},  # API pública: 4/min e 500/dia
    "abuseipdb": {"day": 1000},  # conta gratuita: 1.000 consultas/dia
    "threatfox": {"minute": 60},  # "fair use", sem número publicado
    "hybrid_analysis": {"minute": 200},  # chave "restricted": 200/min e 2.000/hora
    "urlscan": {"minute": 60},  # cada verificação faz até 2 chamadas
    "mxtoolbox": {"day": 64},  # conta gratuita: 64 consultas DNS/dia e 0 de rede (zera 0h UTC)
    "ipinfo": {"minute": 60},  # IPinfo Lite: gratuito e sem limite publicado; limite próprio
}
LIMIT_LABEL = {"minute": "min", "hour": "hora", "day": "dia"}
DEFAULT_PAUSE = timedelta(minutes=1)


def _today():
    return utcnow().strftime("%Y-%m-%d")


def _next_utc_midnight():
    now = utcnow()
    return datetime(now.year, now.month, now.day) + timedelta(days=1)


def _row(provider_id):
    row = db.session.get(ProviderQuota, provider_id)
    if row is None:
        row = ProviderQuota(provider=provider_id, day=_today(), day_calls=0, window_calls=0)
        db.session.add(row)
    if row.day != _today():
        row.day, row.day_calls = _today(), 0
    if row.window_start is None or utcnow() - row.window_start >= timedelta(minutes=1):
        row.window_start, row.window_calls = utcnow(), 0
    return row


def limits_text(provider_id):
    limits = FREE_LIMITS.get(provider_id, {})
    return ", ".join(f"{n}/{LIMIT_LABEL[w]}" for w, n in limits.items())


def check(provider_id):
    """Devolve None se a fonte pode ser chamada agora, ou o motivo da pausa."""
    row = _row(provider_id)
    limits = FREE_LIMITS.get(provider_id, {})
    if row.blocked_until and row.blocked_until > utcnow():
        until = row.blocked_until.replace(tzinfo=timezone.utc).astimezone()
        return f"Limite gratuito atingido; nova tentativa liberada às {until:%H:%M} ({until:%d/%m})"
    if limits.get("minute") and row.window_calls >= limits["minute"]:
        return f"Limite gratuito de {limits['minute']} consultas por minuto atingido; tente em instantes"
    if limits.get("day") and row.day_calls >= limits["day"]:
        return f"Limite gratuito de {limits['day']} consultas por dia atingido; volta amanhã"
    return None


def _parse_reset(value):
    """Reset pode vir como epoch (AbuseIPDB, ThreatFox) ou ISO 8601 (URLScan.io)."""
    if not value:
        return None
    try:
        return datetime.fromtimestamp(int(value), timezone.utc).replace(tzinfo=None)
    except (TypeError, ValueError):
        pass
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return moment.astimezone(timezone.utc).replace(tzinfo=None)
    except ValueError:
        return None


def _read_headers(row, headers):
    """Lê os cabeçalhos de limite que cada API devolve (nomes variam entre fontes)."""
    h = {k.lower(): v for k, v in (headers or {}).items()}
    reset = None

    if "api-limits" in h:  # Hybrid Analysis: JSON com limites e uso por minuto/hora
        try:
            info = json.loads(h["api-limits"])
            limit = int(info["limits"]["minute"])
            used = int(info["used"]["minute"])
            row.remote_limit, row.remote_remaining, row.remote_window = limit, max(limit - used, 0), "minuto"
            if info.get("limit_reached"):
                reset = utcnow() + DEFAULT_PAUSE
        except (ValueError, KeyError, TypeError):
            pass
    else:
        limit = h.get("x-ratelimit-limit") or h.get("x-rate-limit-limit")
        remaining = h.get("x-ratelimit-remaining") or h.get("x-rate-limit-remaining")
        if limit is not None and remaining is not None:
            try:
                row.remote_limit, row.remote_remaining = int(limit), int(remaining)
                row.remote_window = "minuto" if h.get("x-rate-limit-window") == "minute" else "dia"
                if row.remote_remaining <= 0:
                    reset = _parse_reset(h.get("x-ratelimit-reset") or h.get("x-rate-limit-reset"))
            except ValueError:
                pass
    return reset


def record(provider_id, response):
    """Registra uma chamada feita e o que a API informou sobre o limite."""
    row = _row(provider_id)
    row.day_calls += 1
    row.window_calls += 1
    reset = _read_headers(row, getattr(response, "headers", None))

    if getattr(response, "status_code", 200) == 429:
        retry_after = (getattr(response, "headers", None) or {}).get("Retry-After") \
            or (getattr(response, "headers", None) or {}).get("retry-after")
        try:
            reset = utcnow() + timedelta(seconds=int(retry_after))
        except (TypeError, ValueError):
            # O VirusTotal responde QuotaExceededError ao esgotar a cota diária
            # A MxToolbox também zera a cota diária à meia-noite UTC
            reset = reset or (_next_utc_midnight() if provider_id in ("virustotal", "mxtoolbox")
                              else utcnow() + DEFAULT_PAUSE)
    if reset:
        row.blocked_until = reset


def usage(provider_id):
    """Resumo do consumo, exibido na tela de Configurações."""
    row = db.session.get(ProviderQuota, provider_id)
    today = row.day_calls if row and row.day == _today() else 0
    blocked = row.blocked_until if row and row.blocked_until and row.blocked_until > utcnow() else None
    remote = None
    if row and row.remote_limit is not None:
        remote = f"{row.remote_remaining} de {row.remote_limit} restantes no {row.remote_window}"
    return {
        "calls_today": today,
        "free_limits": limits_text(provider_id),
        "remote": remote,
        "blocked_until": iso(blocked),
    }
