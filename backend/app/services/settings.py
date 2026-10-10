"""Configurações do sistema guardadas no banco (tabela settings).

Ordem de prioridade de cada valor:
  1. valor salvo pela tela de Configurações;
  2. valor do arquivo .env (via app.config);
  3. padrão definido aqui.
"""

from flask import current_app, g

from ..extensions import db
from ..models import Setting

PROVIDER_IDS = ("virustotal", "abuseipdb", "threatfox", "hybrid_analysis", "urlscan")

GENERAL = {
    "cache_ttl_hours": {
        "label": "Validade do cache (horas)",
        "config": "CACHE_TTL_HOURS",
        "min": 1,
        "max": 720,
    },
    "cache_error_ttl_minutes": {
        "label": "Validade quando alguma fonte falha (minutos)",
        "config": "CACHE_ERROR_TTL_MINUTES",
        "min": 1,
        "max": 1440,
    },
    "provider_timeout": {
        "label": "Tempo limite por fonte (segundos)",
        "config": "PROVIDER_TIMEOUT",
        "min": 2,
        "max": 60,
    },
    "ioc_default_expiration_days": {
        "label": "Validade padrão dos novos IOCs (dias, 0 = nunca expira)",
        "config": "IOC_DEFAULT_EXPIRATION_DAYS",
        "min": 0,
        "max": 3650,
    },
}


def _build_definitions():
    definitions = {key: {**item, "type": "int"} for key, item in GENERAL.items()}
    for pid in PROVIDER_IDS:
        definitions[f"{pid}_enabled"] = {"type": "bool", "default": True}
        definitions[f"{pid}_api_key"] = {"type": "secret", "config": f"{pid.upper()}_API_KEY"}
    return definitions


DEFINITIONS = _build_definitions()


class SettingsError(ValueError):
    pass


def _stored():
    """Valores do banco, lidos uma vez por requisição."""
    if "settings_cache" not in g:
        g.settings_cache = {s.key: s.value for s in Setting.query.all()}
    return g.settings_cache


def _default(key):
    definition = DEFINITIONS[key]
    if key == "urlscan_enabled":
        return current_app.config.get("URLSCAN_ENABLED_BY_DEFAULT", True)
    if "config" in definition:
        return current_app.config.get(definition["config"])
    return definition.get("default")


def _parse(definition, raw):
    if definition["type"] == "int":
        return int(raw)
    if definition["type"] == "bool":
        return raw == "1"
    return raw


def get(key):
    raw = _stored().get(key)
    if raw is None:
        return _default(key)
    return _parse(DEFINITIONS[key], raw)


def source(key):
    if key in _stored():
        return "configurações"
    definition = DEFINITIONS[key]
    if definition["type"] == "secret" and current_app.config.get(definition["config"]):
        return "arquivo .env"
    return "padrão"


def mask(secret):
    if not secret:
        return ""
    return "••••••••" + secret[-4:] if len(secret) > 8 else "••••••••"


def _to_stored(key, raw):
    """Valida um valor recebido e o converte para texto. None = não alterar."""
    definition = DEFINITIONS.get(key)
    if definition is None:
        raise SettingsError(f"Configuração desconhecida: {key}")

    if definition["type"] == "secret":
        value = str(raw or "").strip()
        if len(value) > 512:
            raise SettingsError("Chave de API muito longa")
        return value or None  # campo vazio mantém a chave atual

    if definition["type"] == "bool":
        return "1" if raw is True or str(raw).lower() in ("1", "true", "on") else "0"

    try:
        number = int(raw)
    except (TypeError, ValueError):
        raise SettingsError(f"{definition['label']}: informe um número inteiro") from None
    if not definition["min"] <= number <= definition["max"]:
        raise SettingsError(
            f"{definition['label']}: use um valor entre {definition['min']} e {definition['max']}"
        )
    return str(number)


def update(values, clear):
    """Salva os valores alterados e retorna a lista de chaves modificadas."""
    pending = {}
    for key, raw in (values or {}).items():
        stored = _to_stored(key, raw)
        if stored is not None and _stored().get(key) != stored:
            pending[key] = stored

    for key in clear or []:
        if DEFINITIONS.get(key, {}).get("type") != "secret":
            raise SettingsError(f"Só é possível remover chaves de API: {key}")

    for key, stored in pending.items():
        setting = db.session.get(Setting, key) or Setting(key=key)
        setting.value = stored
        db.session.add(setting)

    changed = list(pending)
    for key in clear or []:
        setting = db.session.get(Setting, key)
        if setting is not None:
            db.session.delete(setting)
            changed.append(key)

    g.pop("settings_cache", None)
    return changed
