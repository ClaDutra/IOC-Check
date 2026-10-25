from flask import Blueprint, jsonify

from ..extensions import db
from ..ioc_utils import TYPE_LABELS
from ..services import cache, settings
from ..services.providers import PROVIDERS, PROVIDERS_BY_ID, TEST_SAMPLES, provider_state, run_provider
from .utils import json_body

bp = Blueprint("settings", __name__, url_prefix="/api/settings")


def _payload():
    general = [
        {
            "key": key,
            "label": item["label"],
            "value": settings.get(key),
            "min": item["min"],
            "max": item["max"],
            "source": settings.source(key),
        }
        for key, item in settings.GENERAL.items()
    ]
    providers = []
    for p in PROVIDERS:
        key_name = f"{p.id}_api_key"
        providers.append({
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "signup_url": p.signup_url,
            "key_required": p.key_required,
            "types": [TYPE_LABELS[t] for t in TYPE_LABELS if t in p.types],
            "masked_key": settings.mask(settings.get(key_name)),
            "key_source": settings.source(key_name),
            **provider_state(p),
        })
    return {"general": general, "providers": providers}


@bp.get("")
def get_settings():
    return jsonify(_payload())


@bp.put("")
def update_settings():
    data = json_body()
    try:
        changed = settings.update(data.get("values"), data.get("clear"))
    except settings.SettingsError as exc:
        db.session.rollback()
        return jsonify(error=str(exc)), 400

    # Resultados guardados com a configuração antiga de fontes ficariam
    # desatualizados (ex.: "chave não configurada"), então o cache é limpo.
    cleared = 0
    if any(k.endswith(("_enabled", "_api_key")) for k in changed):
        cleared = cache.clear_all()
    db.session.commit()

    if not changed:
        message = "Nenhuma alteração"
    elif cleared:
        message = f"Configurações salvas. Cache limpo ({cleared} entrada(s)) porque as fontes mudaram."
    else:
        message = "Configurações salvas"
    return jsonify(message=message, changed=changed, cache_cleared=cleared, **_payload())


@bp.post("/providers/<provider_id>/test")
def test_provider(provider_id):
    provider = PROVIDERS_BY_ID.get(provider_id)
    if provider is None:
        return jsonify(error="Fonte desconhecida"), 404

    value, ioc_type = TEST_SAMPLES[provider_id]
    result = run_provider(provider, value, ioc_type, ignore_disabled=True)
    db.session.commit()  # grava o consumo da cota gratuita
    ok = result["status"] in ("ok", "not_found")
    if ok:
        message = f"Conexão com {provider.name} funcionando"
    else:
        message = f"{provider.name}: {result['summary']}"
    return jsonify(ok=ok, message=message, sample=value, result=result)
