from flask import Blueprint, current_app, jsonify

from ..ioc_utils import parse_input
from ..services.checker import check_many
from .utils import json_body

bp = Blueprint("check", __name__, url_prefix="/api/check")


@bp.post("")
def check():
    data = json_body()
    indicators = data.get("indicators")
    force_refresh = bool(data.get("force_refresh", False))

    items = parse_input(indicators)
    if not items:
        return jsonify(error="Informe ao menos um indicador"), 400

    limit = current_app.config["MAX_INDICATORS_PER_CHECK"]
    if len(items) > limit:
        return jsonify(error=f"Máximo de {limit} indicadores por consulta"), 400

    results = check_many(items, force_refresh)
    return jsonify(
        results=results,
        summary={
            "total": len(results),
            "invalid": sum(1 for r in results if not r["valid"]),
            "from_cache": sum(1 for r in results if r.get("from_cache")),
        },
    )
