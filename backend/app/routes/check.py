from flask import Blueprint, current_app, jsonify

from ..extensions import db
from ..ioc_utils import parse_input
from ..services import activity, page_capture
from ..services.providers import VERDICT_LABEL
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
    for result in results:
        if not result.get("valid"):
            continue
        # Prints de página ainda dentro do prazo do cache são reaproveitados;
        # "forçar nova consulta" começa sem eles, assim como ignora o cache
        result["captures"] = {} if force_refresh else page_capture.reuse_recent(
            result["history_id"], result["indicator"], [r["provider"] for r in result["results"]])
    db.session.commit()
    for result in results:
        if result.get("valid"):
            activity.action("verificar", f"Verificou {result['indicator']}: {VERDICT_LABEL[result['verdict']]} "
                            f"(score {result['score']}) · {'do cache' if result['from_cache'] else 'consulta nova'}",
                            indicador=result["indicator"], tipo=result["type"], veredito=result["verdict"],
                            score=result["score"], historico=result["history_id"])
        else:
            activity.action("verificar", f"Entrada inválida: {result['input']}", level="aviso")
    return jsonify(
        results=results,
        summary={
            "total": len(results),
            "invalid": sum(1 for r in results if not r["valid"]),
            "from_cache": sum(1 for r in results if r.get("from_cache")),
        },
    )
