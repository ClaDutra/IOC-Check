from flask import Blueprint, Response, jsonify, request

from ..extensions import db
from ..models import QueryLog
from ..services import history
from .utils import json_body, paginated

bp = Blueprint("history", __name__, url_prefix="/api/history")


def _ids(raw):
    """Lista de ids vinda de "1,2,3" (query string) ou de uma lista JSON."""
    if isinstance(raw, str):
        raw = raw.split(",")
    try:
        return [int(i) for i in raw or [] if str(i).strip()]
    except (TypeError, ValueError):
        return None


def _filtered_query():
    query = QueryLog.query
    term = request.args.get("q", "").strip()
    if term:
        query = query.filter(QueryLog.indicator.ilike(f"%{term}%"))
    if request.args.get("verdict"):
        query = query.filter(QueryLog.verdict == request.args["verdict"])
    if request.args.get("type"):
        query = query.filter(QueryLog.ioc_type == request.args["type"])
    if request.args.get("source") in ("cache", "live"):
        query = query.filter(QueryLog.from_cache.is_(request.args["source"] == "cache"))
    return query.order_by(QueryLog.queried_at.desc(), QueryLog.id.desc())


@bp.get("")
def list_history():
    return jsonify(paginated(_filtered_query()))


@bp.get("/<int:log_id>")
def get_entry(log_id):
    return jsonify(history.detail(db.get_or_404(QueryLog, log_id)))


@bp.delete("/<int:log_id>")
def delete_entry(log_id):
    db.get_or_404(QueryLog, log_id)
    history.delete([log_id])
    db.session.commit()
    return jsonify(message="Consulta removida do histórico")


@bp.post("/delete")
def delete_selected():
    ids = _ids(json_body().get("ids"))
    if not ids:
        return jsonify(error="Selecione ao menos uma consulta"), 400
    removed = history.delete(ids)
    db.session.commit()
    return jsonify(removed=removed, message=f"{removed} consulta(s) removida(s) do histórico")


@bp.delete("")
def clear_history():
    removed = history.clear_all()
    db.session.commit()
    return jsonify(removed=removed, message=f"Histórico apagado ({removed} consulta(s))")


@bp.get("/export")
def export_history():
    """Exporta as consultas escolhidas.

    ?ids=1,2,3 exporta só essas consultas (sem ids, todas as do filtro atual);
    ?include=summary,sources,json,evidence,pages escolhe o conteúdo (padrão: summary).
    """
    query = _filtered_query()
    if request.args.get("ids"):
        ids = _ids(request.args["ids"])
        if ids is None:
            return jsonify(error="Lista de consultas inválida"), 400
        query = query.filter(QueryLog.id.in_(ids))
    parts = [p for p in request.args.get("include", "summary").split(",") if p]
    unknown = set(parts) - set(history.EXPORT_PARTS)
    if unknown:
        return jsonify(error=f"Conteúdo desconhecido: {', '.join(sorted(unknown))}"), 400

    content, filename, mimetype = history.export(query.limit(history.MAX_EXPORT).all(), parts)
    return Response(content, mimetype=mimetype,
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})
