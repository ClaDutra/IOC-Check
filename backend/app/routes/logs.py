"""Tela Logs: ações feitas na aplicação e respostas das APIs das fontes."""

import json
from datetime import datetime

from flask import Blueprint, Response, jsonify, request

from ..extensions import db
from ..models import AppLog
from .utils import paginated

bp = Blueprint("logs", __name__, url_prefix="/api/logs")


def _filtered():
    query = AppLog.query
    for field in ("category", "level", "source"):
        if request.args.get(field):
            query = query.filter(getattr(AppLog, field) == request.args[field])
    term = request.args.get("q", "").strip()
    if term:
        like = f"%{term}%"
        query = query.filter(db.or_(AppLog.message.ilike(like), AppLog.details_json.ilike(like)))
    return query.order_by(AppLog.created_at.desc(), AppLog.id.desc())


@bp.get("")
def list_logs():
    data = paginated(_filtered())
    data["sources"] = [s for (s,) in db.session.query(AppLog.source).distinct().order_by(AppLog.source) if s]
    data["counts"] = dict(db.session.query(AppLog.category, db.func.count()).group_by(AppLog.category).all())
    return jsonify(data)


@bp.get("/export")
def export_logs():
    items = [log.to_dict() for log in _filtered().limit(5000)]
    filename = f"logs_ioc_check_{datetime.now():%Y%m%d_%H%M}.json"
    return Response(json.dumps(items, ensure_ascii=False, indent=2), mimetype="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@bp.delete("")
def clear_logs():
    removed = AppLog.query.delete(synchronize_session=False)
    db.session.commit()
    return jsonify(removed=removed, message=f"Logs apagados ({removed} registro(s))")
