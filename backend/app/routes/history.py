import csv
import io
from datetime import datetime

from flask import Blueprint, Response, jsonify, request

from ..extensions import db
from ..models import QueryLog
from .utils import paginated

bp = Blueprint("history", __name__, url_prefix="/api/history")


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


@bp.delete("")
def clear_history():
    removed = QueryLog.query.delete(synchronize_session=False)
    db.session.commit()
    return jsonify(removed=removed, message=f"Histórico apagado ({removed} consulta(s))")


@bp.get("/export")
def export_history():
    buffer = io.StringIO()
    # Ponto e vírgula + BOM para abrir corretamente no Excel em português
    buffer.write("﻿")
    writer = csv.writer(buffer, delimiter=";")
    writer.writerow(
        ["Data da consulta (UTC)", "Indicador", "Tipo", "Veredito", "Score",
         "Origem", "Resultado armazenado em (UTC)"]
    )
    for log in _filtered_query().limit(10000):
        writer.writerow([
            log.queried_at.strftime("%Y-%m-%d %H:%M:%S"),
            log.indicator,
            log.ioc_type,
            log.verdict,
            log.score,
            "cache" if log.from_cache else "consulta nova",
            log.cache_stored_at.strftime("%Y-%m-%d %H:%M:%S") if log.cache_stored_at else "",
        ])

    filename = f"historico_ioc_{datetime.now():%Y%m%d_%H%M}.csv"
    return Response(
        buffer.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
