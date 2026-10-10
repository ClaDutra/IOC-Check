from datetime import timedelta

from flask import Blueprint, jsonify

from ..extensions import db
from ..models import Ioc, QueryLog, utcnow
from ..services import cache
from ..services.providers import configured_providers

bp = Blueprint("stats", __name__, url_prefix="/api")

CHART_DAYS = 14


def _count_by(column):
    rows = db.session.query(column, db.func.count()).group_by(column).all()
    return {key: count for key, count in rows}


@bp.get("/health")
def health():
    return jsonify(status="ok", providers=configured_providers())


@bp.get("/stats")
def stats():
    total_queries = QueryLog.query.count()
    cache_hits = QueryLog.query.filter(QueryLog.from_cache.is_(True)).count()

    # Consultas por dia no período do gráfico (inclui dias sem consultas)
    today = utcnow().date()
    start = today - timedelta(days=CHART_DAYS - 1)
    day = db.func.date(QueryLog.queried_at)
    rows = (
        db.session.query(day, db.func.count())
        .filter(QueryLog.queried_at >= start)
        .group_by(day)
        .all()
    )
    per_day_map = {str(d): c for d, c in rows}
    per_day = [
        {"date": str(start + timedelta(days=i)), "count": per_day_map.get(str(start + timedelta(days=i)), 0)}
        for i in range(CHART_DAYS)
    ]

    top = (
        db.session.query(QueryLog.indicator, QueryLog.verdict, db.func.count().label("total"))
        .group_by(QueryLog.indicator, QueryLog.verdict)
        .order_by(db.desc("total"))
        .limit(5)
        .all()
    )
    recent = QueryLog.query.order_by(QueryLog.queried_at.desc(), QueryLog.id.desc()).limit(8).all()

    return jsonify(
        queries={
            "total": total_queries,
            "cache_hits": cache_hits,
            "cache_hit_rate": round(cache_hits / total_queries * 100, 1) if total_queries else 0,
            "by_verdict": _count_by(QueryLog.verdict),
            "by_type": _count_by(QueryLog.ioc_type),
            "per_day": per_day,
            "top": [{"indicator": i, "verdict": v, "count": c} for i, v, c in top],
            "recent": [log.to_dict() for log in recent],
        },
        iocs={
            "total": Ioc.query.count(),
            "active": Ioc.query.filter(Ioc.active.is_(True), Ioc.not_expired()).count(),
            "expired": Ioc.query.filter(Ioc.expires_at <= utcnow()).count(),
            "by_severity": _count_by(Ioc.severity),
        },
        cache=cache.summary(),
        providers=configured_providers(),
    )
