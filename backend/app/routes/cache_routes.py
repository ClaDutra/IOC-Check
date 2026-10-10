from flask import Blueprint, jsonify, request

from ..extensions import db
from ..models import CacheEntry, utcnow
from ..services import cache
from .utils import paginated

bp = Blueprint("cache", __name__, url_prefix="/api/cache")


@bp.get("")
def list_cache():
    query = CacheEntry.query
    term = request.args.get("q", "").strip()
    if term:
        query = query.filter(CacheEntry.indicator.ilike(f"%{term}%"))
    status = request.args.get("status")
    if status == "valid":
        query = query.filter(CacheEntry.expires_at > utcnow())
    elif status == "expired":
        query = query.filter(CacheEntry.expires_at <= utcnow())

    data = paginated(query.order_by(CacheEntry.stored_at.desc(), CacheEntry.id.desc()))
    data["summary"] = cache.summary()
    return jsonify(data)


@bp.get("/<int:entry_id>")
def get_entry(entry_id):
    return jsonify(db.get_or_404(CacheEntry, entry_id).to_dict(include_results=True))


@bp.delete("/<int:entry_id>")
def delete_entry(entry_id):
    entry = db.get_or_404(CacheEntry, entry_id)
    db.session.delete(entry)
    db.session.commit()
    return jsonify(message="Entrada removida do cache")


@bp.post("/purge-expired")
def purge_expired():
    removed = cache.purge_expired()
    db.session.commit()
    return jsonify(removed=removed, message=f"{removed} entrada(s) expirada(s) removida(s)")


@bp.delete("")
def clear_cache():
    removed = cache.clear_all()
    db.session.commit()
    return jsonify(removed=removed, message=f"Cache esvaziado ({removed} entrada(s))")
