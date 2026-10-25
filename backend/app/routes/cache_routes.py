"""Cache das consultas: funciona nos bastidores (não tem mais tela própria).

A validade é configurada em Configurações → Prazos; os dados completos de cada
consulta ficam no Histórico. Estas rotas alimentam o resumo e a limpeza do cache.
"""

from flask import Blueprint, jsonify, request

from ..extensions import db
from ..models import CacheEntry, utcnow
from ..services import cache
from .utils import paginated

bp = Blueprint("cache", __name__, url_prefix="/api/cache")


@bp.get("/summary")
def cache_summary():
    return jsonify(cache.summary())


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
