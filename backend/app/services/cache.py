"""Cache de consultas persistido no banco (tabela cache_entries).

Cada indicador verificado gera uma entrada com a data de armazenamento (stored_at)
e a data de expiração (expires_at). Enquanto a entrada for válida, novas consultas
ao mesmo indicador reutilizam o resultado sem chamar as APIs externas.
"""

import json
from datetime import datetime, timedelta

from ..extensions import db
from ..models import CacheEntry, utcnow
from . import settings


def get_valid(indicator):
    entry = CacheEntry.query.filter_by(indicator=indicator).first()
    if entry is None or entry.is_expired:
        return None
    entry.hits += 1
    return entry


def store(indicator, ioc_type, verdict, score, results):
    if any(r["status"] == "error" for r in results):
        ttl = timedelta(minutes=settings.get("cache_error_ttl_minutes"))
    else:
        ttl = timedelta(hours=settings.get("cache_ttl_hours"))

    entry = CacheEntry.query.filter_by(indicator=indicator).first()
    if entry is None:
        entry = CacheEntry(indicator=indicator, hits=0)
        db.session.add(entry)

    now = utcnow()
    entry.ioc_type = ioc_type
    entry.verdict = verdict
    entry.score = score
    entry.results_json = json.dumps(results, ensure_ascii=False)
    entry.stored_at = now
    entry.expires_at = min([now + ttl, *_local_ioc_expirations(results)])
    return entry


def _local_ioc_expirations(results):
    """Prazo do IOC da base local que gerou o veredito, se houver.

    O resultado em cache não pode durar mais que o próprio IOC: quando ele
    expira, a próxima consulta precisa deixar de considerá-lo.
    """
    for r in results:
        expires = r.get("details", {}).get("expires_at")
        if r["provider"] == "Base local" and r["status"] == "ok" and expires:
            yield datetime.fromisoformat(expires.rstrip("Z"))


def invalidate_related(value):
    """Remove entradas afetadas por uma mudança na base local.

    Usa "contém" para também invalidar URLs e e-mails do domínio alterado.
    """
    return CacheEntry.query.filter(
        CacheEntry.indicator.contains(value, autoescape=True)
    ).delete(synchronize_session=False)


def invalidate_local_matches():
    """Remove só os resultados que vieram da base local (usado ao limpar a base).

    Resultados obtidos apenas das fontes externas continuam válidos, o que
    economiza a cota das APIs.
    """
    removed = 0
    for entry in CacheEntry.query.all():
        if any(r["provider"] == "Base local" and r["status"] == "ok" for r in entry.results):
            db.session.delete(entry)
            removed += 1
    return removed


def purge_expired():
    return CacheEntry.query.filter(CacheEntry.expires_at <= utcnow()).delete(
        synchronize_session=False
    )


def clear_all():
    return CacheEntry.query.delete(synchronize_session=False)


def summary():
    now = utcnow()
    total = CacheEntry.query.count()
    expired = CacheEntry.query.filter(CacheEntry.expires_at <= now).count()
    hits = db.session.query(db.func.coalesce(db.func.sum(CacheEntry.hits), 0)).scalar()
    oldest = db.session.query(db.func.min(CacheEntry.stored_at)).scalar()
    return {
        "total": total,
        "valid": total - expired,
        "expired": expired,
        "hits": int(hits),
        "ttl_hours": settings.get("cache_ttl_hours"),
        "oldest_stored_at": oldest.isoformat(timespec="seconds") + "Z" if oldest else None,
    }
