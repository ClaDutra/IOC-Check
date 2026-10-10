from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, request
from sqlalchemy import or_

from ..extensions import db
from ..ioc_utils import normalize
from ..models import Ioc, utcnow
from ..services import cache, settings
from .utils import json_body, paginated

bp = Blueprint("iocs", __name__, url_prefix="/api/iocs")

SEVERITIES = ("critical", "high", "medium", "low")


def _clean_tags(raw):
    if isinstance(raw, str):
        raw = raw.split(",")
    tags = []
    for tag in raw or []:
        tag = str(tag).strip().lower()
        if tag and tag not in tags:
            tags.append(tag)
    return ",".join(tags)[:255]


def _apply_fields(ioc, data):
    """Valida e aplica os campos editáveis. Retorna mensagem de erro ou None."""
    if "value" in data:
        value, ioc_type = normalize(str(data["value"]))
        if ioc_type is None:
            return "Indicador em formato não reconhecido"
        duplicate = Ioc.query.filter(Ioc.value == value, Ioc.id != ioc.id).first()
        if duplicate:
            return f"Indicador já cadastrado (ID {duplicate.id})"
        ioc.value, ioc.ioc_type = value, ioc_type

    if "severity" in data:
        if data["severity"] not in SEVERITIES:
            return "Severidade inválida"
        ioc.severity = data["severity"]

    if "description" in data:
        ioc.description = str(data["description"]).strip()[:2000]
    if "source" in data:
        ioc.source = str(data["source"]).strip()[:100]
    if "tags" in data:
        ioc.tags = _clean_tags(data["tags"])
    if "active" in data:
        ioc.active = bool(data["active"])

    if "expires_at" in data:
        try:
            expires_at = _parse_expiration(data["expires_at"])
        except ValueError:
            return "Data de expiração inválida"
        # Datas passadas só são recusadas quando o prazo foi alterado,
        # para permitir editar outros campos de um IOC já expirado.
        if expires_at != ioc.expires_at and expires_at is not None and expires_at <= utcnow():
            return "A data de expiração precisa estar no futuro"
        ioc.expires_at = expires_at
    return None


def _parse_expiration(raw):
    """Converte a data ISO 8601 recebida em UTC sem fuso. Vazio/None = nunca expira."""
    if raw in (None, ""):
        return None
    moment = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    if moment.tzinfo is not None:
        moment = moment.astimezone(timezone.utc).replace(tzinfo=None)
    return moment.replace(microsecond=0)


def _default_expiration():
    days = settings.get("ioc_default_expiration_days")
    return utcnow().replace(microsecond=0) + timedelta(days=days) if days else None


@bp.get("")
def list_iocs():
    query = Ioc.query
    term = request.args.get("q", "").strip()
    if term:
        like = f"%{term}%"
        query = query.filter(
            or_(Ioc.value.ilike(like), Ioc.description.ilike(like), Ioc.tags.ilike(like))
        )
    if request.args.get("type"):
        query = query.filter(Ioc.ioc_type == request.args["type"])
    if request.args.get("severity"):
        query = query.filter(Ioc.severity == request.args["severity"])
    status = request.args.get("status")
    if status == "active":
        query = query.filter(Ioc.active.is_(True), Ioc.not_expired())
    elif status == "inactive":
        query = query.filter(Ioc.active.is_(False))
    elif status == "expired":
        query = query.filter(Ioc.expires_at <= utcnow())
    elif status == "expiring":
        # Vencem nos próximos 7 dias
        query = query.filter(Ioc.not_expired(), Ioc.expires_at <= utcnow() + timedelta(days=7))

    data = paginated(query.order_by(Ioc.created_at.desc(), Ioc.id.desc()))
    data["default_expiration_days"] = settings.get("ioc_default_expiration_days")
    data["expired_total"] = Ioc.query.filter(Ioc.expires_at <= utcnow()).count()
    return jsonify(data)


@bp.post("")
def create_ioc():
    data = json_body()
    if not str(data.get("value", "")).strip():
        return jsonify(error="Informe o indicador"), 400

    ioc = Ioc(severity="high")
    if "expires_at" not in data:
        ioc.expires_at = _default_expiration()
    error = _apply_fields(ioc, data)
    if error:
        status = 409 if "já cadastrado" in error else 400
        return jsonify(error=error), status

    db.session.add(ioc)
    cache.invalidate_related(ioc.value)
    db.session.commit()
    return jsonify(ioc.to_dict()), 201


@bp.get("/<int:ioc_id>")
def get_ioc(ioc_id):
    return jsonify(db.get_or_404(Ioc, ioc_id).to_dict())


@bp.put("/<int:ioc_id>")
def update_ioc(ioc_id):
    ioc = db.get_or_404(Ioc, ioc_id)
    old_value = ioc.value
    error = _apply_fields(ioc, json_body())
    if error:
        status = 409 if "já cadastrado" in error else 400
        return jsonify(error=error), status

    cache.invalidate_related(old_value)
    cache.invalidate_related(ioc.value)
    db.session.commit()
    return jsonify(ioc.to_dict())


@bp.delete("/<int:ioc_id>")
def delete_ioc(ioc_id):
    ioc = db.get_or_404(Ioc, ioc_id)
    cache.invalidate_related(ioc.value)
    db.session.delete(ioc)
    db.session.commit()
    return jsonify(message="Indicador removido")


@bp.post("/purge-expired")
def purge_expired_iocs():
    expired = Ioc.query.filter(Ioc.expires_at <= utcnow()).all()
    for ioc in expired:
        cache.invalidate_related(ioc.value)
        db.session.delete(ioc)
    db.session.commit()
    return jsonify(removed=len(expired), message=f"{len(expired)} IOC(s) expirado(s) removido(s)")


@bp.delete("")
def clear_iocs():
    """Apaga toda a base local para o usuário recomeçar a montar a sua."""
    removed = Ioc.query.delete(synchronize_session=False)
    invalidated = cache.invalidate_local_matches()
    db.session.commit()
    return jsonify(
        removed=removed,
        cache_invalidated=invalidated,
        message=f"Base local apagada ({removed} IOC(s))",
    )
