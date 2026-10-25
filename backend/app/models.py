import json
from datetime import datetime, timezone

from .extensions import db


def utcnow():
    """Data/hora atual em UTC, sem fuso (o SQLite não guarda fuso horário)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso(dt):
    """Serializa datas como ISO 8601 em UTC para o front-end converter ao fuso local."""
    return dt.isoformat(timespec="seconds") + "Z" if dt else None


class Ioc(db.Model):
    """Indicador de comprometimento cadastrado pelo próprio usuário (base local)."""

    __tablename__ = "iocs"

    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(2048), unique=True, nullable=False, index=True)
    ioc_type = db.Column(db.String(20), nullable=False)
    severity = db.Column(db.String(20), nullable=False, default="high")
    description = db.Column(db.Text, nullable=False, default="")
    tags = db.Column(db.String(255), nullable=False, default="")
    source = db.Column(db.String(100), nullable=False, default="")
    active = db.Column(db.Boolean, nullable=False, default=True)
    # Prazo de validade do indicador; None = nunca expira
    expires_at = db.Column(db.DateTime, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    @classmethod
    def not_expired(cls):
        """Filtro SQL: IOCs sem prazo ou com prazo ainda no futuro."""
        return db.or_(cls.expires_at.is_(None), cls.expires_at > utcnow())

    @property
    def tag_list(self):
        return [t for t in self.tags.split(",") if t]

    @property
    def is_expired(self):
        return self.expires_at is not None and self.expires_at <= utcnow()

    def to_dict(self):
        return {
            "id": self.id,
            "value": self.value,
            "type": self.ioc_type,
            "severity": self.severity,
            "description": self.description,
            "tags": self.tag_list,
            "source": self.source,
            "active": self.active,
            "expires_at": iso(self.expires_at),
            "expired": self.is_expired,
            "created_at": iso(self.created_at),
            "updated_at": iso(self.updated_at),
        }


class CacheEntry(db.Model):
    """Resultado consolidado de uma verificação, reaproveitado até expires_at."""

    __tablename__ = "cache_entries"

    id = db.Column(db.Integer, primary_key=True)
    indicator = db.Column(db.String(2048), unique=True, nullable=False, index=True)
    ioc_type = db.Column(db.String(20), nullable=False)
    verdict = db.Column(db.String(20), nullable=False)
    score = db.Column(db.Integer, nullable=False, default=0)
    results_json = db.Column(db.Text, nullable=False, default="[]")
    stored_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    hits = db.Column(db.Integer, nullable=False, default=0)

    @property
    def results(self):
        return json.loads(self.results_json)

    @property
    def is_expired(self):
        return self.expires_at <= utcnow()

    def to_dict(self, include_results=False):
        data = {
            "id": self.id,
            "indicator": self.indicator,
            "type": self.ioc_type,
            "verdict": self.verdict,
            "score": self.score,
            "stored_at": iso(self.stored_at),
            "expires_at": iso(self.expires_at),
            "expired": self.is_expired,
            "hits": self.hits,
        }
        if include_results:
            data["results"] = self.results
        return data


class Setting(db.Model):
    """Configuração editável pela tela de Configurações (sobrepõe o .env)."""

    __tablename__ = "settings"

    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.Text, nullable=False)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class ProviderQuota(db.Model):
    """Consumo de cada fonte externa, para respeitar os limites dos planos gratuitos."""

    __tablename__ = "provider_quota"

    provider = db.Column(db.String(32), primary_key=True)
    day = db.Column(db.String(10), nullable=False, default="")  # dia UTC (AAAA-MM-DD)
    day_calls = db.Column(db.Integer, nullable=False, default=0)
    window_start = db.Column(db.DateTime)  # início da janela de 1 minuto
    window_calls = db.Column(db.Integer, nullable=False, default=0)
    blocked_until = db.Column(db.DateTime)  # pausa após "limite atingido" (HTTP 429)
    remote_limit = db.Column(db.Integer)  # limite informado pela própria API
    remote_remaining = db.Column(db.Integer)
    remote_window = db.Column(db.String(16))
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class QueryLog(db.Model):
    """Histórico: cada consulta feita, inclusive as atendidas pelo cache."""

    __tablename__ = "query_logs"

    id = db.Column(db.Integer, primary_key=True)
    indicator = db.Column(db.String(2048), nullable=False, index=True)
    ioc_type = db.Column(db.String(20), nullable=False)
    verdict = db.Column(db.String(20), nullable=False)
    score = db.Column(db.Integer, nullable=False, default=0)
    from_cache = db.Column(db.Boolean, nullable=False, default=False)
    # Data em que o resultado usado nesta consulta foi armazenado no cache
    cache_stored_at = db.Column(db.DateTime)
    cache_expires_at = db.Column(db.DateTime)
    # Cópia completa do resultado de cada fonte: o histórico continua com todos os
    # dados (e os prints) mesmo depois que o cache expira ou é esvaziado
    results_json = db.Column(db.Text)
    queried_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)

    @property
    def results(self):
        return json.loads(self.results_json) if self.results_json else []

    @property
    def stored_at(self):
        """Momento em que os dados foram obtidos das fontes (usado nos prints)."""
        return self.cache_stored_at or self.queried_at

    def to_dict(self, include_results=False):
        data = {
            "id": self.id,
            "indicator": self.indicator,
            "type": self.ioc_type,
            "verdict": self.verdict,
            "score": self.score,
            "from_cache": self.from_cache,
            "cache_stored_at": iso(self.cache_stored_at),
            "cache_expires_at": iso(self.cache_expires_at),
            "queried_at": iso(self.queried_at),
            "has_details": bool(self.results_json),
        }
        if include_results:
            data["results"] = self.results
        return data
