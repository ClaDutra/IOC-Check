from datetime import datetime, timedelta, timezone

from app.extensions import db
from app.models import Ioc, utcnow


def iso_in(days):
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def expire_now(app, value):
    """Simula a passagem do tempo movendo o prazo do IOC para o passado."""
    with app.app_context():
        ioc = Ioc.query.filter_by(value=value).first()
        ioc.expires_at = utcnow() - timedelta(seconds=1)
        db.session.commit()


def check(client, value):
    return client.post("/api/check", json={"indicators": value}).get_json()["results"][0]


def test_new_ioc_uses_default_expiration(client):
    client.put("/api/settings", json={"values": {"ioc_default_expiration_days": 30}})
    ioc = client.post("/api/iocs", json={"value": "bad.example"}).get_json()
    expires = datetime.fromisoformat(ioc["expires_at"].rstrip("Z"))
    assert timedelta(days=29, hours=23) < expires - utcnow() <= timedelta(days=30)


def test_default_zero_means_never_expires(client):
    client.put("/api/settings", json={"values": {"ioc_default_expiration_days": 0}})
    assert client.post("/api/iocs", json={"value": "bad.example"}).get_json()["expires_at"] is None


def test_explicit_expiration_and_never(client):
    ioc = client.post("/api/iocs", json={"value": "a.example", "expires_at": iso_in(10)}).get_json()
    assert ioc["expires_at"] and not ioc["expired"]
    ioc = client.post("/api/iocs", json={"value": "b.example", "expires_at": None}).get_json()
    assert ioc["expires_at"] is None


def test_past_or_invalid_expiration_is_rejected(client):
    assert client.post("/api/iocs", json={"value": "a.example", "expires_at": iso_in(-1)}).status_code == 400
    assert client.post("/api/iocs", json={"value": "a.example", "expires_at": "amanhã"}).status_code == 400


def test_expired_ioc_is_ignored_by_check(app, client):
    client.post("/api/iocs", json={"value": "bad.example", "severity": "critical"})
    assert check(client, "bad.example")["verdict"] == "malicious"

    expire_now(app, "bad.example")
    client.delete("/api/cache")
    result = check(client, "bad.example")
    assert result["verdict"] == "unknown"
    local = next(r for r in result["results"] if r["provider"] == "Base local")
    assert "expirou" in local["summary"]


def test_cache_does_not_outlive_ioc(client):
    ioc_expiry = iso_in(0.5)  # 12 horas, menos que a validade do cache (24 h)
    client.post("/api/iocs", json={"value": "bad.example", "expires_at": ioc_expiry})
    result = check(client, "bad.example")
    cache_expiry = datetime.fromisoformat(result["expires_at"].rstrip("Z"))
    ioc_expiry_utc = datetime.fromisoformat(ioc_expiry).astimezone(timezone.utc).replace(tzinfo=None, microsecond=0)
    assert cache_expiry == ioc_expiry_utc


def test_edit_expired_ioc_keeps_working_and_renew(app, client):
    ioc_id = client.post("/api/iocs", json={"value": "bad.example"}).get_json()["id"]
    expire_now(app, "bad.example")

    # Editar outros campos não é bloqueado pelo prazo vencido
    assert client.put(f"/api/iocs/{ioc_id}", json={"description": "x"}).status_code == 200
    renewed = client.put(f"/api/iocs/{ioc_id}", json={"expires_at": iso_in(30)}).get_json()
    assert renewed["expired"] is False


def test_status_filter_and_purge_expired(app, client):
    client.post("/api/iocs", json={"value": "old.example"})
    client.post("/api/iocs", json={"value": "soon.example", "expires_at": iso_in(3)})
    client.post("/api/iocs", json={"value": "ok.example", "expires_at": None})
    expire_now(app, "old.example")

    def values(status):
        return [i["value"] for i in client.get(f"/api/iocs?status={status}").get_json()["items"]]

    assert values("expired") == ["old.example"]
    assert values("expiring") == ["soon.example"]
    assert sorted(values("active")) == ["ok.example", "soon.example"]

    data = client.post("/api/iocs/purge-expired").get_json()
    assert data["removed"] == 1
    assert client.get("/api/iocs").get_json()["total"] == 2
