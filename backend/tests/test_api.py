from datetime import timedelta

from app.extensions import db
from app.models import CacheEntry, utcnow


def check(client, indicators, force=False):
    return client.post("/api/check", json={"indicators": indicators, "force_refresh": force})


def test_pages_open_without_login(client):
    for path in ("/", "/check", "/iocs", "/history", "/cache", "/settings"):
        assert client.get(path).status_code == 200
    assert client.get("/login").status_code == 404


def test_changes_without_app_header_are_refused(raw_client):
    # Protege contra outro site aberto no navegador disparando ações no app
    assert raw_client.delete("/api/iocs").status_code == 403
    assert raw_client.post("/api/check", json={"indicators": "8.8.8.8"}).status_code == 403
    assert raw_client.get("/api/iocs").status_code == 200


def test_second_query_comes_from_cache(client):
    first = check(client, "8.8.8.8").get_json()["results"][0]
    second = check(client, "8.8.8.8").get_json()["results"][0]

    assert first["from_cache"] is False
    assert second["from_cache"] is True
    assert second["stored_at"] == first["stored_at"]
    assert second["hits"] == 1


def test_force_refresh_ignores_cache(client):
    check(client, "8.8.8.8")
    result = check(client, "8.8.8.8", force=True).get_json()["results"][0]
    assert result["from_cache"] is False


def test_expired_cache_is_not_used(app, client):
    check(client, "8.8.8.8")
    with app.app_context():
        entry = CacheEntry.query.first()
        entry.expires_at = utcnow() - timedelta(seconds=1)
        db.session.commit()
    assert check(client, "8.8.8.8").get_json()["results"][0]["from_cache"] is False


def test_local_base_marks_malicious_and_invalidates_cache(client):
    before = check(client, "phishing.example").get_json()["results"][0]
    assert before["verdict"] == "unknown"

    response = client.post("/api/iocs", json={"value": "phishing[.]example", "severity": "critical"})
    assert response.status_code == 201

    after = check(client, "phishing.example").get_json()["results"][0]
    assert after["from_cache"] is False
    assert after["verdict"] == "malicious"
    assert after["score"] == 100


def test_url_matches_domain_in_local_base(client):
    client.post("/api/iocs", json={"value": "bad.example", "severity": "medium"})
    result = check(client, "http://bad.example/login").get_json()["results"][0]
    assert result["verdict"] == "suspicious"


def test_invalid_indicator(client):
    data = check(client, "nao-e-ioc").get_json()
    assert data["results"][0]["valid"] is False
    assert data["summary"]["invalid"] == 1


def test_duplicate_ioc_returns_conflict(client):
    client.post("/api/iocs", json={"value": "1.2.3.4"})
    assert client.post("/api/iocs", json={"value": "1.2.3.4"}).status_code == 409


def test_delete_single_ioc(client):
    ioc_id = client.post("/api/iocs", json={"value": "1.2.3.4"}).get_json()["id"]
    assert client.delete(f"/api/iocs/{ioc_id}").status_code == 200
    assert client.get("/api/iocs").get_json()["total"] == 0


def test_clear_base_removes_all_iocs_and_only_local_cache(client):
    client.post("/api/iocs", json={"value": "bad.example"})
    client.post("/api/iocs", json={"value": "1.2.3.4"})
    check(client, ["bad.example", "8.8.8.8"])  # só bad.example veio da base local

    data = client.delete("/api/iocs").get_json()
    assert data["removed"] == 2
    assert data["cache_invalidated"] == 1
    assert client.get("/api/iocs").get_json()["total"] == 0

    cached = [e["indicator"] for e in client.get("/api/cache").get_json()["items"]]
    assert cached == ["8.8.8.8"]
    assert check(client, "bad.example").get_json()["results"][0]["verdict"] == "unknown"


def test_history_records_cache_origin_and_exports_csv(client):
    check(client, "8.8.8.8")
    check(client, "8.8.8.8")
    items = client.get("/api/history").get_json()["items"]
    assert [i["from_cache"] for i in items] == [True, False]
    assert all(i["cache_stored_at"] for i in items)

    csv = client.get("/api/history/export")
    assert csv.status_code == 200
    assert "8.8.8.8" in csv.get_data(as_text=True)


def test_clear_history(client):
    check(client, ["8.8.8.8", "1.1.1.1"])
    assert client.delete("/api/history").get_json()["removed"] == 2
    assert client.get("/api/history").get_json()["total"] == 0


def test_purge_expired_and_clear_cache(app, client):
    check(client, ["8.8.8.8", "1.1.1.1"])
    with app.app_context():
        entry = CacheEntry.query.filter_by(indicator="8.8.8.8").first()
        entry.expires_at = utcnow() - timedelta(seconds=1)
        db.session.commit()

    assert client.post("/api/cache/purge-expired").get_json()["removed"] == 1
    assert client.get("/api/cache").get_json()["summary"]["total"] == 1
    assert client.delete("/api/cache").get_json()["removed"] == 1


def test_stats(client):
    check(client, "8.8.8.8")
    check(client, "8.8.8.8")
    stats = client.get("/api/stats").get_json()
    assert stats["queries"]["total"] == 2
    assert stats["queries"]["cache_hit_rate"] == 50.0
    assert stats["queries"]["per_day"][-1]["count"] == 2
