"""Respeito aos limites dos planos gratuitos (services/quota.py)."""

from datetime import datetime, timedelta

from app.extensions import db
from app.models import ProviderQuota, utcnow
from app.services import quota
from tests.test_providers import FakeResponse, fake_http, run  # noqa: F401  (fixture)

VT_OK = FakeResponse(200, {"data": {"attributes": {"last_analysis_stats": {"harmless": 1}}}})


def test_virustotal_respects_four_per_minute(app, fake_http):
    fake_http["response"] = VT_OK
    results = [run(app, "virustotal", f"8.8.8.{i}", "ipv4") for i in range(5)]
    assert [r["status"] for r in results] == ["ok"] * 4 + ["skipped"]
    assert "4 consultas por minuto" in results[4]["summary"]
    assert results[4]["transient"] is True
    assert len(fake_http["calls"]) == 4  # a 5ª nem chega a chamar a API


def test_429_pauses_source_until_retry_after(app, fake_http):
    fake_http["response"] = FakeResponse(429, {"error": {"code": "QuotaExceededError"}}, {"Retry-After": "3600"})
    first = run(app, "virustotal", "8.8.8.8", "ipv4")
    second = run(app, "virustotal", "1.1.1.1", "ipv4")
    assert first["status"] == "skipped" and first["transient"]
    assert "nova tentativa liberada" in second["summary"]
    assert len(fake_http["calls"]) == 1  # depois do 429, a fonte fica em pausa
    with app.app_context():
        row = db.session.get(ProviderQuota, "virustotal")
        assert row.blocked_until > utcnow() + timedelta(minutes=59)


def test_virustotal_quota_error_without_retry_after_waits_until_midnight(app, fake_http):
    fake_http["response"] = FakeResponse(429, {"error": {"code": "QuotaExceededError"}})
    run(app, "virustotal", "8.8.8.8", "ipv4")
    with app.app_context():
        blocked = db.session.get(ProviderQuota, "virustotal").blocked_until
        assert (blocked.hour, blocked.minute) == (0, 0)


def test_reads_rate_limit_headers(app):
    with app.test_request_context():
        quota.record("abuseipdb", FakeResponse(200, headers={"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "999"}))
        quota.record("hybrid_analysis", FakeResponse(200, headers={
            "api-limits": '{"limits":{"minute":200,"hour":2000},"used":{"minute":3,"hour":3},"limit_reached":false}'}))
        assert quota.usage("abuseipdb")["remote"] == "999 de 1000 restantes no dia"
        assert quota.usage("hybrid_analysis")["remote"] == "197 de 200 restantes no minuto"
        assert quota.usage("abuseipdb")["calls_today"] == 1


def test_daily_counter_resets_on_new_day(app):
    with app.test_request_context():
        db.session.add(ProviderQuota(provider="abuseipdb", day="2000-01-01", day_calls=1000,
                                     window_start=datetime(2000, 1, 1), window_calls=0))
        db.session.commit()
        assert quota.check("abuseipdb") is None  # dia novo: contador zerado


def test_quota_pause_uses_short_cache(client, monkeypatch):
    # Com a fonte pausada, o resultado fica pouco tempo no cache para tentar de novo
    client.put("/api/settings", json={"values": {"virustotal_api_key": "chave-teste-123456"}})
    monkeypatch.setattr(quota, "check", lambda provider_id: "Limite gratuito atingido" if provider_id == "virustotal" else None)
    result = client.post("/api/check", json={"indicators": "8.8.8.8"}).get_json()["results"][0]
    stored = datetime.fromisoformat(result["stored_at"].rstrip("Z"))
    expires = datetime.fromisoformat(result["expires_at"].rstrip("Z"))
    assert (expires - stored) == timedelta(minutes=10)


def test_settings_show_usage_and_terms(client):
    providers = client.get("/api/settings").get_json()["providers"]
    vt = next(p for p in providers if p["id"] == "virustotal")
    assert vt["usage"]["free_limits"] == "4/min, 500/dia"
    assert "não comercial" in vt["terms"]
