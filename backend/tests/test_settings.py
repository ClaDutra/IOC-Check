from datetime import datetime


def test_list_settings_has_all_providers(client):
    data = client.get("/api/settings").get_json()
    names = [p["name"] for p in data["providers"]]
    assert names == ["VirusTotal", "AbuseIPDB", "ThreatFox", "Hybrid Analysis", "URLScan.io", "MxToolbox", "IPinfo"]
    assert {g["key"] for g in data["general"]} == {
        "cache_ttl_hours", "cache_error_ttl_minutes", "provider_timeout", "ioc_default_expiration_days",
    }


def test_api_key_is_saved_and_masked(client):
    data = client.put(
        "/api/settings", json={"values": {"threatfox_api_key": "segredo-muito-longo-1234"}}
    ).get_json()
    threatfox = next(p for p in data["providers"] if p["id"] == "threatfox")
    assert threatfox["masked_key"].endswith("1234")
    assert "segredo" not in threatfox["masked_key"]
    assert threatfox["active"] is True
    assert threatfox["key_source"] == "configurações"


def test_blank_key_keeps_current_and_clear_removes(client):
    client.put("/api/settings", json={"values": {"virustotal_api_key": "chave-abcdefgh"}})
    data = client.put("/api/settings", json={"values": {"virustotal_api_key": ""}}).get_json()
    assert data["changed"] == []

    data = client.put("/api/settings", json={"clear": ["virustotal_api_key"]}).get_json()
    vt = next(p for p in data["providers"] if p["id"] == "virustotal")
    assert vt["masked_key"] == "" and vt["active"] is False


def test_invalid_ttl_is_rejected(client):
    response = client.put("/api/settings", json={"values": {"cache_ttl_hours": 0}})
    assert response.status_code == 400


def test_ttl_setting_changes_cache_expiration(client):
    client.put("/api/settings", json={"values": {"cache_ttl_hours": 2}})
    result = client.post("/api/check", json={"indicators": "8.8.8.8"}).get_json()["results"][0]
    stored = datetime.fromisoformat(result["stored_at"].rstrip("Z"))
    expires = datetime.fromisoformat(result["expires_at"].rstrip("Z"))
    assert (expires - stored).total_seconds() == 2 * 3600


def test_changing_provider_clears_cache(client):
    client.post("/api/check", json={"indicators": "8.8.8.8"})
    data = client.put("/api/settings", json={"values": {"virustotal_enabled": False}}).get_json()
    assert data["cache_cleared"] == 1


def test_disabled_provider_is_skipped(client):
    client.put("/api/settings", json={"values": {"abuseipdb_enabled": False}})
    results = client.post("/api/check", json={"indicators": "8.8.8.8"}).get_json()["results"][0]["results"]
    abuse = next(r for r in results if r["provider"] == "AbuseIPDB")
    assert abuse["status"] == "skipped"
    assert "desativada" in abuse["summary"]


def test_clearing_base_keeps_settings(client):
    client.put("/api/settings", json={"values": {"cache_ttl_hours": 5}})
    client.delete("/api/iocs")
    general = client.get("/api/settings").get_json()["general"]
    assert next(g for g in general if g["key"] == "cache_ttl_hours")["value"] == 5
