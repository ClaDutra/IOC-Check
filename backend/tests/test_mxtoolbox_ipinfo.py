"""MxToolbox (MX, SPF, DMARC, PTR) e IPinfo Lite.

Os fixtures da MxToolbox são respostas reais do endpoint de teste público da API
(example.com, que não exige chave).
"""

import json
from pathlib import Path

from app.models import ProviderQuota
from app.services import quota
from app.services.report_parsers import analyze_ipinfo, analyze_mxtoolbox
from tests.test_providers import FakeResponse, fake_http, run  # noqa: F401  (fixture)

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name):
    return json.loads((FIXTURES / name).read_text("utf-8"))


def facts(result):
    return {f["label"]: f["value"] for f in result["facts"]}


MX_RESPONSES = {
    "/mx/": FakeResponse(200, fixture("mxtoolbox_mx_example.json")),
    "/spf/": FakeResponse(200, fixture("mxtoolbox_spf_example.json")),
    "/dmarc/": FakeResponse(200, fixture("mxtoolbox_dmarc_example.json")),
}


def test_mxtoolbox_parser_with_real_responses():
    lookups = {c: fixture(f"mxtoolbox_{c}_example.json") for c in ("mx", "spf", "dmarc")}
    result = analyze_mxtoolbox(lookups)
    info = facts(result)
    assert info["Registro SPF"] == "v=spf1 -all"
    assert info["Registro DMARC"].startswith("v=DMARC1;p=reject")
    # example.com publica um "MX nulo" (.): o domínio não recebe e-mail
    assert "sem servidor MX" in result["summary"] and "DMARC p=reject" in result["summary"]
    assert any(r["text"].startswith("OK · SPF") for r in result["sections"][0]["rows"])


def test_mxtoolbox_domain_uses_three_dns_lookups(app, fake_http):
    fake_http["response"] = MX_RESPONSES
    result = run(app, "mxtoolbox", "example.com", "domain")
    assert result["status"] == "ok" and result["verdict"] == "unknown"  # contexto, não reputação
    urls = [url for _m, url, _kw in fake_http["calls"]]
    assert [u.rsplit("/", 2)[1] for u in urls] == ["mx", "spf", "dmarc"]
    _m, _u, kwargs = fake_http["calls"][0]
    assert kwargs["headers"]["Authorization"] == "chave-teste"  # UUID puro, sem "Bearer"
    assert kwargs["params"] == {"argument": "example.com"}


def test_mxtoolbox_email_and_url_use_their_domain(app, fake_http):
    fake_http["response"] = MX_RESPONSES
    run(app, "mxtoolbox", "joao@example.com", "email")
    assert fake_http["calls"][0][2]["params"] == {"argument": "example.com"}
    fake_http["calls"].clear()
    run(app, "mxtoolbox", "https://example.com/login", "url")
    assert fake_http["calls"][0][2]["params"] == {"argument": "example.com"}


def test_mxtoolbox_ip_uses_single_ptr_lookup(app, fake_http):
    fake_http["response"] = FakeResponse(200, {"Failed": [], "Warnings": [], "Passed": [],
                                               "Information": [{"Domain Name": "dns.google"}]})
    result = run(app, "mxtoolbox", "8.8.8.8", "ipv4")
    assert len(fake_http["calls"]) == 1 and "/ptr/" in fake_http["calls"][0][1]
    assert facts(result)["DNS reverso (PTR)"] == "dns.google"


def test_mxtoolbox_respects_daily_free_limit(app, fake_http):
    fake_http["response"] = MX_RESPONSES
    with app.app_context():
        from app.extensions import db

        row = quota._row("mxtoolbox")
        row.day_calls = 63  # só resta 1 das 64 consultas do dia
        db.session.commit()
    result = run(app, "mxtoolbox", "example.com", "domain")
    assert len(fake_http["calls"]) == 1  # não passa do limite
    assert result["status"] == "ok" and result["transient"] is True
    assert "SPF não consultado" in result["summary"]
    assert run(app, "mxtoolbox", "example.org", "domain")["status"] == "skipped"
    with app.app_context():
        assert db.session.get(ProviderQuota, "mxtoolbox").day_calls == 64


def test_mxtoolbox_invalid_key(app, fake_http):
    fake_http["response"] = FakeResponse(401, {})
    assert run(app, "mxtoolbox", "example.com", "domain")["status"] == "error"


def test_mxtoolbox_skips_hashes(app, fake_http):
    result = run(app, "mxtoolbox", "a" * 64, "sha256")
    assert result["status"] == "skipped" and not fake_http["calls"]


IPINFO_LITE = {"ip": "8.8.8.8", "asn": "AS15169", "as_name": "Google LLC", "as_domain": "google.com",
               "country_code": "US", "country": "United States", "continent_code": "NA",
               "continent": "North America"}


def test_ipinfo_lite(app, fake_http):
    fake_http["response"] = FakeResponse(200, IPINFO_LITE)
    result = run(app, "ipinfo", "8.8.8.8", "ipv4")
    _m, url, kwargs = fake_http["calls"][0]
    assert url == "https://api.ipinfo.io/lite/8.8.8.8"
    assert kwargs["headers"]["Authorization"] == "Bearer chave-teste"
    assert result["status"] == "ok" and result["verdict"] == "unknown"
    assert result["summary"] == "AS15169 Google LLC · domínio google.com · United States (US)"
    assert facts(result)["Organização (AS)"] == "Google LLC"
    assert result["link"] == "https://ipinfo.io/8.8.8.8"


def test_ipinfo_parser_handles_missing_fields():
    assert analyze_ipinfo({"ip": "1.2.3.4"})["summary"] == "Sem informações de rede para este IP"


def test_ipinfo_only_ips_and_errors(app, fake_http):
    assert run(app, "ipinfo", "example.com", "domain")["status"] == "skipped"
    fake_http["response"] = FakeResponse(403, {})
    assert run(app, "ipinfo", "8.8.8.8", "ipv4")["status"] == "error"
    fake_http["response"] = FakeResponse(429, {})
    assert run(app, "ipinfo", "8.8.8.8", "ipv4")["transient"] is True


def test_new_sources_listed_in_settings(client):
    providers = {p["id"]: p for p in client.get("/api/settings").get_json()["providers"]}
    assert providers["mxtoolbox"]["name"] == "MxToolbox" and providers["mxtoolbox"]["key_required"]
    assert providers["ipinfo"]["name"] == "IPinfo"
    assert "64" in providers["mxtoolbox"]["usage"]["free_limits"]
