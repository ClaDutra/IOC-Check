"""Testa a interpretação das respostas de cada fonte, simulando as APIs (sem rede)."""

import pytest
import requests

from app.services import providers


class FakeResponse:
    def __init__(self, status_code=200, payload=None, headers=None):
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}

    def json(self):
        return self._payload


@pytest.fixture
def fake_http(monkeypatch):
    """Substitui requests.get/post e registra as chamadas feitas."""
    calls = []
    state = {"response": FakeResponse()}

    def fake(method):
        def handler(url, **kwargs):
            calls.append((method, url, kwargs))
            response = state["response"]
            # Um dicionário {trecho da URL: resposta} permite simular várias chamadas
            if isinstance(response, dict):
                response = next(r for part, r in response.items() if part in url)
            if isinstance(response, Exception):
                raise response
            return response
        return handler

    monkeypatch.setattr(providers.requests, "get", fake("GET"))
    monkeypatch.setattr(providers.requests, "post", fake("POST"))
    state["calls"] = calls
    return state


def run(app, provider_id, value, ioc_type, key="chave-teste"):
    with app.test_request_context():
        from app.extensions import db
        from app.models import Setting

        db.session.merge(Setting(key=f"{provider_id}_api_key", value=key))
        db.session.merge(Setting(key=f"{provider_id}_enabled", value="1"))
        db.session.commit()
        result = providers.run_provider(providers.PROVIDERS_BY_ID[provider_id], value, ioc_type)
        db.session.commit()  # como o app faz ao fim de cada verificação (grava o consumo da cota)
        return result


def test_threatfox_malicious(app, fake_http):
    fake_http["response"] = FakeResponse(200, {
        "query_status": "ok",
        "data": [
            {"ioc": "45.33.32.15:443", "confidence_level": 90, "malware_printable": "Cobalt Strike",
             "threat_type": "botnet_cc", "tags": ["c2"], "first_seen": "2026-01-01 10:00:00 UTC"},
            {"ioc": "45.33.32.156:80", "confidence_level": 100, "malware_printable": "Outro"},
        ],
    })
    result = run(app, "threatfox", "45.33.32.15", "ipv4")
    assert result["status"] == "ok"
    assert result["verdict"] == "malicious"
    assert result["score"] == 90  # o registro de 45.33.32.156 foi ignorado
    assert result["details"]["malware"] == ["Cobalt Strike"]
    method, url, kwargs = fake_http["calls"][0]
    assert method == "POST" and kwargs["headers"]["Auth-Key"] == "chave-teste"


def test_threatfox_no_result(app, fake_http):
    fake_http["response"] = FakeResponse(200, {"query_status": "no_result"})
    assert run(app, "threatfox", "example.com", "domain")["status"] == "not_found"


def test_threatfox_hash_uses_search_hash(app, fake_http):
    fake_http["response"] = FakeResponse(200, {"query_status": "no_result"})
    run(app, "threatfox", "44d88612fea8a8f36de82e1278abb02f", "md5")
    assert fake_http["calls"][0][2]["json"]["query"] == "search_hash"


def test_hybrid_analysis_uses_search_and_overview(app, fake_http):
    fake_http["response"] = {
        "/search/hash": FakeResponse(200, {"sha256s": ["a" * 64], "reports": [{"state": "SUCCESS", "verdict": "malicious"}]}),
        "/overview/": FakeResponse(200, {"verdict": "malicious", "threat_score": 95, "vx_family": "Trojan.Generic"}),
    }
    result = run(app, "hybrid_analysis", "44d88612fea8a8f36de82e1278abb02f", "md5")
    assert result["verdict"] == "malicious"
    assert result["score"] == 95
    assert "Trojan.Generic" in result["summary"]
    assert fake_http["calls"][1][1].endswith("/overview/" + "a" * 64)


def test_hybrid_analysis_only_checks_hashes(app, fake_http):
    # Chaves gratuitas ("restricted") não têm acesso à busca por IP, domínio ou URL
    result = run(app, "hybrid_analysis", "example.com", "domain")
    assert result["status"] == "skipped"
    assert fake_http["calls"] == []


def test_hybrid_analysis_unknown_hash(app, fake_http):
    fake_http["response"] = FakeResponse(200, {"sha256s": [], "reports": []})
    assert run(app, "hybrid_analysis", "a" * 64, "sha256")["status"] == "not_found"


def test_urlscan_counts_malicious(app, fake_http):
    fake_http["response"] = FakeResponse(200, {
        "total": 3,
        "results": [
            {"_id": "uuid-1", "verdicts": {"overall": {"malicious": True}}, "result": "https://urlscan.io/api/v1/result/uuid-1/"},
            {"verdicts": {"overall": {"malicious": True}}},
            {"verdicts": {"overall": {"malicious": False}}},
        ],
    })
    result = run(app, "urlscan", "phishing.example", "domain", key="")
    assert result["verdict"] == "malicious"
    assert result["link"] == "https://urlscan.io/result/uuid-1/"  # página do relatório, não a API
    assert "API-Key" not in fake_http["calls"][0][2]["headers"]


def test_urlscan_does_not_support_md5(app, fake_http):
    result = run(app, "urlscan", "44d88612fea8a8f36de82e1278abb02f", "md5")
    assert result["status"] == "skipped"
    assert fake_http["calls"] == []


def test_invalid_key_and_connection_errors(app, fake_http):
    fake_http["response"] = FakeResponse(401, {})
    assert "inválida" in run(app, "virustotal", "8.8.8.8", "ipv4")["summary"]

    fake_http["response"] = requests.ConnectionError()
    result = run(app, "abuseipdb", "8.8.8.8", "ipv4")
    assert result["status"] == "error" and "conexão" in result["summary"]


def test_unexpected_format_is_reported(app, fake_http):
    fake_http["response"] = FakeResponse(200, {"query_status": "ok", "data": [{"confidence_level": "alto"}]})
    result = run(app, "threatfox", "45.33.32.15", "ipv4")
    assert result["status"] in ("error", "not_found")


def test_private_ip_is_never_sent(app, fake_http):
    assert run(app, "virustotal", "192.168.0.10", "ipv4")["status"] == "skipped"
    assert fake_http["calls"] == []
