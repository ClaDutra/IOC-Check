"""Testa os detalhes extraídos dos relatórios do URLScan.io e do AbuseIPDB."""

import copy
import json
from pathlib import Path

from app.services.report_parsers import analyze_abuseipdb, analyze_urlscan_report
from tests.test_providers import FakeResponse, fake_http, run  # noqa: F401  (fixture)

# Relatório real de uma varredura do URLScan.io: URL que entrega o malware Mozi (ELF/MIPS)
MOZI_REPORT = json.loads((Path(__file__).parent / "fixtures" / "urlscan_result_mozi.json").read_text("utf-8"))
MOZI_SHA256 = "4293c1d8574dc87c58360d6bac3daa182f64f7785c9d41da5e0741d2b1817fc7"


def flag_texts(result):
    return [f["text"] for f in result["flags"]]


def test_urlscan_detects_executable_download():
    result = analyze_urlscan_report(MOZI_REPORT)
    assert "Baixa arquivo executável: Mozi.m" in flag_texts(result)
    # Executável servido direto de um IP e marcado pelos mecanismos de IA -> malicioso
    assert result["verdict"] == "malicious"
    assert result["executables"] == 1

    downloads = next(s for s in result["sections"] if s["title"] == "Arquivos baixados pela página")
    assert "ELF 32-bit" in downloads["rows"][0]["text"]
    assert downloads["rows"][0]["check"] == MOZI_SHA256  # vira link "verificar" no front


def test_urlscan_context_facts_and_flags():
    result = analyze_urlscan_report(MOZI_REPORT)
    facts = {f["label"]: f["value"] for f in result["facts"]}
    assert facts["Rede (ASN)"] == "AS7311 · FRONTIER - Frontier Networks Inc, CA"
    assert facts["IP"] == "45.2.24.40 (Montreal, CA)"
    assert facts["DNS reverso"] == "cbl-45-2-24-40.yyz.frontiernetworks.ca"
    texts = flag_texts(result)
    assert "Página sem HTTPS" in texts
    assert "Servido diretamente por endereço IP, sem domínio" in texts
    assert any("Mecanismos de detecção" in t for t in texts)
    screenshot = next(f for f in result["facts"] if f["label"] == "Captura de tela")
    assert screenshot["href"].startswith("https://urlscan.io/screenshots/")


def test_urlscan_redirect_chain_and_brand():
    report = copy.deepcopy(MOZI_REPORT)
    report["meta"]["processors"]["download"]["data"] = []
    report["verdicts"]["engines"]["malicious"] = False
    report["verdicts"]["overall"]["brands"] = [{"name": "Banco Exemplo"}]
    report["data"]["requests"] = [{
        "request": {
            "type": "Document",
            "request": {"url": "https://login-falso.example/entrar"},
            "redirectResponse": {"url": "http://encurtador.example/abc", "status": 301},
        }
    }]

    result = analyze_urlscan_report(report)
    texts = flag_texts(result)
    assert "Redireciona 1 vez(es)" in texts
    assert "Imita a marca: Banco Exemplo" in texts
    assert result["verdict"] == "malicious"
    chain = next(s for s in result["sections"] if s["title"] == "Cadeia de redirecionamentos")
    assert chain["rows"][0]["text"] == "301 http://encurtador.example/abc → https://login-falso.example/entrar"


def test_urlscan_clean_page_stays_clean():
    report = copy.deepcopy(MOZI_REPORT)
    report["meta"]["processors"]["download"]["data"] = []
    report["verdicts"]["engines"]["malicious"] = False
    result = analyze_urlscan_report(report)
    assert result["verdict"] == "clean"
    assert not any(f["level"] == "bad" for f in result["flags"])


def test_urlscan_provider_fetches_full_report(app, fake_http):
    fake_http["response"] = {
        "/api/v1/search/": FakeResponse(200, {
            "total": 1,
            "results": [{"_id": "01a12732-6214-75bc-8961-b48c48f3eda0", "verdicts": {"overall": {"malicious": False}}}],
        }),
        "/api/v1/result/": FakeResponse(200, MOZI_REPORT),
    }
    result = run(app, "urlscan", "http://45.2.24.40:59399/Mozi.m", "url", key="")

    assert result["verdict"] == "malicious"
    assert "baixa 1 executável(is)" in result["summary"]
    assert "Baixa arquivo executável: Mozi.m" in flag_texts(result)
    assert fake_http["calls"][1][1].endswith("/api/v1/result/01a12732-6214-75bc-8961-b48c48f3eda0/")


def test_urlscan_report_failure_keeps_search_result(app, fake_http):
    fake_http["response"] = {
        "/api/v1/search/": FakeResponse(200, {"total": 1, "results": [{"_id": "abc"}]}),
        "/api/v1/result/": FakeResponse(404, {}),
    }
    result = run(app, "urlscan", "example.com", "domain", key="")
    assert result["status"] == "ok"
    assert "Relatório detalhado da última varredura indisponível" in flag_texts(result)


ABUSE_DATA = {
    "abuseConfidenceScore": 100,
    "totalReports": 3,
    "isTor": True,
    "isWhitelisted": False,
    "usageType": "Data Center/Web Hosting/Transit",
    "isp": "Exemplo Hosting",
    "countryName": "Germany",
    "numDistinctUsers": 3,
    "lastReportedAt": "2026-10-09T12:00:00+00:00",
    "reports": [
        {"reportedAt": "2026-10-09T12:00:00+00:00", "categories": [18, 22], "comment": "SSH brute force"},
        {"reportedAt": "2026-10-08T12:00:00+00:00", "categories": [18], "comment": "x" * 300},
        {"reportedAt": "2026-10-07T12:00:00+00:00", "categories": [14], "comment": ""},
    ],
}


def test_abuseipdb_categories_tor_and_reports():
    result = analyze_abuseipdb(ABUSE_DATA)
    texts = flag_texts(result)
    assert "Nó de saída da rede Tor" in texts
    assert "Endereço de datacenter/hospedagem" in texts
    assert "Denunciado por: Força bruta (2), SSH (1), Varredura de portas (1)" in texts

    facts = {f["label"]: f["value"] for f in result["facts"]}
    assert facts["País"] == "Germany"
    assert facts["Denunciantes distintos"] == "3"

    rows = result["sections"][0]["rows"]
    assert rows[0]["text"].startswith("2026-10-09 · Força bruta, SSH · SSH brute force")
    assert len(rows[1]["text"]) < 200  # comentários longos são truncados


def test_abuseipdb_provider_requests_verbose(app, fake_http):
    fake_http["response"] = FakeResponse(200, {"data": ABUSE_DATA})
    result = run(app, "abuseipdb", "45.33.32.156", "ipv4")
    assert result["verdict"] == "malicious"
    assert "nó de saída Tor" in result["summary"]
    assert "verbose" in fake_http["calls"][0][2]["params"]
