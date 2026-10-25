"""Dados extras de VirusTotal, AbuseIPDB, ThreatFox, Hybrid Analysis e o print do URLScan.io.

Os fixtures são respostas reais das APIs (planos gratuitos) para o IP 45.2.24.40,
que distribuía o malware Mozi, e para o arquivo Mozi.m.
"""

import json
from pathlib import Path

from app.services.report_parsers import (
    analyze_abuseipdb,
    analyze_hybrid_overview,
    analyze_threatfox,
    analyze_virustotal,
)
from tests.test_providers import FakeResponse, fake_http, run  # noqa: F401  (fixture)

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name):
    return json.loads((FIXTURES / name).read_text("utf-8"))


def texts(items, key="text"):
    return [item[key] for item in items]


def facts(result):
    return {f["label"]: f["value"] for f in result["facts"]}


# --- VirusTotal --------------------------------------------------------------

def test_virustotal_ip_context_from_real_response():
    attributes = fixture("virustotal_ip_45.2.24.40.json")["data"]["attributes"]
    result = analyze_virustotal(attributes, "ipv4")
    info = facts(result)
    assert info["Rede (ASN)"] == "AS7311 · Frontier Networks Inc"
    assert info["Registro regional"] == "ARIN"
    engines = result["sections"][0]
    assert engines["title"] == "Mecanismos que apontaram risco (5)"
    assert "CRDF: malicious" in texts(engines["rows"])


def test_virustotal_url_brand_and_redirects():
    attributes = {
        "url": "http://encurtador.example/x",
        "last_final_url": "https://banco-falso.example/login",
        "redirection_chain": ["http://encurtador.example/x"],
        "title": "Acesse sua conta",
        "targeted_brand": {"Phishtank": "Banco Exemplo"},
        "categories": {"Forcepoint ThreatSeeker": "phishing and other frauds"},
    }
    result = analyze_virustotal(attributes, "url")
    flags = texts(result["flags"])
    assert "Imita a marca: Banco Exemplo" in flags
    assert "Redireciona para outro endereço" in flags
    assert any(f.startswith("Categorizado como: phishing") for f in flags)
    assert result["verdict"] == "malicious"


def test_virustotal_file_sandboxes_and_yara():
    attributes = {
        "meaningful_name": "Mozi.m",
        "type_description": "ELF",
        "popular_threat_classification": {"suggested_threat_label": "trojan.mirai/mozi"},
        "sandbox_verdicts": {"Zenbox Linux": {"category": "malicious", "sandbox_name": "Zenbox Linux",
                                              "malware_classification": ["MALWARE"], "malware_names": ["Mozi"]}},
        "crowdsourced_yara_results": [{"rule_name": "Mozi_Botnet", "source": "github.com/exemplo"}],
        "sigma_analysis_stats": {"critical": 1, "high": 2},
    }
    result = analyze_virustotal(attributes, "sha256")
    flags = texts(result["flags"])
    assert "Classificação mais comum: trojan.mirai/mozi" in flags
    assert "3 regra(s) Sigma de severidade alta ou crítica" in flags
    rows = {s["title"]: texts(s["rows"]) for s in result["sections"]}
    assert rows["Veredito das sandboxes"] == ["Zenbox Linux: malicious (Mozi)"]
    assert rows["Regras YARA que identificaram o arquivo"] == ["Mozi_Botnet (github.com/exemplo)"]


# --- AbuseIPDB ---------------------------------------------------------------

def test_abuseipdb_extra_fields_from_real_response():
    data = fixture("abuseipdb_check_45.2.24.40.json")["data"]
    info = facts(analyze_abuseipdb(data))
    assert info["Versão do IP"] == "IPv4"
    assert info["País"] == "Canada"
    assert "Germany" in info["Países que mais denunciaram"]
    assert "Primeira denúncia no período" in info


# --- ThreatFox ---------------------------------------------------------------

def test_threatfox_related_ioc_on_same_ip(app, fake_http):
    # Buscar o IP traz a URL de malware hospedada nele: o IP fica "suspeito"
    fake_http["response"] = FakeResponse(200, fixture("threatfox_search_45.2.24.40.json"))
    result = run(app, "threatfox", "45.2.24.40", "ipv4")
    assert result["verdict"] == "suspicious"
    assert "hospeda 1 IOC(s) de malware (Mozi)" in result["summary"]
    related = next(s for s in result["sections"] if s["title"] == "IOCs no mesmo host")
    assert related["rows"][0]["check"] == "http://45.2.24.40:59399/Mozi.m"


def test_threatfox_exact_match_context():
    entry = fixture("threatfox_search_45.2.24.40.json")["data"][0]
    result = analyze_threatfox([entry])
    info = facts(result)
    assert info["Tipo de ameaça"].startswith("Indicator that identifies a malware distribution server")
    assert info["Reportado por"] == "HoneyLabs"
    malpedia = next(f for f in result["facts"] if f["label"] == "Ficha do malware (Malpedia)")
    assert malpedia["href"].startswith("https://malpedia.caad.fkie.fraunhofer.de/")


# --- Hybrid Analysis ---------------------------------------------------------

def test_hybrid_overview_from_real_response():
    overview = fixture("hybrid_overview_mozi.json")
    reports = fixture("hybrid_search_hash_mozi.json")["reports"]
    result = analyze_hybrid_overview(overview, reports)
    flags = texts(result["flags"])
    assert result["verdict"] == "malicious"
    assert result["score"] == 85  # sem threat_score, usa a detecção dos antivírus
    assert "Família: Trojan/Linux.Mirai" in flags
    assert any("não conseguiu executar" in f for f in flags)
    assert facts(result)["Detecção nos antivírus"] == "85%"
    origins = next(s for s in result["sections"] if s["title"] == "Endereços de onde o arquivo foi baixado")
    assert origins["rows"][0]["check"].startswith("http://")


# --- URLScan.io: captura de tela -------------------------------------------

def test_urlscan_returns_screenshot(app, fake_http):
    search = fixture("urlscan_search_45.2.24.40.json")
    fake_http["response"] = {
        "/api/v1/search/": FakeResponse(200, search),
        "/api/v1/result/": FakeResponse(404, {}),
    }
    result = run(app, "urlscan", "45.2.24.40", "ipv4", key="")
    media = result["media"][0]
    assert media["type"] == "image"
    assert media["url"] == search["results"][0]["screenshot"]
    assert media["url"].startswith("https://urlscan.io/screenshots/")


def test_urlscan_redirects_from_real_report():
    # Relatório real: http://google.com/ → https://google.com/ → https://www.google.com/
    from app.services.report_parsers import analyze_urlscan_report

    result = analyze_urlscan_report(fixture("urlscan_result_redirect_google.json"))
    assert "Redireciona 2 vez(es)" in texts(result["flags"])
    chain = next(s for s in result["sections"] if s["title"] == "Cadeia de redirecionamentos")
    assert texts(chain["rows"]) == [
        "307 http://google.com/ → https://google.com/",
        "301 https://google.com/ → https://www.google.com/",
    ]


def test_threatfox_domain_hosting_iocs_is_only_a_warning(app, fake_http):
    # github.com hospeda arquivos de terceiros: aviso sem tornar o domínio suspeito
    fake_http["response"] = FakeResponse(200, {"query_status": "ok", "data": [
        {"ioc": "https://github.com/usuario/repo/raw/main/stealer.exe", "malware_printable": "Unknown Stealer",
         "confidence_level": 100, "threat_type": "payload_delivery"}]})
    result = run(app, "threatfox", "github.com", "domain")
    assert result["verdict"] == "unknown"
    assert "hospeda 1 IOC(s)" in result["summary"]
    assert any(f["text"].startswith("Hospeda 1 IOC(s)") for f in result["flags"])
