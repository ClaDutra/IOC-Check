"""Logs da aplicação, link direto para a fonte, evidência em texto, marca d'água e
detalhes do IOC a partir da Minha base."""

import io
import json

from PIL import Image

from app.models import AppLog
from app.services import evidence, page_capture
from tests.test_providers import FakeResponse, fake_http, run  # noqa: F401  (fixture)


def check(client, value):
    return client.post("/api/check", json={"indicators": value}).get_json()["results"][0]


def by_provider(result, name):
    return next(r for r in result["results"] if r["provider"] == name)


# --- Link direto para a fonte ---------------------------------------------------

def test_source_link_even_without_key(client):
    result = check(client, "8.8.8.8")
    vt = by_provider(result, "VirusTotal")
    assert vt["status"] == "skipped"  # sem chave nos testes
    assert vt["link"] == "https://www.virustotal.com/gui/search/8.8.8.8"
    assert by_provider(result, "AbuseIPDB")["link"] == "https://www.abuseipdb.com/check/8.8.8.8"
    assert by_provider(result, "IPinfo")["link"] == "https://ipinfo.io/8.8.8.8"
    assert by_provider(result, "Hybrid Analysis")["link"] is None  # IP não é tipo do Hybrid Analysis


def test_source_link_when_api_fails(app, fake_http):
    fake_http["response"] = FakeResponse(500, {})
    result = run(app, "threatfox", "bad.example", "domain")
    assert result["status"] == "error"
    assert result["link"] == "https://threatfox.abuse.ch/browse.php?search=ioc%3Abad.example"
    fake_http["response"] = FakeResponse(404, {})
    result = run(app, "hybrid_analysis", "a" * 64, "sha256")
    assert result["link"] == "https://www.hybrid-analysis.com/search?query=" + "a" * 64


# --- Logs -------------------------------------------------------------------------

def test_actions_and_api_calls_are_logged_without_keys(app, client, fake_http):
    valor_falso = "valor-ficticio-de-teste-123456"
    client.put("/api/settings", json={"values": {"abuseipdb_api_key": valor_falso}})
    # resposta que (por absurdo) devolve a chave: ela precisa ser mascarada no log
    fake_http["response"] = FakeResponse(200, {"data": {"abuseConfidenceScore": 0, "eco": valor_falso}},
                                         headers={"X-RateLimit-Remaining": "999"})
    check(client, "151.243.24.56")

    logs = client.get("/api/logs").get_json()
    api = [i for i in logs["items"] if i["category"] == "api"]
    assert api and api[0]["source"] == "abuseipdb" and api[0]["status_code"] == 200
    assert api[0]["details"]["requisicao"]["params"]["ipAddress"] == "151.243.24.56"
    assert api[0]["details"]["resposta"]["limite"] == {"X-RateLimit-Remaining": "999"}
    actions = [i["message"] for i in logs["items"] if i["category"] == "acao"]
    assert any(m.startswith("Verificou 151.243.24.56") for m in actions)
    assert any(m.startswith("Alterou: abuseipdb_api_key") for m in actions)

    with app.app_context():
        everything = " ".join((log.message or "") + (log.details_json or "") for log in AppLog.query.all())
    assert valor_falso not in everything and "•••" in everything
    assert "Key" not in json.dumps(api[0]["details"]["requisicao"])  # cabeçalhos nunca são gravados


def test_failed_route_does_not_commit_partial_changes(client):
    ioc_id = client.post("/api/iocs", json={"value": "bad.example"}).get_json()["id"]
    assert client.put(f"/api/iocs/{ioc_id}", json={"description": "nova", "severity": "x"}).status_code == 400
    assert client.get(f"/api/iocs/{ioc_id}").get_json()["description"] == ""


def test_logs_filters_export_and_clear(client):
    check(client, "8.8.8.8")
    client.post("/api/iocs", json={"value": "1.2.3.4"})
    only = client.get("/api/logs?category=acao&source=minha base").get_json()
    assert only["total"] == 1 and "1.2.3.4" in only["items"][0]["message"]
    assert client.get("/api/logs?q=8.8.8.8").get_json()["total"] >= 1
    export = client.get("/api/logs/export")
    assert export.mimetype == "application/json" and json.loads(export.data)
    assert client.delete("/api/logs").get_json()["removed"] >= 2
    assert client.get("/api/logs").get_json()["total"] == 0
    assert client.get("/logs").status_code == 200


# --- Evidência em texto e marca d'água ---------------------------------------------

def test_text_evidence(client):
    client.post("/api/iocs", json={"value": "bad.example", "severity": "critical"})
    log_id = check(client, "bad.example")["history_id"]
    full = client.get(f"/api/evidence/{log_id}.txt")
    text = full.get_data(as_text=True)
    assert full.mimetype == "text/plain" and "Indicador: bad.example" in text
    assert "github.com/ClaDutra/IOC-Check" in text and "Base local" not in text
    one = client.get(f"/api/evidence/{log_id}.txt?provider=VirusTotal").get_data(as_text=True)
    assert "## VirusTotal" in one and "virustotal.com/gui/search/bad.example" in one
    assert client.get(f"/api/evidence/{log_id}.txt?provider=Base local").status_code == 404
    download = client.get(f"/api/evidence/{log_id}.txt?download=1")
    assert download.headers["Content-Disposition"].startswith('attachment; filename="evidencia_bad.example')


def test_watermark_keeps_size_and_marks_image():
    plain = Image.new("RGB", (900, 500), (255, 255, 255))
    marked = evidence.watermark(plain)
    assert marked.size == plain.size and marked.getbbox() and marked.tobytes() != plain.tobytes()


def test_page_text_saved_with_print(app, client):
    log_id = check(client, "8.8.8.8")["history_id"]
    assert client.get(f"/api/capture/{log_id}.txt?provider=VirusTotal").status_code == 404
    with app.app_context():
        png, meta = page_capture.files(log_id, "VirusTotal")
        buffer = io.BytesIO()
        Image.new("RGB", (400, 300), (240, 240, 240)).save(buffer, format="PNG")
        png.write_bytes(buffer.getvalue())
        info = {"provider": "VirusTotal", "url": "https://www.virustotal.com/gui/ip-address/8.8.8.8",
                "title": "8.8.8.8", "captured_at": "2026-10-24T12:00:00Z"}
        meta.write_text(json.dumps(info), "utf-8")
        page_capture.text_file(log_id, "VirusTotal").write_text(
            page_capture.page_text_document(info, "Community Score\n\n\n\n0 / 94"), "utf-8")
    detail = client.get(f"/api/history/{log_id}").get_json()
    assert detail["captures"]["VirusTotal"]["text"] == f"/api/capture/{log_id}.txt?provider=VirusTotal"
    text = client.get(detail["captures"]["VirusTotal"]["text"]).get_data(as_text=True)
    assert "Community Score\n\n0 / 94" in text and "Endereço: https://www.virustotal.com" in text
    served = client.get(f"/api/capture/{log_id}.png?provider=VirusTotal")
    assert Image.open(io.BytesIO(served.data)).size == (400, 300)


# --- Detalhes do IOC a partir da Minha base ------------------------------------------

def test_ioc_details_with_latest_check(client):
    ioc_id = client.post("/api/iocs", json={"value": "bad.example", "tags": "phishing"}).get_json()["id"]
    empty = client.get(f"/api/iocs/{ioc_id}/details").get_json()
    assert empty["latest"] is None and empty["queries"] == []

    check(client, "bad.example")
    check(client, "bad.example")
    data = client.get(f"/api/iocs/{ioc_id}/details").get_json()
    assert data["ioc"]["tags"] == ["phishing"]
    assert data["total_queries"] == 2 and data["latest"]["verdict"] == "malicious"
    assert any(r["provider"] == "VirusTotal" for r in data["latest"]["results"])
    assert client.get("/api/iocs/9999/details").status_code == 404
