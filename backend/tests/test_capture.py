"""Print da página da fonte (services/page_capture.py), sem abrir navegador de verdade."""

import io
import json
from datetime import timedelta

from PIL import Image

from app.models import iso, utcnow
from app.services import page_capture


def fake_png():
    buffer = io.BytesIO()
    Image.new("RGB", (1366, 900), (240, 240, 240)).save(buffer, format="PNG")
    return buffer.getvalue()


def checked_ip(client, monkeypatch):
    # Simula uma resposta do AbuseIPDB para o resultado ter o link da página da fonte
    client.put("/api/settings", json={"values": {"abuseipdb_api_key": "chave-teste-123456"}})

    class Response:
        status_code, headers = 200, {}

        def json(self):
            return {"data": {"abuseConfidenceScore": 0, "totalReports": 5}}

    import app.services.providers as providers
    monkeypatch.setattr(providers.requests, "get", lambda url, **kw: Response())
    return client.post("/api/check", json={"indicators": "151.243.24.56"}).get_json()["results"][0]


def test_detects_human_verification_pages():
    assert page_capture.is_challenge("Um momento…", "Confirme que é humano")
    assert page_capture.is_challenge("ThreatFox | Checking your browser", "")
    assert page_capture.is_challenge("AbuseIPDB", "Executando verificação de segurança")
    # Página normal que apenas cita "captcha" não é confundida com verificação
    assert not page_capture.is_challenge("151.243.24.56 | AbuseIPDB", "Protected by reCAPTCHA. 5 reports")


def test_only_source_pages_are_allowed():
    assert page_capture.is_allowed("https://www.abuseipdb.com/check/151.243.24.56")
    assert page_capture.is_allowed("https://urlscan.io/result/abc/")
    assert not page_capture.is_allowed("http://www.abuseipdb.com/check/1.1.1.1")  # sem HTTPS
    assert not page_capture.is_allowed("https://site-qualquer.example/")


def write_capture(log_id, provider="AbuseIPDB", url="https://www.abuseipdb.com/check/151.243.24.56", captured_at=None):
    image, meta = page_capture.files(log_id, provider)
    image.write_bytes(fake_png())
    meta.write_text(json.dumps({"provider": provider, "url": url, "title": "t", "needed_human": True,
                                "captured_at": captured_at or iso(utcnow())}), "utf-8")


def test_capture_route_saves_and_serves_print(client, monkeypatch):
    result = checked_ip(client, monkeypatch)
    log_id = result["history_id"]

    def fake_capture(log, provider, url):
        assert url == "https://www.abuseipdb.com/check/151.243.24.56"
        write_capture(log, provider, url)
        return page_capture.info(log, provider)

    monkeypatch.setattr(page_capture, "capture", fake_capture)
    data = client.post(f"/api/capture/{log_id}?provider=AbuseIPDB").get_json()
    assert data["needed_human"] is True
    assert data["image"] == f"/api/capture/{log_id}.png?provider=AbuseIPDB"

    image = client.get(data["image"])
    assert image.status_code == 200 and image.mimetype == "image/png"
    download = client.get(data["image"] + "&download=1")
    assert download.headers["Content-Disposition"].startswith('attachment; filename="print_abuseipdb_151.243.24.56_')

    # O print fica na consulta do histórico, com os dados completos
    detail = client.get(f"/api/history/{log_id}").get_json()
    assert detail["captures"]["AbuseIPDB"]["image"] == data["image"]
    # Como o cache: a próxima consulta do mesmo indicador já traz o print, copiado para ela
    again = client.post("/api/check", json={"indicators": "151.243.24.56"}).get_json()["results"][0]
    reused = again["captures"]["AbuseIPDB"]
    assert again["history_id"] != log_id
    assert reused["image"] == f"/api/capture/{again['history_id']}.png?provider=AbuseIPDB"
    assert reused["reused_from"] == log_id and reused["captured_at"] == data["captured_at"]
    assert reused["expired"] is False and reused["expires_at"]


def test_capture_errors(client, monkeypatch):
    result = checked_ip(client, monkeypatch)
    log_id = result["history_id"]
    # Base local não tem página pública; fonte inexistente dá 404
    assert client.post(f"/api/capture/{log_id}?provider=Base local").status_code == 400
    assert client.post(f"/api/capture/{log_id}?provider=Inexistente").status_code == 404
    assert client.get(f"/api/capture/{log_id}.png?provider=AbuseIPDB").status_code == 404
    assert client.post("/api/capture/9999?provider=AbuseIPDB").status_code == 404

    def busy(*args):
        raise page_capture.CaptureBusy("Já existe uma captura em andamento")

    monkeypatch.setattr(page_capture, "capture", busy)
    assert client.post(f"/api/capture/{log_id}?provider=AbuseIPDB").status_code == 409


def test_print_survives_cache_and_is_removed_with_history(app, client, monkeypatch):
    log_id = checked_ip(client, monkeypatch)["history_id"]
    with app.app_context():
        write_capture(log_id)
    client.delete("/api/cache")
    assert client.get(f"/api/capture/{log_id}.png?provider=AbuseIPDB").status_code == 200

    client.delete(f"/api/history/{log_id}")
    with app.app_context():
        assert not page_capture.files(log_id, "AbuseIPDB")[0].exists()


def test_reused_print_follows_cache_ttl(app, client, monkeypatch):
    log_id = checked_ip(client, monkeypatch)["history_id"]
    old = iso(utcnow() - timedelta(hours=25))  # prazo padrão do cache: 24h
    with app.app_context():
        write_capture(log_id, captured_at=old)
    again = client.post("/api/check", json={"indicators": "151.243.24.56"}).get_json()["results"][0]
    assert again["captures"] == {}  # fora do prazo: não é reaproveitado
    assert client.get(f"/api/history/{log_id}").get_json()["captures"]["AbuseIPDB"]["expired"] is True

    # Com um prazo maior nas configurações, o mesmo print volta a valer
    client.put("/api/settings", json={"values": {"cache_ttl_hours": 48}})
    again = client.post("/api/check", json={"indicators": "151.243.24.56"}).get_json()["results"][0]
    assert again["captures"]["AbuseIPDB"]["reused_from"] == log_id


def test_reused_print_survives_original_and_force_refresh_skips(app, client, monkeypatch):
    log_id = checked_ip(client, monkeypatch)["history_id"]
    with app.app_context():
        write_capture(log_id)
    again = client.post("/api/check", json={"indicators": "151.243.24.56"}).get_json()["results"][0]
    client.delete(f"/api/history/{log_id}")
    assert client.get(again["captures"]["AbuseIPDB"]["image"]).status_code == 200

    fresh = client.post("/api/check", json={"indicators": "151.243.24.56", "force_refresh": True}).get_json()
    assert fresh["results"][0]["captures"] == {}


def test_manual_print_upload(client, monkeypatch):
    log_id = checked_ip(client, monkeypatch)["history_id"]
    url = f"/api/capture/{log_id}/manual?provider=AbuseIPDB"
    data = client.post(url, data={"image": (io.BytesIO(fake_png()), "print.png"),
                                  "text": "151.243.24.56 was found in our database!"},
                       content_type="multipart/form-data").get_json()
    assert data["manual"] is True and data["url"] == "https://www.abuseipdb.com/check/151.243.24.56"
    assert data["image"] == f"/api/capture/{log_id}.png?provider=AbuseIPDB"
    assert "found in our database" in client.get(data["text"]).get_data(as_text=True)
    image = Image.open(io.BytesIO(client.get(data["image"]).data))
    assert image.format == "PNG" and image.size == (1366, 900)
    # fica no histórico e é reaproveitado como o cache
    assert client.get(f"/api/history/{log_id}").get_json()["captures"]["AbuseIPDB"]["manual"] is True
    again = client.post("/api/check", json={"indicators": "151.243.24.56"}).get_json()["results"][0]
    assert again["captures"]["AbuseIPDB"]["reused_from"] == log_id


def test_manual_print_rejects_bad_input(client, monkeypatch):
    log_id = checked_ip(client, monkeypatch)["history_id"]
    url = f"/api/capture/{log_id}/manual?provider=AbuseIPDB"
    assert client.post(url, data={}, content_type="multipart/form-data").status_code == 400
    bad = client.post(url, data={"image": (io.BytesIO(b"<script>nao sou imagem</script>"), "x.png")},
                      content_type="multipart/form-data")
    assert bad.status_code == 400 and "imagem válida" in bad.get_json()["error"]
    local = f"/api/capture/{log_id}/manual?provider=Base local"
    assert client.post(local, data={"image": (io.BytesIO(fake_png()), "p.png")},
                       content_type="multipart/form-data").status_code == 404
    jpeg = io.BytesIO()
    Image.new("RGB", (300, 200), (10, 20, 30)).save(jpeg, format="JPEG")
    ok = client.post(url, data={"image": (io.BytesIO(jpeg.getvalue()), "p.jpg")}, content_type="multipart/form-data")
    assert ok.status_code == 200 and "text" not in ok.get_json()  # sem texto enviado, sem texto salvo
