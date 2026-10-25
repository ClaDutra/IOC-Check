"""Prints de evidência (PNG) gerados a partir das consultas do histórico."""

import io

from PIL import Image

from app.services import evidence


def checked(client, value="8.8.8.8"):
    return client.post("/api/check", json={"indicators": value}).get_json()["results"][0]


def png(response):
    assert response.status_code == 200
    assert response.mimetype == "image/png"
    return Image.open(io.BytesIO(response.data))


def test_check_returns_history_id(client):
    assert isinstance(checked(client)["history_id"], int)


def test_evidence_survives_cache_clearing(client):
    result = checked(client)
    client.delete("/api/cache")
    png(client.get(f"/api/evidence/{result['history_id']}.png"))


def test_full_evidence_image(client):
    result = checked(client)
    image = png(client.get(f"/api/evidence/{result['history_id']}.png"))
    assert image.width == 1200 and image.height > 300


def test_single_source_evidence_and_download(client, monkeypatch):
    import app.services.providers as providers

    class Response:
        status_code, headers = 200, {}

        def json(self):
            return {"data": {"abuseConfidenceScore": 90, "totalReports": 12}}

    client.put("/api/settings", json={"values": {"abuseipdb_api_key": "chave-teste-123456"}})
    monkeypatch.setattr(providers.requests, "get", lambda url, **kw: Response())
    result = checked(client, "151.243.24.56")
    url = f"/api/evidence/{result['history_id']}.png?provider=AbuseIPDB"
    png(client.get(url))
    download = client.get(url + "&download=1")
    assert download.headers["Content-Disposition"].startswith('attachment; filename="evidencia_151.243.24.56_abuseipdb_')


def test_local_base_is_not_in_evidence(app, client):
    client.post("/api/iocs", json={"value": "bad.example", "severity": "critical", "tags": "phishing"})
    result = checked(client, "bad.example")
    assert result["verdict"] == "malicious"  # a base local continua valendo na verificação
    assert client.get(f"/api/evidence/{result['history_id']}.png?provider=Base local").status_code == 404

    from app.extensions import db
    from app.models import QueryLog

    with app.app_context():
        entry = db.session.get(QueryLog, result["history_id"])
        assert all(r["provider"] != "Base local" for r in evidence.tool_results(entry))
        # Sem ferramentas com veredito, o print não herda o "malicioso" da base local
        assert evidence.tool_verdict(evidence.tool_results(entry)) == ("unknown", 0)
    png(client.get(f"/api/evidence/{result['history_id']}.png"))


def test_unknown_entry_or_provider(client):
    result = checked(client)
    assert client.get("/api/evidence/9999.png").status_code == 404
    assert client.get(f"/api/evidence/{result['history_id']}.png?provider=Inexistente").status_code == 404


def test_long_values_and_screenshot_are_handled(app, monkeypatch):
    # Textos longos (URLs, hashes) quebram de linha; a captura do URLScan.io entra no cartão
    shot = io.BytesIO()
    Image.new("RGB", (1600, 1200), (200, 200, 220)).save(shot, format="PNG")
    monkeypatch.setattr(evidence, "_fetch_image", lambda url: shot.getvalue())

    class Entry:
        indicator = "http://" + "a" * 300 + ".example/" + "b" * 200
        ioc_type, verdict, score = "url", "malicious", 90
        from datetime import datetime
        stored_at = datetime(2026, 10, 11, 12, 0)
        results = [{
            "provider": "URLScan.io", "status": "ok", "verdict": "malicious", "score": 90,
            "summary": "Resumo " * 60,
            "flags": [{"text": "Baixa arquivo executável: " + "x" * 400, "level": "bad"}] * 6,
            "facts": [{"label": "SHA256", "value": "f" * 64}, {"label": "URL final", "value": "http://" + "c" * 250}],
            "sections": [{"title": "Cadeia de redirecionamentos", "rows": [{"text": "301 a → b"}] * 14}],
            "media": [{"type": "image", "url": "https://urlscan.io/screenshots/x.png", "caption": "Captura"}],
            "link": "https://urlscan.io/result/x/",
        }]

    with app.app_context():
        image = evidence.render_source(Entry, Entry.results[0])
        assert image.width == 1200 and 1000 < image.height < 6000
        assert evidence.render_all(Entry).height > image.height - 200


def test_screenshot_only_from_urlscan():
    assert evidence._fetch_image("https://exemplo.com/imagem.png") is None
