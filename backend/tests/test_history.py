"""Histórico completo (dados + prints), exportação seletiva e cache só nos bastidores."""

import io
import json
import zipfile

from PIL import Image

from app.extensions import db
from app.models import QueryLog
from app.services import history, media, page_capture


def check(client, value):
    return client.post("/api/check", json={"indicators": value}).get_json()["results"][0]


def fake_png(color=(200, 200, 220)):
    buffer = io.BytesIO()
    Image.new("RGB", (40, 30), color).save(buffer, format="PNG")
    return buffer.getvalue()


def test_history_keeps_full_results_after_cache_is_cleared(client):
    client.post("/api/iocs", json={"value": "bad.example", "severity": "critical", "tags": "phishing"})
    log_id = check(client, "bad.example")["history_id"]
    client.delete("/api/cache")

    detail = client.get(f"/api/history/{log_id}").get_json()
    assert detail["verdict"] == "malicious"
    local = next(r for r in detail["results"] if r["provider"] == "Base local")
    assert local["details"]["tags"] == ["phishing"]
    assert detail["cache_expires_at"] and detail["has_details"] is True


def test_cached_query_also_keeps_its_snapshot(client):
    check(client, "8.8.8.8")
    second = check(client, "8.8.8.8")
    assert second["from_cache"] is True
    detail = client.get(f"/api/history/{second['history_id']}").get_json()
    assert detail["from_cache"] is True and detail["results"]


def test_delete_one_and_selected(client):
    ids = [check(client, v)["history_id"] for v in ("8.8.8.8", "1.1.1.1", "9.9.9.9")]
    assert client.delete(f"/api/history/{ids[0]}").status_code == 200
    assert client.get(f"/api/history/{ids[0]}").status_code == 404
    assert client.post("/api/history/delete", json={"ids": ids[1:]}).get_json()["removed"] == 2
    assert client.get("/api/history").get_json()["total"] == 0
    assert client.post("/api/history/delete", json={"ids": []}).status_code == 400


def test_export_only_selected_items_as_csv(client):
    a = check(client, "8.8.8.8")["history_id"]
    check(client, "1.1.1.1")
    text = client.get(f"/api/history/export?ids={a}").get_data(as_text=True)
    assert "8.8.8.8" in text and "1.1.1.1" not in text
    # Sem ids: todas as consultas do filtro atual
    everything = client.get("/api/history/export").get_data(as_text=True)
    assert "8.8.8.8" in everything and "1.1.1.1" in everything


def test_export_single_parts_and_zip(app, client):
    client.post("/api/iocs", json={"value": "bad.example", "severity": "high"})
    log_id = check(client, "bad.example")["history_id"]
    with app.app_context():
        image, meta = page_capture.files(log_id, "VirusTotal")
        image.write_bytes(fake_png())
        meta.write_text('{"provider": "VirusTotal", "captured_at": "2026-10-11T12:00:00Z"}', "utf-8")

    sources = client.get(f"/api/history/export?ids={log_id}&include=sources")
    assert sources.mimetype == "text/csv" and "Base local" in sources.get_data(as_text=True)

    data = client.get(f"/api/history/export?ids={log_id}&include=json")
    assert data.mimetype == "application/json"
    assert json.loads(data.data)["items"][0]["results"]

    bundle = client.get(f"/api/history/export?ids={log_id}&include=summary,json,evidence,pages")
    assert bundle.mimetype == "application/zip"
    names = zipfile.ZipFile(io.BytesIO(bundle.data)).namelist()
    assert "resumo.csv" in names and "dados_completos.json" in names
    assert any(n.startswith("evidencias/") and n.endswith("todas-as-fontes.png") for n in names)
    assert any(n.startswith("paginas/") and n.endswith("virustotal.png") for n in names)


def test_export_rejects_bad_input(client):
    assert client.get("/api/history/export?include=senhas").status_code == 400
    assert client.get("/api/history/export?ids=a,b").status_code == 400


def test_urlscan_screenshot_is_archived_locally(app, client, monkeypatch):
    url = "https://urlscan.io/screenshots/abc.png"

    class Response:
        status_code, headers, content = 200, {"Content-Type": "image/png"}, fake_png()

    calls = []
    monkeypatch.setattr(media.requests, "get", lambda u, **kw: calls.append(u) or Response())
    with app.app_context():
        app.config["ARCHIVE_MEDIA"] = True
        media.archive_results([{"media": [{"type": "image", "url": url}]}])
        media.archive_results([{"media": [{"type": "image", "url": "https://evil.example/x.png"}]}])
    assert calls == [url]  # baixada uma vez e só do URLScan.io

    served = client.get(f"/api/evidence/screenshot?url={url}")
    assert served.status_code == 200 and served.mimetype == "image/png"
    assert calls == [url]  # servida pela cópia local
    assert client.get("/api/evidence/screenshot?url=https://evil.example/x.png").status_code == 404


def test_backfill_copies_cached_data_to_old_history_rows(app, client):
    check(client, "8.8.8.8")
    with app.app_context():
        log = QueryLog.query.first()
        log.results_json = None
        db.session.commit()
        image, meta = page_capture.legacy_files("8.8.8.8", "Base local")
        image.write_bytes(fake_png())
        meta.write_text('{"provider": "Base local", "captured_at": "2026-10-11T12:00:00Z"}', "utf-8")

        history.backfill()
        log = QueryLog.query.first()
        assert log.results
        assert page_capture.files(log.id, "Base local")[0].exists()
        assert not image.exists()


def test_cache_page_removed_but_cache_still_configurable(client):
    response = client.get("/cache")
    assert response.status_code == 302 and response.headers["Location"].endswith("/settings#cache")
    assert client.get("/api/cache/summary").get_json()["ttl_hours"] == 24
    client.put("/api/settings", json={"values": {"cache_ttl_hours": 48}})
    assert client.get("/api/cache/summary").get_json()["ttl_hours"] == 48
    nav = client.get("/history").get_data(as_text=True)
    assert 'href="/cache"' not in nav and 'id="shutdown-btn"' in nav


def test_shutdown_is_ignored_in_tests(client, raw_client):
    assert client.post("/api/system/shutdown").status_code == 200
    assert raw_client.post("/api/system/shutdown").status_code == 403  # exige o cabeçalho do app
