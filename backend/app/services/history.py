"""Histórico completo: cada consulta guarda todos os dados das fontes e os prints.

Também monta a exportação, em que o analista escolhe as consultas e o conteúdo:
resumo (CSV), detalhes fonte por fonte (CSV), dados completos (JSON), prints de
evidência e prints das páginas das fontes (PNG). Um único CSV sai direto; as
demais combinações saem num arquivo .zip.
"""

import csv
import io
import json
import shutil
import zipfile
from datetime import datetime

from PIL import Image

from ..extensions import db
from ..models import CacheEntry, QueryLog, iso, utcnow
from . import evidence, media, page_capture

EXPORT_PARTS = {
    "summary": "Resumo das consultas (CSV)",
    "sources": "Detalhes fonte por fonte (CSV)",
    "json": "Dados completos (JSON)",
    "evidence": "Prints de evidência (PNG)",
    "pages": "Prints das páginas das fontes (PNG)",
}
MAX_EXPORT = 10000
MAX_EXPORT_IMAGES = 300  # gerar imagens é mais pesado: limita a quantidade por exportação


def _fmt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else ""


def _safe(text, size=50):
    return "".join(c if c.isalnum() or c in "-." else "_" for c in text)[:size]


def backfill():
    """Na atualização, copia para o histórico os dados que ainda estão no cache e
    vincula os prints de página antigos (guardados por indicador) à consulta mais recente."""
    pending = QueryLog.query.filter(QueryLog.results_json.is_(None)).all()
    if not pending:
        return
    entries = {e.indicator: e for e in CacheEntry.query.all()}
    latest = {}
    for log in pending:
        entry = entries.get(log.indicator)
        if entry is not None:
            log.results_json = entry.results_json
            log.cache_expires_at = log.cache_expires_at or entry.expires_at
            if latest.get(log.indicator) is None or log.queried_at > latest[log.indicator].queried_at:
                latest[log.indicator] = log
    for indicator, log in latest.items():
        for result in log.results:
            old_png, old_meta = page_capture.legacy_files(indicator, result.get("provider", ""))
            new_png, new_meta = page_capture.files(log.id, result.get("provider", ""))
            if old_png.exists() and old_meta.exists() and not new_png.exists():
                shutil.move(old_png, new_png)
                shutil.move(old_meta, new_meta)
    db.session.commit()


def delete(ids):
    ids = [int(i) for i in ids]
    removed = QueryLog.query.filter(QueryLog.id.in_(ids)).delete(synchronize_session=False)
    page_capture.delete_for(ids)
    return removed


def clear_all():
    removed = QueryLog.query.delete(synchronize_session=False)
    page_capture.clear_all()
    media.clear_all()
    return removed


def detail(log):
    data = log.to_dict(include_results=True)
    data["captures"] = page_capture.captures_for(log.id, [r.get("provider", "") for r in data["results"]])
    return data


# --- Exportação ----------------------------------------------------------------

def _summary_csv(logs):
    buffer = io.StringIO()
    buffer.write("﻿")  # BOM + ponto e vírgula: abre certo no Excel em português
    writer = csv.writer(buffer, delimiter=";")
    writer.writerow(["Data da consulta (UTC)", "Indicador", "Tipo", "Veredito", "Score",
                     "Origem", "Resultado armazenado em (UTC)", "Fontes com alerta"])
    for log in logs:
        alerts = [r["provider"] for r in log.results
                  if r.get("status") == "ok" and r.get("verdict") in ("malicious", "suspicious")]
        writer.writerow([_fmt(log.queried_at), log.indicator, log.ioc_type, log.verdict, log.score,
                         "cache" if log.from_cache else "consulta nova", _fmt(log.cache_stored_at),
                         ", ".join(alerts)])
    return buffer.getvalue()


def _sources_csv(logs):
    buffer = io.StringIO()
    buffer.write("﻿")
    writer = csv.writer(buffer, delimiter=";")
    writer.writerow(["Data da consulta (UTC)", "Indicador", "Fonte", "Status", "Veredito", "Score",
                     "Resumo", "Alertas", "Informações", "Link"])
    for log in logs:
        for r in log.results:
            writer.writerow([
                _fmt(log.queried_at), log.indicator, r.get("provider", ""), r.get("status", ""),
                r.get("verdict", "") if r.get("status") == "ok" else "", r.get("score", ""),
                r.get("summary", ""),
                " | ".join(f.get("text", "") for f in r.get("flags") or []),
                " | ".join(f"{f.get('label')}: {f.get('value')}" for f in r.get("facts") or []),
                r.get("link", ""),
            ])
    return buffer.getvalue()


def _json(logs):
    items = []
    for log in logs:
        item = log.to_dict(include_results=True)
        item["queried_at"], item["cache_stored_at"] = iso(log.queried_at), iso(log.cache_stored_at)
        items.append(item)
    return json.dumps({"exported_at": iso(utcnow()), "total": len(items), "items": items},
                      ensure_ascii=False, indent=2)


def _folder(log):
    return f"{log.queried_at:%Y%m%d_%H%M%S}_{_safe(log.indicator)}_{log.id}"


def export(logs, parts):
    """Devolve (conteúdo, nome do arquivo, tipo MIME)."""
    parts = [p for p in EXPORT_PARTS if p in parts] or ["summary"]
    stamp = f"{datetime.now():%Y%m%d_%H%M}"
    if parts == ["summary"]:
        return _summary_csv(logs).encode("utf-8"), f"historico_ioc_{stamp}.csv", "text/csv; charset=utf-8"
    if parts == ["sources"]:
        return _sources_csv(logs).encode("utf-8"), f"historico_fontes_{stamp}.csv", "text/csv; charset=utf-8"
    if parts == ["json"]:
        return _json(logs).encode("utf-8"), f"historico_ioc_{stamp}.json", "application/json"

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as z:
        if "summary" in parts:
            z.writestr("resumo.csv", _summary_csv(logs))
        if "sources" in parts:
            z.writestr("fontes.csv", _sources_csv(logs))
        if "json" in parts:
            z.writestr("dados_completos.json", _json(logs))
        images = 0
        for log in logs:
            if images >= MAX_EXPORT_IMAGES:
                z.writestr("LEIA-ME.txt", f"Limite de {MAX_EXPORT_IMAGES} imagens por exportação atingido. "
                                          "Exporte o restante em outra seleção.")
                break
            folder = _folder(log)
            if "evidence" in parts and log.results:
                z.writestr(f"evidencias/{folder}/todas-as-fontes.png", evidence.to_png(evidence.render_all(log)))
                z.writestr(f"evidencias/{folder}/todas-as-fontes.txt", evidence.text_all(log))
                images += 1
            if "pages" in parts:
                for result in log.results:
                    png, _meta = page_capture.files(log.id, result.get("provider", ""))
                    if png.exists():
                        slug = page_capture._slug(result["provider"])
                        marked = evidence.watermark(Image.open(io.BytesIO(png.read_bytes())))
                        z.writestr(f"paginas/{folder}/{slug}.png", evidence.to_png(marked))
                        text = page_capture.text_file(log.id, result.get("provider", ""))
                        if text.exists():
                            z.write(text, f"paginas/{folder}/{slug}.txt")
                        images += 1
    return buffer.getvalue(), f"historico_ioc_{stamp}.zip", "application/zip"
