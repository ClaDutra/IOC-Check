import io
from datetime import datetime

from flask import Blueprint, Response, jsonify, request
from PIL import Image

from ..extensions import db
from ..models import QueryLog
from ..services import activity, evidence, page_capture

bp = Blueprint("capture", __name__, url_prefix="/api/capture")


def _source(log_id):
    """Resultado da fonte pedida (?provider=) dentro de uma consulta do histórico."""
    entry = db.get_or_404(QueryLog, log_id)
    provider = request.args.get("provider", "")
    result = next((r for r in entry.results if r.get("provider") == provider), None)
    return entry, provider, result


@bp.post("/<int:log_id>")
def capture_page(log_id):
    """Abre a página da fonte e salva o print. Pode levar até alguns minutos se o site
    pedir verificação humana, que o próprio usuário resolve na janela aberta."""
    entry, provider, result = _source(log_id)
    if result is None:
        return jsonify(error="Fonte não encontrada neste resultado"), 404
    if not page_capture.is_allowed(result.get("link")):
        return jsonify(error="Esta fonte não tem página pública para capturar"), 400
    try:
        data = page_capture.capture(log_id, provider, result["link"])
    except page_capture.CaptureBusy as exc:
        return jsonify(error=str(exc)), 409
    except page_capture.CaptureError as exc:
        activity.action("print da página", f"Falhou o print de {provider} para {entry.indicator}: {exc}",
                        level="erro")
        activity.flush()  # a resposta de erro descarta a transação da rota
        return jsonify(error=str(exc)), 502
    activity.action("print da página", f"Print da página de {provider} para {entry.indicator}"
                    + (" (após verificação humana)" if data.get("needed_human") else ""), url=data.get("url"))
    return jsonify(data)


@bp.post("/<int:log_id>/manual")
def upload_manual(log_id):
    """Recebe o print que o usuário tirou no próprio navegador (colado ou enviado).

    Campo "image" (arquivo) e, opcionalmente, "text" com o texto da página.
    """
    entry, provider, result = _source(log_id)
    if result is None or provider == "Base local":
        return jsonify(error="Fonte não encontrada neste resultado"), 404
    upload = request.files.get("image")
    try:
        data = page_capture.save_manual(log_id, provider, result.get("link"),
                                        upload.read(page_capture.MAX_UPLOAD + 1) if upload else b"",
                                        request.form.get("text", ""))
    except page_capture.CaptureError as exc:
        return jsonify(error=str(exc)), 400
    activity.action("print da página", f"Print manual de {provider} para {entry.indicator} salvo",
                    url=result.get("link"))
    return jsonify(data)


@bp.get("/<int:log_id>")
def capture_info(log_id):
    _entry, provider, _result = _source(log_id)
    data = page_capture.info(log_id, provider)
    return (jsonify(data), 200) if data else (jsonify(error="Nenhum print desta página ainda"), 404)


@bp.get("/<int:log_id>.png")
def capture_image(log_id):
    entry, provider, _result = _source(log_id)
    image_path, _meta = page_capture.files(log_id, provider)
    if not image_path.exists():
        return jsonify(error="Nenhum print desta página ainda"), 404
    safe = "".join(c if c.isalnum() or c in "-." else "_" for c in entry.indicator)[:60]
    filename = f"print_{page_capture._slug(provider)}_{safe}_{datetime.now():%Y%m%d_%H%M}.png"
    disposition = "attachment" if request.args.get("download") else "inline"
    # A marca d'água é aplicada ao servir, então vale também para prints antigos
    image = evidence.watermark(Image.open(io.BytesIO(image_path.read_bytes())))
    return Response(evidence.to_png(image), mimetype="image/png",
                    headers={"Content-Disposition": f'{disposition}; filename="{filename}"', "Cache-Control": "no-store"})


@bp.get("/<int:log_id>.txt")
def capture_text(log_id):
    """Texto visível da página da fonte, salvo no momento do print."""
    entry, provider, _result = _source(log_id)
    path = page_capture.text_file(log_id, provider)
    if not path.exists():
        return jsonify(error="Este print não tem o texto da página (tire um novo print para obtê-lo)"), 404
    safe = "".join(c if c.isalnum() or c in "-." else "_" for c in entry.indicator)[:60]
    filename = f"pagina_{page_capture._slug(provider)}_{safe}_{datetime.now():%Y%m%d_%H%M}.txt"
    disposition = "attachment" if request.args.get("download") else "inline"
    return Response(path.read_text("utf-8"), mimetype="text/plain; charset=utf-8",
                    headers={"Content-Disposition": f'{disposition}; filename="{filename}"', "Cache-Control": "no-store"})
