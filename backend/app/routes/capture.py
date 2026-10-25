from datetime import datetime

from flask import Blueprint, Response, jsonify, request

from ..extensions import db
from ..models import QueryLog
from ..services import page_capture

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
        return jsonify(error=str(exc)), 502
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
    return Response(image_path.read_bytes(), mimetype="image/png",
                    headers={"Content-Disposition": f'{disposition}; filename="{filename}"', "Cache-Control": "no-store"})
