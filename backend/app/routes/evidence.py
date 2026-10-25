from datetime import datetime

from flask import Blueprint, Response, jsonify, request

from ..extensions import db
from ..models import QueryLog
from ..services import evidence, media

bp = Blueprint("evidence", __name__, url_prefix="/api/evidence")


@bp.get("/<int:log_id>.png")
def evidence_image(log_id):
    """Print de evidência de uma consulta do histórico (vale mesmo após o cache expirar).

    ?provider=<nome> gera só a fonte indicada; sem o parâmetro, gera todas.
    ?download=1 faz o navegador baixar o arquivo em vez de exibi-lo.
    """
    entry = db.get_or_404(QueryLog, log_id)
    if not entry.results:
        return jsonify(error="Esta consulta não tem os dados detalhados guardados"), 404
    provider = request.args.get("provider")
    if provider:
        result = next((r for r in evidence.tool_results(entry) if r.get("provider") == provider), None)
        if result is None:
            return jsonify(error="Fonte não encontrada neste resultado"), 404
        image = evidence.render_source(entry, result)
        slug = provider.lower().replace(" ", "-").replace(".", "")
    else:
        image = evidence.render_all(entry)
        slug = "todas-as-fontes"

    safe_indicator = "".join(c if c.isalnum() or c in "-." else "_" for c in entry.indicator)[:60]
    filename = f"evidencia_{safe_indicator}_{slug}_{datetime.now():%Y%m%d_%H%M}.png"
    disposition = "attachment" if request.args.get("download") else "inline"
    return Response(
        evidence.to_png(image),
        mimetype="image/png",
        headers={"Content-Disposition": f'{disposition}; filename="{filename}"', "Cache-Control": "no-store"},
    )


@bp.get("/screenshot")
def screenshot():
    """Captura de tela do URLScan.io servida pela cópia local (guardada na consulta)."""
    data = media.get(request.args.get("url", ""))
    if not data:
        return jsonify(error="Imagem indisponível"), 404
    return Response(data, mimetype="image/png", headers={"Cache-Control": "private, max-age=86400"})
