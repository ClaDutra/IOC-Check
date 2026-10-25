"""Encerramento do servidor pelo navegador.

O iniciar.bat roda o IOC Check em segundo plano (sem janela do CMD aberta), então
o botão "Encerrar IOC Check" da barra lateral é a forma de fechá-lo.
"""

import os
import threading

from flask import Blueprint, current_app, jsonify

from ..services import activity

bp = Blueprint("system", __name__, url_prefix="/api/system")


@bp.post("/shutdown")
def shutdown():
    if current_app.config.get("TESTING"):
        return jsonify(message="Encerramento ignorado nos testes")
    activity.log("sistema", "encerrar", "IOC Check encerrado pelo botão da barra lateral", source="sistema")
    # Espera um instante para a resposta chegar ao navegador antes de fechar
    threading.Timer(0.5, lambda: os._exit(0)).start()
    return jsonify(message="IOC Check encerrado. Você já pode fechar esta aba.")
