import os
import sys

# Rodando em segundo plano (pythonw, sem janela do CMD) não existe console:
# as mensagens do servidor vão para backend/instance/ioc_check.log
if sys.stdout is None or sys.stderr is None:
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "instance")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "ioc_check.log")
    # Recomeça o arquivo quando passa de 5 MB, para não crescer sem limite
    mode = "w" if os.path.exists(log_path) and os.path.getsize(log_path) > 5 * 1024 * 1024 else "a"
    log_file = open(log_path, mode, encoding="utf-8", buffering=1)
    sys.stdout = sys.stdout or log_file
    sys.stderr = sys.stderr or log_file

from app import create_app  # noqa: E402

app = create_app()

if __name__ == "__main__":
    from app.services import activity

    with app.app_context():
        activity.log("sistema", "iniciar", f"Servidor iniciado em http://localhost:{os.getenv('PORT', '5000')}",
                     source="sistema")
    # Ferramenta pessoal sem login: escuta apenas no próprio computador (127.0.0.1),
    # então outras máquinas da rede não conseguem acessar sua base.
    app.run(
        host="127.0.0.1",
        port=int(os.getenv("PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "1") == "1",
    )
