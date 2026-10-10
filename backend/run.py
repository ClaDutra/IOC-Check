import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    # Ferramenta pessoal sem login: escuta apenas no próprio computador (127.0.0.1),
    # então outras máquinas da rede não conseguem acessar sua base.
    app.run(
        host="127.0.0.1",
        port=int(os.getenv("PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "1") == "1",
    )
