import os

from flask import Flask, jsonify, request

from .config import Config
from .extensions import db

# Cabeçalho exigido nas requisições que alteram dados. Como o app não tem login,
# isso impede que outro site aberto no navegador dispare ações no IOC Check
# (o navegador não deixa páginas de outra origem enviarem cabeçalhos próprios).
CSRF_HEADER = "X-Requested-With"
CSRF_VALUE = "IOCCheck"

# O front-end (páginas HTML, CSS e JavaScript) fica em <raiz>/frontend,
# separado deste pacote do back-end (<raiz>/backend/app).
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend"))


def create_app(config_class=Config):
    app = Flask(
        __name__,
        instance_relative_config=True,
        template_folder=os.path.join(FRONTEND_DIR, "templates"),
        static_folder=os.path.join(FRONTEND_DIR, "static"),
    )
    app.config.from_object(config_class)
    # Relê os templates quando o arquivo muda, mesmo com o modo de depuração desligado
    # (sem isso, um servidor antigo continuaria mostrando o HTML de antes da atualização)
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.jinja_env.auto_reload = True

    os.makedirs(app.instance_path, exist_ok=True)
    if not app.config.get("SQLALCHEMY_DATABASE_URI"):
        db_path = os.path.join(app.instance_path, "ioc_check.db")
        app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"

    db.init_app(app)

    from .routes import register_blueprints

    register_blueprints(app)

    @app.url_defaults
    def static_version(endpoint, values):
        # CSS e JS ganham ?v=<data do arquivo>: o navegador baixa a versão nova sempre que
        # o arquivo muda, em vez de usar uma cópia antiga guardada
        if endpoint == "static" and "filename" in values and "v" not in values:
            path = os.path.join(app.static_folder, values["filename"])
            if os.path.isfile(path):
                values["v"] = int(os.path.getmtime(path))

    @app.before_request
    def require_app_header():
        if (
            request.path.startswith("/api/")
            and request.method in ("POST", "PUT", "PATCH", "DELETE")
            and request.headers.get(CSRF_HEADER) != CSRF_VALUE
        ):
            return jsonify(error="Requisição recusada: origem não autorizada"), 403
        return None

    @app.errorhandler(404)
    def not_found(error):
        if request.path.startswith("/api/"):
            return jsonify(error="Recurso não encontrado"), 404
        return error

    @app.errorhandler(405)
    def method_not_allowed(error):
        if request.path.startswith("/api/"):
            return jsonify(error="Método não permitido"), 405
        return error

    @app.errorhandler(500)
    def server_error(error):
        db.session.rollback()
        if request.path.startswith("/api/"):
            return jsonify(error="Erro interno do servidor"), 500
        return error

    with app.app_context():
        from . import models  # noqa: F401  (registra as tabelas)

        db.create_all()
        _upgrade_schema()

        from .services import history

        history.backfill()

    return app


# Colunas adicionadas depois da criação do banco. create_all() não altera
# tabelas existentes, então elas são acrescentadas aqui em bancos antigos.
NEW_COLUMNS = {
    "iocs": {"expires_at": "DATETIME"},
    "query_logs": {"results_json": "TEXT", "cache_expires_at": "DATETIME"},
}


def _upgrade_schema():
    inspector = db.inspect(db.engine)
    with db.engine.begin() as conn:
        for table, columns in NEW_COLUMNS.items():
            existing = {c["name"] for c in inspector.get_columns(table)}
            for name, sql_type in columns.items():
                if name not in existing:
                    conn.execute(db.text(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}"))
