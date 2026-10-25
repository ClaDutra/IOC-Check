import pytest

from app import CSRF_HEADER, CSRF_VALUE, create_app
from app.config import TestConfig
from app.extensions import db


@pytest.fixture
def app(tmp_path):
    app = create_app(TestConfig)
    app.config["CAPTURE_ROOT"] = str(tmp_path)  # prints de página vão para uma pasta temporária
    yield app
    with app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Cliente que envia o cabeçalho exigido, como o front-end faz."""
    client = app.test_client()
    client.environ_base["HTTP_" + CSRF_HEADER.upper().replace("-", "_")] = CSRF_VALUE
    return client


@pytest.fixture
def raw_client(app):
    """Cliente sem o cabeçalho, simulando uma requisição vinda de outro site."""
    return app.test_client()
