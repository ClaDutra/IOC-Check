"""Cópia local das capturas de tela do URLScan.io (pasta instance/midias).

A API do URLScan.io devolve só o link da imagem. Guardando uma cópia no momento
da consulta, o histórico e os prints de evidência continuam com a imagem mesmo
depois que o cache expira ou que o site deixa de exibi-la. Cada imagem é baixada
uma única vez (o nome do arquivo vem do próprio link).
"""

import hashlib
from pathlib import Path

import requests
from flask import current_app

SCREENSHOT_PREFIX = "https://urlscan.io/screenshots/"
MAX_BYTES = 8 * 1024 * 1024


def is_allowed(url):
    return str(url or "").startswith(SCREENSHOT_PREFIX)


def _dir():
    # CAPTURE_ROOT permite apontar para outra pasta (os testes usam uma temporária)
    path = Path(current_app.config.get("CAPTURE_ROOT") or current_app.instance_path) / "midias"
    path.mkdir(parents=True, exist_ok=True)
    return path


def path_for(url):
    return _dir() / (hashlib.sha1(str(url).encode("utf-8")).hexdigest() + ".png")


def get(url, download=True):
    """Bytes da imagem: a cópia local ou, se ainda não houver, baixa e guarda."""
    if not is_allowed(url):
        return None
    path = path_for(url)
    if path.exists():
        return path.read_bytes()
    if not download:
        return None
    try:
        response = requests.get(url, timeout=8)
    except requests.RequestException:
        return None
    if (response.status_code != 200 or len(response.content) > MAX_BYTES
            or not response.headers.get("Content-Type", "").startswith("image/")):
        return None
    path.write_bytes(response.content)
    return response.content


def archive_results(results):
    """Guarda as imagens de um resultado novo (chamado logo após a consulta)."""
    if not current_app.config.get("ARCHIVE_MEDIA", True):
        return
    for result in results:
        for item in result.get("media") or []:
            if item.get("type") == "image":
                get(item.get("url"))


def clear_all():
    for path in _dir().glob("*.png"):
        path.unlink(missing_ok=True)
