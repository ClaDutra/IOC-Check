from flask import Blueprint, redirect, render_template, url_for

bp = Blueprint("pages", __name__)


@bp.get("/")
def dashboard():
    return render_template("dashboard.html", active="dashboard")


@bp.get("/check")
def check_page():
    return render_template("check.html", active="check")


@bp.get("/iocs")
def iocs_page():
    return render_template("iocs.html", active="iocs")


@bp.get("/history")
def history_page():
    return render_template("history.html", active="history")


@bp.get("/cache")
def cache_page():
    # A tela de cache foi removida: o histórico guarda tudo e a validade fica nas configurações
    return redirect(url_for("pages.settings_page") + "#cache")


@bp.get("/settings")
def settings_page():
    return render_template("settings.html", active="settings")


@bp.get("/logs")
def logs_page():
    return render_template("logs.html", active="logs")
