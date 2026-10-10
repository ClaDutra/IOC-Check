from flask import Blueprint, render_template

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
    return render_template("cache.html", active="cache")


@bp.get("/settings")
def settings_page():
    return render_template("settings.html", active="settings")
