def register_blueprints(app):
    from . import cache_routes, check, history, iocs, pages, settings_routes, stats

    for module in (pages, check, iocs, history, cache_routes, stats, settings_routes):
        app.register_blueprint(module.bp)
