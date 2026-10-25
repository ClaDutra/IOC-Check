def register_blueprints(app):
    from . import cache_routes, capture, check, evidence, history, iocs, pages, settings_routes, stats, system

    for module in (pages, check, iocs, history, cache_routes, stats, settings_routes, evidence, capture, system):
        app.register_blueprint(module.bp)
