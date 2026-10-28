from flask import Flask
from config import Config


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Load persisted state (config.json), migrating from SQLite if needed
    from app import store
    store.load()

    from app.routes.api import api_bp
    from app.routes.iclock import iclock_bp
    from app.routes.ui_api import ui_api_bp
    from app.routes.pages import pages_bp
    from app.routes.fkweb import fkweb_bp

    # Server-rendered pages at /, the actions their buttons call under /api/ui
    app.register_blueprint(pages_bp)
    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(ui_api_bp, url_prefix="/api/ui")
    app.register_blueprint(iclock_bp, url_prefix="/iclock")
    app.register_blueprint(fkweb_bp)

    return app
