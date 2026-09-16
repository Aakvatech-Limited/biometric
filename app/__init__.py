from flask import Flask
from config import Config


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Load persisted state (config.json), migrating from SQLite if needed
    from app import store
    store.load()

    from app.routes.dashboard import dashboard_bp
    from app.routes.devices import devices_bp
    from app.routes.settings import settings_bp
    from app.routes.api import api_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(devices_bp, url_prefix="/devices")
    app.register_blueprint(settings_bp, url_prefix="/settings")
    app.register_blueprint(api_bp, url_prefix="/api")

    return app
