from flask import Flask

from .config import DB_PATH, STATIC_DIR, TEMPLATE_DIR, apply_config
from .db import close_db, init_db
from .routes import register_routes


def create_app() -> Flask:
    # Central app factory that wires configuration, routes, and database lifecycle hooks.
    app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
    apply_config(app)
    register_routes(app)
    app.teardown_request(close_db)
    init_db(DB_PATH)
    return app
