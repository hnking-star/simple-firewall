from flask import Flask
from flask_cors import CORS

from .api import api
from .config import DEFAULT_DATABASE_PATH


def create_app(config=None):
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config.from_mapping(DATABASE_PATH=str(DEFAULT_DATABASE_PATH))
    if config:
        app.config.update(config)

    CORS(app)
    app.register_blueprint(api)
    return app
