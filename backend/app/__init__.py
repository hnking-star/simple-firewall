from flask import Flask
from flask_cors import CORS

from .api import api
from .config import DEFAULT_DATABASE_PATH
from .db import init_db
from .timed_update_service import TimedUpdateService


def create_app(config=None):
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config.from_mapping(DATABASE_PATH=str(DEFAULT_DATABASE_PATH))
    if config:
        app.config.update(config)

    init_db(app.config['DATABASE_PATH'])
    CORS(app)
    app.register_blueprint(api)
    if not app.config.get('TESTING'):
        TimedUpdateService(app.config['DATABASE_PATH']).start()
    return app
