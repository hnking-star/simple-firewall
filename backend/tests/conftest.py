import sqlite3
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_ROOT))

from app import create_app
from app.db import init_db


@pytest.fixture()
def db_path(tmp_path):
    return tmp_path / 'firewall_test.db'


@pytest.fixture()
def app(db_path):
    flask_app = create_app({'DATABASE_PATH': str(db_path), 'TESTING': True})
    with flask_app.app_context():
        init_db(str(db_path))
    return flask_app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def db_connection(db_path):
    init_db(str(db_path))
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()
