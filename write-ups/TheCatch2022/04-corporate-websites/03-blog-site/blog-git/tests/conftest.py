import os
import tempfile
from pathlib import Path

import pytest

from flaskr import create_app
from flaskr.db import get_db
from flaskr.db import init_db
from flaskr.db import close_db


@pytest.fixture
def app():
    """Create and configure a new app instance for each test."""
    # create the app with common test config
    app = create_app({"TESTING": True, 'PASSWORD_POLICY': 1})

    # create the database and load test data
    with app.app_context():
        init_db()
        for line in Path(os.path.join(os.path.dirname(__file__), "data.sql")).read_text().splitlines():
            get_db().cursor().execute(line)
        get_db().commit()
        yield app
        close_db()


@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()


@pytest.fixture
def runner(app):
    """A test runner for the app's Click commands."""
    return app.test_cli_runner()


class AuthActions:
    def __init__(self, client):
        self._client = client

    def login(self, username="test", password="test"):
        return self._client.post(
            "/auth/login", data={"username": username, "password": password}
        )

    def logout(self):
        return self._client.get("/auth/logout")


@pytest.fixture
def auth(client):
    return AuthActions(client)
