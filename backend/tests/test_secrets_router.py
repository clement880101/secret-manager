import importlib
import os
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


ALICE_NAME = "alice"
BOB_NAME = "bob"


def _reset_app_modules() -> None:
    """Drop the app modules *and* their packages.

    Popping only submodules is not enough: ``from . import service`` resolves
    against the package attribute, so a stale module would be reused.
    """
    for name in list(sys.modules):
        if name == "database" or name in ("auth", "secret_manager") or name.startswith(("auth.", "secret_manager.")):
            del sys.modules[name]


@pytest.fixture()
def client(monkeypatch, tmp_path):
    """Serve the secrets router against a fresh SQLite file with GitHub stubbed out."""
    monkeypatch.setenv("DB_URL", f"sqlite:///{tmp_path / 'secrets.db'}")

    project_root = Path(__file__).resolve().parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    _reset_app_modules()

    database = importlib.import_module("database")
    local = importlib.import_module("auth.local")
    secrets_router = importlib.import_module("secret_manager.router")

    database.init_db()

    app = FastAPI()
    app.include_router(secrets_router.router)
    client = TestClient(app)
    # Real tokens from the service itself, rather than a stubbed identity.
    client.alice = {"Authorization": f"Bearer {local.issue_token(ALICE_NAME)}"}
    client.bob = {"Authorization": f"Bearer {local.issue_token(BOB_NAME)}"}
    yield client

    _reset_app_modules()


def test_get_secret_returns_owned_secret(client):
    assert client.post("/secrets", json={"key": "k1", "value": "v1"}, headers=client.alice).status_code == 200

    response = client.get("/secrets/k1", headers=client.alice)

    assert response.status_code == 200
    assert response.json() == {"key": "k1", "value": "v1", "owner_id": ALICE_NAME}


def test_get_secret_returns_shared_secret(client):
    client.post("/secrets", json={"key": "k1", "value": "v1"}, headers=client.alice)
    assert client.post("/secrets/k1/share", json={"user_id": BOB_NAME}, headers=client.alice).status_code == 200

    response = client.get("/secrets/k1", headers=client.bob)

    assert response.status_code == 200
    assert response.json() == {"key": "k1", "value": "v1", "owner_id": ALICE_NAME}


def test_get_secret_hidden_from_unrelated_user(client):
    client.post("/secrets", json={"key": "k1", "value": "v1"}, headers=client.alice)
    client.post("/secrets", json={"key": "k2", "value": "v2"}, headers=client.bob)

    assert client.get("/secrets/k1", headers=client.bob).status_code == 403


def test_get_secret_requires_auth(client):
    assert client.get("/secrets/k1").status_code == 401


def test_secret_lifecycle(client):
    assert client.post("/secrets", json={"key": "k1", "value": "v1"}, headers=client.alice).status_code == 200
    assert client.post("/secrets", json={"key": "k1", "value": "v2"}, headers=client.alice).status_code == 409

    listed = client.get("/secrets", headers=client.alice)
    assert listed.status_code == 200
    assert listed.json() == {"items": [{"key": "k1", "owner_id": ALICE_NAME, "shared": False}]}

    assert client.delete("/secrets/k1", headers=client.bob).status_code == 404
    assert client.delete("/secrets/k1", headers=client.alice).status_code == 200
    assert client.delete("/secrets/k1", headers=client.alice).status_code == 404
    assert client.get("/secrets", headers=client.alice).json() == {"items": []}
