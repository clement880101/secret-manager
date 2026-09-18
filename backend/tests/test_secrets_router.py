import importlib
import os
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


TOKENS = {"alice-token": 1111, "bob-token": 2222}
ALICE = {"Authorization": "Bearer alice-token"}
BOB = {"Authorization": "Bearer bob-token"}


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
    auth_service = importlib.import_module("auth.service")
    secrets_router = importlib.import_module("secret_manager.router")

    def fake_fetch(access_token, token_kind="oauth"):
        user_id = TOKENS[access_token]
        return {"id": user_id, "login": f"user{user_id}", "name": None, "avatar_url": None}

    monkeypatch.setattr(auth_service, "fetch_github_user", fake_fetch)
    assert secrets_router.service.session_scope.__wrapped__.__globals__["engine"].url.database == str(
        tmp_path / "secrets.db"
    ), "router is not wired to this test's database"

    database.init_db()

    app = FastAPI()
    app.include_router(secrets_router.router)
    yield TestClient(app)

    _reset_app_modules()


def test_get_secret_returns_owned_secret(client):
    assert client.post("/secrets", json={"key": "k1", "value": "v1"}, headers=ALICE).status_code == 200

    response = client.get("/secrets/k1", headers=ALICE)

    assert response.status_code == 200
    assert response.json() == {"key": "k1", "value": "v1", "owner_id": "1111"}


def test_get_secret_returns_shared_secret(client):
    client.post("/secrets", json={"key": "k1", "value": "v1"}, headers=ALICE)
    assert client.post("/secrets/k1/share", json={"github_id": "2222"}, headers=ALICE).status_code == 200

    response = client.get("/secrets/k1", headers=BOB)

    assert response.status_code == 200
    assert response.json() == {"key": "k1", "value": "v1", "owner_id": "1111"}


def test_get_secret_hidden_from_unrelated_user(client):
    client.post("/secrets", json={"key": "k1", "value": "v1"}, headers=ALICE)
    client.post("/secrets", json={"key": "k2", "value": "v2"}, headers=BOB)

    assert client.get("/secrets/k1", headers=BOB).status_code == 403


def test_get_secret_requires_auth(client):
    assert client.get("/secrets/k1").status_code == 401


def test_secret_lifecycle(client):
    assert client.post("/secrets", json={"key": "k1", "value": "v1"}, headers=ALICE).status_code == 200
    assert client.post("/secrets", json={"key": "k1", "value": "v2"}, headers=ALICE).status_code == 409

    listed = client.get("/secrets", headers=ALICE)
    assert listed.status_code == 200
    assert listed.json() == {"items": [{"key": "k1", "value": "v1", "owner_id": "1111"}]}

    assert client.delete("/secrets/k1", headers=BOB).status_code == 404
    assert client.delete("/secrets/k1", headers=ALICE).status_code == 200
    assert client.delete("/secrets/k1", headers=ALICE).status_code == 404
    assert client.get("/secrets", headers=ALICE).json() == {"items": []}
