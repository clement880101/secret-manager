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


# --- keys that could be stored but never reached -----------------------------

def test_a_key_with_a_slash_is_refused(client):
    """It could be created and then never read or deleted: the route treats the
    key as one path segment, so it sat in `list` forever, unreachable."""
    response = client.post(
        "/secrets", json={"key": "prod/db/password", "value": "v"}, headers=client.alice
    )

    assert response.status_code == 422
    assert client.get("/secrets", headers=client.alice).json() == {"items": []}


def test_control_characters_in_a_key_are_refused(client):
    assert client.post(
        "/secrets", json={"key": "bad\nkey", "value": "v"}, headers=client.alice
    ).status_code == 422


def test_keys_that_survive_a_url_round_trip_are_allowed(client):
    """Everything else works once encoded, so nothing else should be blocked."""
    from urllib.parse import quote

    # "key%20enc" is deliberately absent: TestClient and a real server disagree
    # on how to re-encode a percent sign in a path. Verified against a real
    # uvicorn instead, where it round-trips correctly.
    for key in ["prod.db.password", "prod:db:password", "key with space",
                "clé-secrète-日本", "key?x=1", "key#frag"]:
        assert client.post(
            "/secrets", json={"key": key, "value": f"value-of-{key}"}, headers=client.alice
        ).status_code == 200, key
        got = client.get(f"/secrets/{quote(key, safe='')}", headers=client.alice)
        assert got.status_code == 200, key
        assert got.json()["value"] == f"value-of-{key}", key


def test_sharing_with_an_unknown_user_returns_404(client):
    """It used to answer 200 and create the account, so a typo looked like it
    had worked and the secret was shared with a name nobody held."""
    client.post("/secrets", json={"key": "k", "value": "v"}, headers=client.alice)

    response = client.post(
        "/secrets/k/share", json={"user_id": "nosuchuser"}, headers=client.alice
    )

    assert response.status_code == 404
    assert "nosuchuser" in response.json()["detail"]


def test_sharing_still_works_with_a_real_user(client):
    client.post("/secrets", json={"key": "k", "value": "v"}, headers=client.alice)
    # bob exists because the fixture issued him a token.
    assert client.post(
        "/secrets/k/share", json={"user_id": BOB_NAME}, headers=client.alice
    ).status_code == 200
    assert client.get("/secrets/k", headers=client.bob).json()["value"] == "v"


def test_update_replaces_the_value_and_keeps_the_share(client):
    client.post("/secrets", json={"key": "k1", "value": "v1"}, headers=client.alice)
    client.post("/secrets/k1/share", json={"user_id": BOB_NAME}, headers=client.alice)

    assert client.put("/secrets/k1", json={"value": "v2"}, headers=client.alice).status_code == 200

    assert client.get("/secrets/k1", headers=client.alice).json()["value"] == "v2"
    # The point of updating in place: bob still has it.
    assert client.get("/secrets/k1", headers=client.bob).json()["value"] == "v2"


def test_update_of_a_missing_key_is_404(client):
    assert client.put("/secrets/ghost", json={"value": "v"}, headers=client.alice).status_code == 404


def test_update_requires_auth(client):
    assert client.put("/secrets/k1", json={"value": "v"}).status_code == 401


def test_a_reader_cannot_update_what_was_shared_with_them(client):
    client.post("/secrets", json={"key": "k1", "value": "v1"}, headers=client.alice)
    client.post("/secrets/k1/share", json={"user_id": BOB_NAME}, headers=client.alice)

    # Bob can read it. That must not let him write it.
    assert client.put("/secrets/k1", json={"value": "hijacked"}, headers=client.bob).status_code == 404
    assert client.get("/secrets/k1", headers=client.alice).json()["value"] == "v1"


def test_update_rejects_an_oversized_value(client):
    client.post("/secrets", json={"key": "k1", "value": "v1"}, headers=client.alice)

    too_big = "x" * (64 * 1024 + 1)
    assert client.put("/secrets/k1", json={"value": too_big}, headers=client.alice).status_code == 422
    assert client.get("/secrets/k1", headers=client.alice).json()["value"] == "v1"
