"""Authentication that needs nothing outside this service."""

import importlib
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text


def _load(monkeypatch, tmp_path, **env):
    monkeypatch.setenv("DB_URL", f"sqlite:///{tmp_path / 'auth.db'}")
    for key in ("AUTH_MODE", "OAUTH_ID_GITHUB", "OAUTH_SECRET_GITHUB", "BOOTSTRAP_TOKEN"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    project_root = Path(__file__).resolve().parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    for name in list(sys.modules):
        if (
            name in ("database", "crypto", "settings", "app", "version", "auth", "secret_manager")
            or name.startswith(("auth.", "secret_manager."))
        ):
            del sys.modules[name]

    database = importlib.import_module("database")
    importlib.import_module("auth.models")
    importlib.import_module("secret_manager.models")
    settings = importlib.import_module("settings")
    local = importlib.import_module("auth.local")
    database.init_db()
    return database, settings, local


# --- which mode a deployment ends up in -------------------------------------

def test_defaults_to_local_when_nothing_is_configured(monkeypatch, tmp_path):
    """A freshly pulled image must authenticate without any setup."""
    _, settings, _ = _load(monkeypatch, tmp_path)

    assert settings.auth_mode() == "local"


def test_defaults_to_github_when_an_oauth_app_is_configured(monkeypatch, tmp_path):
    """An existing GitHub deployment keeps working untouched."""
    _, settings, _ = _load(
        monkeypatch, tmp_path, OAUTH_ID_GITHUB="id", OAUTH_SECRET_GITHUB="secret"
    )

    assert settings.auth_mode() == "github"


def test_explicit_mode_wins(monkeypatch, tmp_path):
    _, settings, _ = _load(
        monkeypatch, tmp_path, AUTH_MODE="local", OAUTH_ID_GITHUB="id", OAUTH_SECRET_GITHUB="secret"
    )

    assert settings.auth_mode() == "local"


# --- tokens -----------------------------------------------------------------

def test_token_roundtrip(monkeypatch, tmp_path):
    _, _, local = _load(monkeypatch, tmp_path)

    token = local.issue_token("alice", label="laptop")

    assert token.startswith("smt_")
    assert local.resolve_token(token) == "alice"


def test_only_the_digest_is_stored(monkeypatch, tmp_path):
    """A copy of the database must not be a set of working credentials."""
    database, _, local = _load(monkeypatch, tmp_path)

    token = local.issue_token("alice")

    with database.session_scope() as db:
        stored = [row[0] for row in db.execute(text("SELECT token_hash FROM api_tokens"))]
    assert token not in stored
    assert stored == [local.hash_token(token)]


def test_unknown_and_revoked_tokens_are_rejected(monkeypatch, tmp_path):
    _, _, local = _load(monkeypatch, tmp_path)
    token = local.issue_token("alice")

    assert local.resolve_token("smt_nonsense") is None
    assert local.resolve_token("") is None

    assert local.revoke_token(token) is True
    assert local.resolve_token(token) is None
    assert local.revoke_token(token) is False


def test_tokens_are_listed_without_revealing_them(monkeypatch, tmp_path):
    _, _, local = _load(monkeypatch, tmp_path)
    token = local.issue_token("alice", label="laptop")

    listed = local.list_tokens("alice")

    assert len(listed) == 1
    assert listed[0]["label"] == "laptop"
    assert token not in str(listed)


# --- bootstrap --------------------------------------------------------------

def test_bootstrap_creates_one_token_then_stops(monkeypatch, tmp_path):
    """Without this a fresh deployment would have no way in; with it repeated
    restarts must not keep minting credentials."""
    _, _, local = _load(monkeypatch, tmp_path)

    first = local.ensure_bootstrap_token()
    assert first is not None
    assert local.resolve_token(first) == "admin"

    assert local.ensure_bootstrap_token() is None


def test_bootstrap_token_can_be_supplied(monkeypatch, tmp_path):
    _, _, local = _load(monkeypatch, tmp_path, BOOTSTRAP_TOKEN="smt_preset_value")

    issued = local.ensure_bootstrap_token()

    assert issued == "smt_preset_value"
    assert local.resolve_token("smt_preset_value") == "admin"


# --- routes -----------------------------------------------------------------

@pytest.fixture()
def local_client(monkeypatch, tmp_path):
    _load(monkeypatch, tmp_path)
    app_module = importlib.import_module("app")
    local = sys.modules["auth.local"]
    return TestClient(app_module.app), local


def test_whoami_identifies_a_local_token(local_client):
    client, local = local_client
    token = local.issue_token("alice")

    response = client.get("/auth/whoami", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json() == {"user_id": "alice", "auth_mode": "local"}


def test_secrets_work_with_a_local_token(local_client):
    client, local = local_client
    headers = {"Authorization": f"Bearer {local.issue_token('alice')}"}

    assert client.post("/secrets", json={"key": "k", "value": "v"}, headers=headers).status_code == 200
    assert client.get("/secrets", headers=headers).json() == {
        "items": [{"key": "k", "value": "v", "owner_id": "alice"}]
    }


def test_issuing_a_token_requires_one(local_client):
    client, local = local_client

    assert client.post("/auth/tokens", json={"user_id": "bob"}).status_code == 401

    headers = {"Authorization": f"Bearer {local.issue_token('alice')}"}
    response = client.post("/auth/tokens", json={"user_id": "bob"}, headers=headers)

    assert response.status_code == 200
    assert local.resolve_token(response.json()["token"]) == "bob"


def test_github_routes_are_absent_in_local_mode(local_client):
    client, _ = local_client

    assert client.post("/auth/login").status_code == 404
    assert client.get("/auth/login/anything").status_code == 404


def test_a_rejected_token_does_not_authenticate(local_client):
    client, _ = local_client

    assert client.get("/secrets", headers={"Authorization": "Bearer smt_bogus"}).status_code == 401


# --- self-service registration ----------------------------------------------

def test_register_then_log_in_with_the_password(local_client):
    """A user must be able to get back in from another machine."""
    client, _ = local_client

    registered = client.post(
        "/auth/register", json={"username": "alice", "password": "correct horse"}
    )
    assert registered.status_code == 200
    assert registered.json()["user_id"] == "alice"

    session = client.post(
        "/auth/sessions", json={"username": "alice", "password": "correct horse"}
    )
    assert session.status_code == 200
    assert session.json()["token"] != registered.json()["token"]

    whoami = client.get(
        "/auth/whoami", headers={"Authorization": f"Bearer {session.json()['token']}"}
    )
    assert whoami.json()["user_id"] == "alice"


def test_password_is_not_stored(local_client):
    from sqlalchemy import text

    client, _ = local_client
    database = sys.modules["database"]
    client.post("/auth/register", json={"username": "alice", "password": "correct horse"})

    with database.session_scope() as db:
        stored = db.execute(text("SELECT password_hash FROM credentials")).scalar()

    assert "correct horse" not in stored
    assert stored.startswith("scrypt$")


def test_usernames_are_unique(local_client):
    client, _ = local_client
    client.post("/auth/register", json={"username": "alice", "password": "correct horse"})

    again = client.post("/auth/register", json={"username": "alice", "password": "different pw"})

    assert again.status_code == 400
    assert "taken" in again.json()["detail"]


def test_short_passwords_are_refused(local_client):
    client, _ = local_client

    response = client.post("/auth/register", json={"username": "alice", "password": "short"})

    assert response.status_code == 400
    assert "at least" in response.json()["detail"]


def test_wrong_password_and_unknown_user_are_indistinguishable(local_client):
    """Otherwise the API tells an attacker which usernames exist."""
    client, _ = local_client
    client.post("/auth/register", json={"username": "alice", "password": "correct horse"})

    wrong = client.post("/auth/sessions", json={"username": "alice", "password": "nope nope"})
    missing = client.post("/auth/sessions", json={"username": "ghost", "password": "nope nope"})

    assert wrong.status_code == missing.status_code == 401
    assert wrong.json() == missing.json()


def test_registration_can_be_closed(monkeypatch, tmp_path):
    _load(monkeypatch, tmp_path, ALLOW_REGISTRATION="false")
    app_module = importlib.import_module("app")
    client = TestClient(app_module.app)

    response = client.post("/auth/register", json={"username": "mallory", "password": "longenough"})

    assert response.status_code == 403


def test_registration_routes_are_absent_in_github_mode(monkeypatch, tmp_path):
    _load(monkeypatch, tmp_path, OAUTH_ID_GITHUB="id", OAUTH_SECRET_GITHUB="secret")
    app_module = importlib.import_module("app")
    client = TestClient(app_module.app)

    assert client.post("/auth/register", json={"username": "a", "password": "longenough"}).status_code == 404
    assert client.post("/auth/sessions", json={"username": "a", "password": "longenough"}).status_code == 404


def test_registered_users_can_share_with_each_other(local_client):
    client, _ = local_client
    alice = client.post("/auth/register", json={"username": "alice", "password": "correct horse"}).json()["token"]
    bob = client.post("/auth/register", json={"username": "bob", "password": "battery staple"}).json()["token"]
    ah = {"Authorization": f"Bearer {alice}"}
    bh = {"Authorization": f"Bearer {bob}"}

    client.post("/secrets", json={"key": "k", "value": "v"}, headers=ah)
    assert client.get("/secrets", headers=bh).json() == {"items": []}

    client.post("/secrets/k/share", json={"github_id": "bob"}, headers=ah)

    assert client.get("/secrets", headers=bh).json() == {
        "items": [{"key": "k", "value": "v", "owner_id": "alice"}]
    }
    # Sharing grants read, not control.
    assert client.delete("/secrets/k", headers=bh).status_code == 404
