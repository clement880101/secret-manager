"""Login state must survive a restart and be visible to every replica."""

import importlib
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException


KEY = Fernet.generate_key().decode()


def _load(monkeypatch, db_path, key=KEY):
    """Import the app modules fresh, as a newly started replica would."""
    monkeypatch.setenv("DB_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("SECRET_ENCRYPTION_KEY", key)
    monkeypatch.setenv("OAUTH_ID_GITHUB", "client-id")
    monkeypatch.setenv("OAUTH_SECRET_GITHUB", "client-secret")
    monkeypatch.setenv("BACKEND_URL", "https://api.example.com")

    project_root = Path(__file__).resolve().parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    for name in list(sys.modules):
        if (
            name in ("database", "crypto", "settings", "auth", "secret_manager")
            or name.startswith(("auth.", "secret_manager."))
        ):
            del sys.modules[name]

    database = importlib.import_module("database")
    models = importlib.import_module("auth.models")
    importlib.import_module("secret_manager.models")
    service = importlib.import_module("auth.service")
    database.init_db()
    return database, service, models


@pytest.fixture()
def db_path(tmp_path):
    return tmp_path / "auth.db"


def test_login_survives_a_restart(monkeypatch, db_path):
    """A redeploy mid-login used to lose the session entirely."""
    _, service, _ = _load(monkeypatch, db_path)
    started = service.initiate_login()

    # A different process, same database.
    _, service, _ = _load(monkeypatch, db_path)

    assert service.get_session_status(started["session_id"]) == {"status": "pending"}


def test_token_is_handed_over_once_then_the_session_is_gone(monkeypatch, db_path):
    _, service, _ = _load(monkeypatch, db_path)
    started = service.initiate_login()
    monkeypatch.setattr(
        service,
        "fetch_github_user",
        lambda token, token_kind="oauth": {"id": 55, "login": "u", "name": None, "avatar_url": None},
    )
    service.complete_session(
        started["session_id"],
        {"access_token": "gho_realtoken", "token_type": "bearer", "scope": ""},
        {"id": "55"},
    )

    first = service.get_session_status(started["session_id"])
    assert first == {"status": "ready", "token": "gho_realtoken", "user_id": "55"}

    with pytest.raises(HTTPException) as excinfo:
        service.get_session_status(started["session_id"])
    assert excinfo.value.status_code == 404


def test_pending_token_is_encrypted_at_rest(monkeypatch, db_path):
    """The row holds a live GitHub token until the CLI collects it."""
    database, service, models = _load(monkeypatch, db_path)
    started = service.initiate_login()
    service.complete_session(
        started["session_id"],
        {"access_token": "gho_realtoken", "token_type": "bearer", "scope": ""},
        {"id": "55"},
    )

    with database.session_scope() as db:
        stored = db.get(models.LoginSession, started["session_id"]).access_token

    assert "gho_realtoken" not in stored
    assert stored.startswith("enc:v1:")


def test_state_cannot_be_replayed(monkeypatch, db_path):
    """Redeeming a state clears it, so a repeated callback is rejected."""
    _, service, _ = _load(monkeypatch, db_path)
    started = service.initiate_login()
    state = started["auth_url"].split("state=")[1].split("&")[0]

    assert service._validate_state(state) == started["session_id"]

    with pytest.raises(HTTPException) as excinfo:
        service._validate_state(state)
    assert excinfo.value.status_code == 400


def test_expired_sessions_are_purged(monkeypatch, db_path):
    database, service, models = _load(monkeypatch, db_path)
    started = service.initiate_login()

    with database.session_scope() as db:
        record = db.get(models.LoginSession, started["session_id"])
        record.created_at -= service.SESSION_TTL_SECONDS + 60

    with pytest.raises(HTTPException) as excinfo:
        service.get_session_status(started["session_id"])
    assert excinfo.value.status_code == 404

    with database.session_scope() as db:
        assert db.get(models.LoginSession, started["session_id"]) is None


def test_two_replicas_share_one_login(monkeypatch, db_path):
    """The login is started on one instance and completed on another."""
    _, replica_a, _ = _load(monkeypatch, db_path)
    started = replica_a.initiate_login()
    state = started["auth_url"].split("state=")[1].split("&")[0]

    _, replica_b, _ = _load(monkeypatch, db_path)
    assert replica_b._validate_state(state) == started["session_id"]
    replica_b.complete_session(
        started["session_id"],
        {"access_token": "gho_x", "token_type": "bearer", "scope": ""},
        {"id": "77"},
    )

    _, replica_c, _ = _load(monkeypatch, db_path)
    assert replica_c.get_session_status(started["session_id"])["token"] == "gho_x"
