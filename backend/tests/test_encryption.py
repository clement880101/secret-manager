"""Secret values must not sit in the database in plaintext."""

import importlib
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select


KEY = Fernet.generate_key().decode()
OTHER_KEY = Fernet.generate_key().decode()


def _load(monkeypatch, tmp_path, key=None):
    """Import the app modules against a fresh database and key."""
    monkeypatch.setenv("DB_URL", f"sqlite:///{tmp_path / 'secrets.db'}")
    if key is None:
        monkeypatch.delenv("SECRET_ENCRYPTION_KEY", raising=False)
    else:
        monkeypatch.setenv("SECRET_ENCRYPTION_KEY", key)

    project_root = Path(__file__).resolve().parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    for name in list(sys.modules):
        if (
            name in ("database", "crypto", "settings", "app", "auth", "secret_manager")
            or name.startswith(("auth.", "secret_manager."))
        ):
            del sys.modules[name]

    database = importlib.import_module("database")
    importlib.import_module("auth.models")
    models = importlib.import_module("secret_manager.models")
    service = importlib.import_module("secret_manager.service")
    database.init_db()
    return database, service, models


def _stored_value(database, models):
    with database.session_scope() as session:
        return session.scalars(select(models.Secret)).one().value


def test_value_is_not_stored_in_plaintext(monkeypatch, tmp_path):
    database, service, models = _load(monkeypatch, tmp_path, KEY)

    service.put_secret("alice", "k", "hunter2")

    raw = _stored_value(database, models)
    assert "hunter2" not in raw
    assert raw.startswith("enc:v1:")


def test_roundtrip_through_the_service(monkeypatch, tmp_path):
    _, service, _ = _load(monkeypatch, tmp_path, KEY)

    service.put_secret("alice", "k", "hunter2")

    assert service.get_secret_for_user("alice", "k")["value"] == "hunter2"
    # list deliberately carries no values.
    assert service.list_visible("alice") == [{"key": "k", "owner_id": "alice", "shared": False}]


def test_shared_secret_decrypts_for_the_recipient(monkeypatch, tmp_path):
    _, service, _ = _load(monkeypatch, tmp_path, KEY)

    service.put_secret("alice", "k", "hunter2")
    service.put_secret("bob", "own", "bob-secret")  # bob has to exist to be shared with
    service.share_secret("alice", "k", "bob")

    assert service.get_secret_for_user("bob", "k")["value"] == "hunter2"


def test_without_a_key_values_are_stored_as_before(monkeypatch, tmp_path):
    """No key must not break anything -- deployments upgrade before they configure."""
    database, service, models = _load(monkeypatch, tmp_path, None)

    service.put_secret("alice", "k", "hunter2")

    assert _stored_value(database, models) == "hunter2"
    assert service.get_secret_for_user("alice", "k")["value"] == "hunter2"


def test_legacy_plaintext_rows_stay_readable_after_a_key_is_added(monkeypatch, tmp_path):
    """The live database already holds plaintext rows; they must survive."""
    _, service, _ = _load(monkeypatch, tmp_path, None)
    service.put_secret("alice", "legacy", "old-value")

    # Same database file, now with encryption switched on.
    _, service, _ = _load(monkeypatch, tmp_path, KEY)

    assert service.get_secret_for_user("alice", "legacy")["value"] == "old-value"

    service.put_secret("alice", "fresh", "new-value")
    assert {item["key"] for item in service.list_visible("alice")} == {"legacy", "fresh"}
    assert service.get_secret_for_user("alice", "fresh")["value"] == "new-value"


def test_ciphertext_without_a_key_fails_loudly(monkeypatch, tmp_path):
    _, service, _ = _load(monkeypatch, tmp_path, KEY)
    service.put_secret("alice", "k", "hunter2")

    _, service, _ = _load(monkeypatch, tmp_path, None)

    with pytest.raises(RuntimeError, match="encrypted but SECRET_ENCRYPTION_KEY is not set"):
        service.get_secret_for_user("alice", "k")


def test_wrong_key_fails_loudly(monkeypatch, tmp_path):
    _, service, _ = _load(monkeypatch, tmp_path, KEY)
    service.put_secret("alice", "k", "hunter2")

    _, service, _ = _load(monkeypatch, tmp_path, OTHER_KEY)

    with pytest.raises(RuntimeError, match="could not be decrypted"):
        service.get_secret_for_user("alice", "k")


def test_malformed_key_is_rejected(monkeypatch, tmp_path):
    _, service, _ = _load(monkeypatch, tmp_path, "not-a-valid-fernet-key")

    with pytest.raises(RuntimeError, match="not a valid Fernet key"):
        service.put_secret("alice", "k", "hunter2")
