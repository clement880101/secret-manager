"""Rotating the encryption key must not make existing secrets unreadable."""

import importlib
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet


OLD_KEY = Fernet.generate_key().decode()
NEW_KEY = Fernet.generate_key().decode()


def _load(monkeypatch, db_path, key, retired=""):
    monkeypatch.setenv("DB_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("SECRET_ENCRYPTION_KEY", key)
    monkeypatch.setenv("SECRET_ENCRYPTION_KEYS_RETIRED", retired)

    project_root = Path(__file__).resolve().parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    for name in list(sys.modules):
        if (
            name in ("database", "crypto", "settings", "migrations", "rotate_keys",
                     "auth", "secret_manager")
            or name.startswith(("auth.", "secret_manager."))
        ):
            del sys.modules[name]

    database = importlib.import_module("database")
    importlib.import_module("auth.models")
    importlib.import_module("secret_manager.models")
    service = importlib.import_module("secret_manager.service")
    crypto = importlib.import_module("crypto")
    database.init_db()
    return database, service, crypto


@pytest.fixture()
def db_path(tmp_path):
    return tmp_path / "rotate.db"


def test_swapping_the_key_without_retiring_the_old_one_fails_loudly(monkeypatch, db_path):
    """The failure mode this whole mechanism exists to prevent."""
    _, service, _ = _load(monkeypatch, db_path, OLD_KEY)
    service.put_secret("alice", "k", "hunter2")

    _, service, _ = _load(monkeypatch, db_path, NEW_KEY)

    with pytest.raises(RuntimeError, match="SECRET_ENCRYPTION_KEYS_RETIRED"):
        service.get_secret_for_user("alice", "k")


def test_a_retired_key_keeps_old_values_readable(monkeypatch, db_path):
    """Step one of a rotation: new key in front, old one still accepted."""
    _, service, _ = _load(monkeypatch, db_path, OLD_KEY)
    service.put_secret("alice", "old", "written-before")

    _, service, _ = _load(monkeypatch, db_path, NEW_KEY, retired=OLD_KEY)

    assert service.get_secret_for_user("alice", "old")["value"] == "written-before"
    service.put_secret("alice", "new", "written-after")
    assert service.get_secret_for_user("alice", "new")["value"] == "written-after"


def test_rotation_rewrites_everything_onto_the_current_key(monkeypatch, db_path):
    database, service, crypto = _load(monkeypatch, db_path, OLD_KEY)
    service.put_secret("alice", "one", "first")
    service.put_secret("alice", "two", "second")

    database, service, crypto = _load(monkeypatch, db_path, NEW_KEY, retired=OLD_KEY)
    rotate_keys = importlib.import_module("rotate_keys")

    summary = rotate_keys.rotate()

    assert summary == {"examined": 2, "rewritten": 2, "remaining": 0}
    assert service.get_secret_for_user("alice", "one")["value"] == "first"

    # Step two: the retired key can now be dropped entirely.
    _, service, _ = _load(monkeypatch, db_path, NEW_KEY)
    assert service.get_secret_for_user("alice", "one")["value"] == "first"
    assert service.get_secret_for_user("alice", "two")["value"] == "second"


def test_rotating_twice_rewrites_nothing_the_second_time(monkeypatch, db_path):
    _, service, _ = _load(monkeypatch, db_path, OLD_KEY)
    service.put_secret("alice", "k", "v")

    _load(monkeypatch, db_path, NEW_KEY, retired=OLD_KEY)
    rotate_keys = importlib.import_module("rotate_keys")
    rotate_keys.rotate()

    assert rotate_keys.rotate()["rewritten"] == 0


def test_rotation_picks_up_plaintext_written_before_encryption(monkeypatch, db_path):
    """A deployment that ran without a key at all should end up encrypted."""
    monkeypatch.setenv("SECRET_ENCRYPTION_KEY", "")
    _, service, _ = _load(monkeypatch, db_path, "")
    service.put_secret("alice", "legacy", "plain")

    _, service, _ = _load(monkeypatch, db_path, NEW_KEY)
    rotate_keys = importlib.import_module("rotate_keys")

    assert rotate_keys.rotate()["rewritten"] == 1
    assert service.get_secret_for_user("alice", "legacy")["value"] == "plain"


def test_migrations_run_and_are_recorded(monkeypatch, db_path):
    database, _, _ = _load(monkeypatch, db_path, NEW_KEY)
    migrations = importlib.import_module("migrations")

    assert migrations.table_exists("schema_migrations")
    # Running again applies nothing, which is what makes restarts safe.
    assert migrations.run_migrations() == []


def test_rotation_across_many_batches_misses_nothing(monkeypatch, db_path):
    """The bug this guards against lost 500 of 1200 secrets.

    Paging with OFFSET assumes a stable scan order. Rewriting a row writes a
    new tuple, which moves it, so later pages skipped rows earlier pages had
    pushed past. A single-secret test passes happily; only a multi-batch one
    finds it.
    """
    _, service, _ = _load(monkeypatch, db_path, OLD_KEY)
    total = 250
    for i in range(total):
        service.put_secret("alice", f"key-{i:04d}", f"value-{i:04d}")

    _load(monkeypatch, db_path, NEW_KEY, retired=OLD_KEY)
    rotate_keys = importlib.import_module("rotate_keys")

    # A batch size well below the row count, so it has to paginate.
    summary = rotate_keys.rotate(batch_size=40)

    assert summary["examined"] == total
    assert summary["rewritten"] == total
    assert summary["remaining"] == 0

    # The real test: readable with the retired key gone.
    _, service, _ = _load(monkeypatch, db_path, NEW_KEY)
    for i in range(total):
        assert service.get_secret_for_user("alice", f"key-{i:04d}")["value"] == f"value-{i:04d}"


def test_rotation_reports_anything_it_could_not_move(monkeypatch, db_path):
    """The caller has to know before dropping the retired key."""
    _, service, _ = _load(monkeypatch, db_path, OLD_KEY)
    service.put_secret("alice", "k", "v")

    _load(monkeypatch, db_path, NEW_KEY, retired=OLD_KEY)
    rotate_keys = importlib.import_module("rotate_keys")

    assert rotate_keys.rotate()["remaining"] == 0
