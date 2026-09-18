"""Races that only appear once more than one replica is serving traffic.

The threaded cases need a database that supports real concurrent writers, so
they run against Postgres when TEST_POSTGRES_URL is set and skip otherwise.
SQLite serialises writers and would report success for code that is not
actually safe, which is worse than not testing it.
"""

import importlib
import os
import sys
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException
from sqlalchemy import text


POSTGRES_URL = os.getenv("TEST_POSTGRES_URL")
requires_postgres = pytest.mark.skipif(
    not POSTGRES_URL, reason="set TEST_POSTGRES_URL to exercise real concurrent writers"
)
CONCURRENCY = 8


def _load(monkeypatch, db_url):
    monkeypatch.setenv("DB_URL", db_url)
    monkeypatch.setenv("SECRET_ENCRYPTION_KEY", Fernet.generate_key().decode())

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
    auth_models = importlib.import_module("auth.models")
    secret_models = importlib.import_module("secret_manager.models")
    auth_service = importlib.import_module("auth.service")
    secret_service = importlib.import_module("secret_manager.service")
    database.init_db()
    with database.session_scope() as db:
        for table in ("shares", "secrets", "api_tokens", "credentials", "auth_attempts", "users"):
            db.execute(text(f"DELETE FROM {table}"))
    return database, auth_service, secret_service, auth_models, secret_models


def _race(fn, n=CONCURRENCY):
    """Run fn on n threads released simultaneously; tally outcomes by type."""
    barrier = threading.Barrier(n)

    def go(i):
        barrier.wait()
        try:
            fn(i)
            return "ok"
        except Exception as exc:  # noqa: BLE001 - tallying failure kinds is the point
            return type(exc).__name__

    with ThreadPoolExecutor(max_workers=n) as pool:
        return Counter(pool.map(go, range(n)))


@pytest.fixture()
def pg(monkeypatch):
    return _load(monkeypatch, POSTGRES_URL)


# --- deterministic: these run everywhere -----------------------------------

def test_ensure_user_is_idempotent(monkeypatch, tmp_path):
    _, _, _, auth_models, _ = _load(monkeypatch, f"sqlite:///{tmp_path / 'a.db'}")

    auth_models.ensure_user("alice")
    auth_models.ensure_user("alice")  # must not raise


def test_ensure_user_tolerates_losing_the_race(monkeypatch, tmp_path):
    """Simulate another replica inserting the row between our check and insert."""
    from sqlalchemy.exc import IntegrityError

    database, _, _, auth_models, _ = _load(monkeypatch, f"sqlite:///{tmp_path / 'a.db'}")

    real_scope = database.session_scope
    calls = {"n": 0}

    def exploding_scope():
        calls["n"] += 1
        if calls["n"] == 2:  # the insert transaction
            raise IntegrityError("duplicate key", None, Exception())
        return real_scope()

    monkeypatch.setattr(auth_models, "session_scope", exploding_scope)

    auth_models.ensure_user("bob")  # swallowed, because the row now exists


# --- real concurrent writers ------------------------------------------------

@requires_postgres
def test_first_request_from_a_new_user_does_not_500(pg):
    """Every authenticated request creates the user if absent."""
    _, auth_service, _, _, _ = pg

    outcomes = _race(lambda i: auth_service.get_or_create_user("newcomer"))

    assert outcomes == Counter(ok=CONCURRENCY), outcomes


@requires_postgres
def test_one_writer_wins_a_duplicate_key(pg):
    _, _, secret_service, _, _ = pg

    outcomes = _race(lambda i: secret_service.put_secret("alice", "dup", f"v{i}"))

    assert outcomes["ok"] == 1
    assert outcomes["ValueError"] == CONCURRENCY - 1


@requires_postgres
def test_concurrent_sharing_is_idempotent(pg):
    database, _, secret_service, _, secret_models = pg
    secret_service.put_secret("owner", "k", "v")

    outcomes = _race(lambda i: secret_service.share_secret("owner", "k", "target"))

    assert outcomes == Counter(ok=CONCURRENCY), outcomes
    with database.session_scope() as db:
        assert db.query(secret_models.Share).count() == 1
    assert len(secret_service.list_visible("target")) == 1


