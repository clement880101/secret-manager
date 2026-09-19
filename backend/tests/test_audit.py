"""A secret manager should be able to answer who read what, and when."""

import importlib
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


def _load(monkeypatch, tmp_path, **env):
    monkeypatch.setenv("DB_URL", f"sqlite:///{tmp_path / 'audit.db'}")
    for key in ("ENABLE_AUDIT_LOG", "AUDIT_RETENTION_DAYS", "BOOTSTRAP_TOKEN"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    project_root = Path(__file__).resolve().parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    for name in list(sys.modules):
        if (
            name in ("database", "crypto", "settings", "app", "version", "audit",
                     "audit_models", "auth", "secret_manager")
            or name.startswith(("auth.", "secret_manager."))
        ):
            del sys.modules[name]

    database = importlib.import_module("database")
    importlib.import_module("auth.models")
    importlib.import_module("secret_manager.models")
    audit = importlib.import_module("audit")
    app_module = importlib.import_module("app")
    database.init_db()
    return TestClient(app_module.app), audit


@pytest.fixture()
def client(monkeypatch, tmp_path):
    test_client, audit = _load(monkeypatch, tmp_path)
    token = test_client.post(
        "/auth/register", json={"username": "alice", "password": "a good password"}
    ).json()["token"]
    test_client.hdrs = {"Authorization": f"Bearer {token}"}
    test_client.audit = audit
    return test_client


def _actions(client):
    return [item["action"] for item in client.get("/auth/audit", headers=client.hdrs).json()["items"]]


def test_reading_a_secret_is_recorded(client):
    """The question after a laptop goes missing is which values were read."""
    client.post("/secrets", json={"key": "k", "value": "v"}, headers=client.hdrs)
    client.get("/secrets/k", headers=client.hdrs)

    events = client.get("/auth/audit", headers=client.hdrs).json()["items"]
    reads = [e for e in events if e["action"] == "secret.read"]

    assert len(reads) == 1
    assert reads[0]["target"] == "k"


def test_a_refused_read_is_not_recorded_as_a_read(client, monkeypatch, tmp_path):
    """Otherwise the trail cannot distinguish access from an attempt at it."""
    client.post("/secrets", json={"key": "k", "value": "v"}, headers=client.hdrs)
    other = client.post(
        "/auth/register", json={"username": "bob", "password": "another password"}
    ).json()["token"]

    assert client.get("/secrets/k", headers={"Authorization": f"Bearer {other}"}).status_code == 403

    bob_events = client.get("/auth/audit", headers={"Authorization": f"Bearer {other}"}).json()["items"]
    assert [e for e in bob_events if e["action"] == "secret.read"] == []


def test_writes_shares_and_deletions_are_recorded(client):
    client.post("/auth/register", json={"username": "bob", "password": "another password"})
    client.post("/secrets", json={"key": "k", "value": "v"}, headers=client.hdrs)
    client.post("/secrets/k/share", json={"user_id": "bob"}, headers=client.hdrs)
    client.delete("/secrets/k", headers=client.hdrs)

    actions = _actions(client)

    assert "secret.create" in actions
    assert "secret.share" in actions
    assert "secret.delete" in actions


def test_registration_and_login_are_recorded(client):
    client.post("/auth/sessions", json={"username": "alice", "password": "a good password"})

    actions = _actions(client)

    assert "auth.register" in actions
    assert "auth.login" in actions


def test_the_trail_never_contains_a_value_or_a_token(client):
    client.post("/secrets", json={"key": "k", "value": "hunter2"}, headers=client.hdrs)
    client.get("/secrets/k", headers=client.hdrs)

    raw = str(client.get("/auth/audit", headers=client.hdrs).json())

    assert "hunter2" not in raw
    assert "smt_" not in raw


def test_you_only_see_your_own_activity(client):
    client.post("/secrets", json={"key": "k", "value": "v"}, headers=client.hdrs)
    other = client.post(
        "/auth/register", json={"username": "bob", "password": "another password"}
    ).json()["token"]

    bob_events = client.get("/auth/audit", headers={"Authorization": f"Bearer {other}"}).json()["items"]

    assert {e["action"] for e in bob_events} <= {"auth.register"}


def test_the_audit_trail_requires_authentication(client):
    assert client.get("/auth/audit").status_code == 401


def test_recording_never_breaks_the_request(client, monkeypatch):
    """Losing a line is better than refusing a legitimate operation."""
    def explode(*args, **kwargs):
        raise RuntimeError("audit storage is unavailable")

    monkeypatch.setattr(client.audit, "session_scope", explode)

    response = client.post("/secrets", json={"key": "k2", "value": "v"}, headers=client.hdrs)

    assert response.status_code == 200


def test_old_events_are_pruned(client):
    client.post("/secrets", json={"key": "k", "value": "v"}, headers=client.hdrs)
    audit = client.audit
    database = sys.modules["database"]
    models = sys.modules["audit_models"]

    with database.session_scope() as db:
        for row in db.query(models.AuditEvent).all():
            row.at -= 200 * 86400

    assert audit.prune() > 0
    assert client.get("/auth/audit", headers=client.hdrs).json()["items"] == []


def test_auditing_can_be_disabled(monkeypatch, tmp_path):
    test_client, _ = _load(monkeypatch, tmp_path, ENABLE_AUDIT_LOG="false")
    token = test_client.post(
        "/auth/register", json={"username": "alice", "password": "a good password"}
    ).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    test_client.post("/secrets", json={"key": "k", "value": "v"}, headers=headers)

    assert test_client.get("/auth/audit", headers=headers).json()["items"] == []
