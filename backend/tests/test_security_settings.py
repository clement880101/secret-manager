"""Cover the switches that decide how exposed a deployment is."""

import importlib
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


def _app_modules():
    """Reload the app graph, packages included, against current environment."""
    project_root = Path(__file__).resolve().parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    for name in list(sys.modules):
        if (
            name in ("database", "settings", "app", "version", "crypto", "audit",
                     "audit_models", "migrations", "auth", "secret_manager")
            or name.startswith(("auth.", "secret_manager."))
        ):
            del sys.modules[name]
    return importlib.import_module("app")


@pytest.fixture()
def build_app(monkeypatch, tmp_path):
    """Build the real FastAPI app under a given environment."""
    created = []

    def _build(**env):
        monkeypatch.setenv("DB_URL", f"sqlite:///{tmp_path / 'secrets.db'}")
        for key in ("ENABLE_API_DOCS", "ALLOWED_ORIGINS"):
            monkeypatch.delenv(key, raising=False)
        for key, value in env.items():
            monkeypatch.setenv(key, value)
        module = _app_modules()
        created.append(module)
        return TestClient(module.app)

    yield _build

    for name in list(sys.modules):
        if (
            name in ("database", "settings", "app", "auth", "secret_manager")
            or name.startswith(("auth.", "secret_manager."))
        ):
            del sys.modules[name]


def test_api_docs_are_off_by_default(build_app):
    client = build_app()

    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_api_docs_can_be_enabled(build_app):
    client = build_app(ENABLE_API_DOCS="true")

    assert client.get("/docs").status_code == 200
    assert client.get("/openapi.json").status_code == 200


def test_no_cors_grant_by_default(build_app):
    client = build_app()

    response = client.get("/healthz", headers={"Origin": "https://evil.example"})

    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers


def test_cors_grant_is_limited_to_configured_origins(build_app):
    client = build_app(ALLOWED_ORIGINS="https://app.example")

    allowed = client.get("/healthz", headers={"Origin": "https://app.example"})
    denied = client.get("/healthz", headers={"Origin": "https://evil.example"})

    assert allowed.headers.get("access-control-allow-origin") == "https://app.example"
    assert allowed.headers.get("access-control-allow-credentials") == "true"
    assert "access-control-allow-origin" not in denied.headers


def test_wildcard_origin_never_carries_credentials(build_app):
    """`*` plus credentials is rejected by browsers and defeats the point of CORS."""
    client = build_app(ALLOWED_ORIGINS="*")

    response = client.get("/healthz", headers={"Origin": "https://evil.example"})

    assert response.headers.get("access-control-allow-origin") == "*"
    assert "access-control-allow-credentials" not in response.headers





# --- resource limits -------------------------------------------------------

def _token(client):
    return client.post(
        "/auth/register", json={"username": "alice", "password": "a good password"}
    ).json()["token"]


def test_an_oversized_body_is_refused_before_it_is_buffered(build_app):
    """One authenticated account could otherwise write until the disk filled."""
    client = build_app()
    headers = {"Authorization": f"Bearer {_token(client)}"}

    response = client.post(
        "/secrets", json={"key": "big", "value": "A" * (2 * 1024 * 1024)}, headers=headers
    )

    assert response.status_code == 413


def test_an_oversized_value_is_refused(build_app):
    client = build_app()
    headers = {"Authorization": f"Bearer {_token(client)}"}

    response = client.post(
        "/secrets", json={"key": "k", "value": "A" * (100 * 1024)}, headers=headers
    )

    assert response.status_code == 422


def test_an_oversized_key_is_refused(build_app):
    client = build_app()
    headers = {"Authorization": f"Bearer {_token(client)}"}

    response = client.post("/secrets", json={"key": "K" * 1000, "value": "v"}, headers=headers)

    assert response.status_code == 422


def test_a_realistic_secret_still_fits(build_app):
    """The limits must not refuse a certificate or a private key."""
    client = build_app()
    headers = {"Authorization": f"Bearer {_token(client)}"}
    private_key = "-----BEGIN PRIVATE KEY-----\n" + "M" * 3000 + "\n-----END PRIVATE KEY-----"

    assert client.post(
        "/secrets", json={"key": "tls", "value": private_key}, headers=headers
    ).status_code == 200
    assert client.get("/secrets/tls", headers=headers).json()["value"] == private_key


# --- operational endpoints and switches ------------------------------------

def test_metrics_is_off_by_default(build_app):
    """The counts are not something every deployment wants unauthenticated."""
    client = build_app()

    assert client.get("/metrics").status_code == 404


def test_metrics_reports_counts_when_enabled(build_app):
    client = build_app(ENABLE_METRICS="true")
    headers = {"Authorization": f"Bearer {_token(client)}"}
    client.post("/secrets", json={"key": "k", "value": "v"}, headers=headers)

    body = client.get("/metrics").text

    assert "secretmgr_secrets_total 1" in body
    # Two users: alice, plus the "admin" the bootstrap token creates.
    assert "secretmgr_users_total 2" in body
    assert "secretmgr_build_info" in body
    # A gauge of how many secrets exist must never become a list of them.
    assert "\"v\"" not in body and "smt_" not in body


def test_tokens_do_not_expire_by_default(build_app):
    client = build_app()
    headers = {"Authorization": f"Bearer {_token(client)}"}

    assert client.get("/auth/whoami", headers=headers).status_code == 200


def test_tokens_expire_when_a_ttl_is_set(build_app):
    import sys

    client = build_app(TOKEN_TTL_DAYS="1")
    token = _token(client)
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/auth/whoami", headers=headers).status_code == 200

    database = sys.modules["database"]
    models = sys.modules["auth.models"]
    with database.session_scope() as db:
        for row in db.query(models.ApiToken).all():
            row.created_at -= 3 * 86400

    assert client.get("/auth/whoami", headers=headers).status_code == 401
    # The expired token is deleted, not merely refused. The bootstrap token
    # was not aged, so it survives -- check for this one specifically.
    local = sys.modules["auth.local"]
    with database.session_scope() as db:
        assert db.get(models.ApiToken, local.hash_token(token)) is None


def test_an_administrator_sees_everyone_s_audit_trail(build_app):
    client = build_app(ADMIN_USERS="root")
    alice = client.post(
        "/auth/register", json={"username": "alice", "password": "a good password"}
    ).json()["token"]
    root = client.post(
        "/auth/register", json={"username": "root", "password": "another password"}
    ).json()["token"]
    client.post("/secrets", json={"key": "k", "value": "v"}, headers={"Authorization": f"Bearer {alice}"})

    as_admin = client.get("/auth/audit", headers={"Authorization": f"Bearer {root}"}).json()
    as_alice = client.get("/auth/audit", headers={"Authorization": f"Bearer {alice}"}).json()

    assert as_admin["scope"] == "all"
    assert any(e["actor"] == "alice" for e in as_admin["items"])
    assert as_alice["scope"] == "self"
    assert all("actor" not in e for e in as_alice["items"])
