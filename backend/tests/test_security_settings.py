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
            name in ("database", "settings", "app", "auth", "secret_manager")
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
        monkeypatch.setenv("OAUTH_ID_GITHUB", "id")
        monkeypatch.setenv("OAUTH_SECRET_GITHUB", "secret")
        monkeypatch.setenv("BACKEND_URL", "http://localhost:8000")
        for key in ("ENABLE_API_DOCS", "ENABLE_TEST_LOGIN", "ALLOWED_ORIGINS"):
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


def test_test_login_route_is_off_by_default(build_app):
    client = build_app()

    assert client.post("/auth/login-test", json={"token": "x"}).status_code == 404


def test_test_login_route_can_be_enabled(build_app, monkeypatch):
    client = build_app(ENABLE_TEST_LOGIN="1")

    auth_service = sys.modules["auth.service"]
    monkeypatch.setattr(
        auth_service,
        "fetch_github_user",
        lambda token, token_kind="oauth": {"id": 4242, "login": "u", "name": None, "avatar_url": None},
    )

    response = client.post("/auth/login-test", json={"token": "pat"})

    assert response.status_code == 200
    assert response.json()["user_id"] == "4242"
