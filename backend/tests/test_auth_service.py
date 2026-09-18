import importlib
import sys
import urllib.parse
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient


def test_parse_token_fetches_remote_user(monkeypatch, auth_service_module):
    service = auth_service_module["service"]
    database = auth_service_module["database"]
    User = auth_service_module["User"]

    captured = {}

    def fake_fetch(access_token, token_kind="oauth"):
        captured["token"] = access_token
        captured["token_kind"] = token_kind
        return {
            "id": 12345,
            "login": "remote-user",
            "name": "Remote User",
            "avatar_url": "https://example.com/avatar.png",
        }

    monkeypatch.setattr(service, "fetch_github_user", fake_fetch)

    user_id = service.parse_token("Bearer real-token")

    assert captured["token"] == "real-token"
    assert captured["token_kind"] == "oauth"
    assert user_id == "12345"
    with database.session_scope() as session:
        assert session.get(User, "12345") is not None


def test_parse_token_missing_header_raises(auth_service_module):
    service = auth_service_module["service"]

    with pytest.raises(HTTPException) as excinfo:
        service.parse_token(None)

    assert excinfo.value.status_code == 401


def test_login_with_personal_token(monkeypatch, auth_service_module):
    service = auth_service_module["service"]
    database = auth_service_module["database"]
    User = auth_service_module["User"]

    def fake_verify(access_token, token_kind="oauth"):
        assert token_kind == "pat"
        return {
            "id": "999",
            "login": "token-user",
            "name": "Token User",
            "avatar_url": "https://example.com/avatar.png",
        }

    monkeypatch.setattr(service, "verify_access_token", fake_verify)

    result = service.login_with_personal_token("ghp-example")

    assert result["access_token"] == "ghp-example"
    assert result["user"]["id"] == "999"

    with database.session_scope() as session:
        assert session.get(User, "999") is not None


def test_fetch_github_user_uses_token_scheme_for_pat(monkeypatch, auth_service_module):
    service = auth_service_module["service"]

    calls = []

    class FakeResponse:
        def __init__(self, status_code, payload=None):
            self.status_code = status_code
            self._payload = payload or {}

        def json(self):
            return self._payload

    def fake_get(url, headers, timeout):
        calls.append(headers["Authorization"])
        scheme = headers["Authorization"].split(" ", 1)[0]
        if scheme == "token":
            return FakeResponse(
                200,
                {
                    "id": 42,
                    "login": "pat-user",
                    "name": "PAT User",
                    "avatar_url": "https://example.com/avatar.png",
                },
            )
        return FakeResponse(401)

    monkeypatch.setattr(service.httpx, "get", fake_get)

    user = service.fetch_github_user("pat-example", token_kind="pat")

    assert calls == ["token pat-example"]
    assert user["login"] == "pat-user"


def test_fetch_github_user_keeps_bearer_for_oauth(monkeypatch, auth_service_module):
    service = auth_service_module["service"]

    calls = []

    class FakeResponse:
        def __init__(self, status_code, payload=None):
            self.status_code = status_code
            self._payload = payload or {}

        def json(self):
            return self._payload

    def fake_get(url, headers, timeout):
        calls.append(headers["Authorization"])
        return FakeResponse(
            200,
            {
                "id": 77,
                "login": "oauth-user",
                "name": "OAuth User",
                "avatar_url": "https://example.com/avatar.png",
            },
        )

    monkeypatch.setattr(service.httpx, "get", fake_get)

    user = service.fetch_github_user("oauth-example")

    assert calls == ["Bearer oauth-example"]
    assert user["login"] == "oauth-user"


def _build_auth_test_client(monkeypatch):
    monkeypatch.setenv("DB_URL", "sqlite:///:memory:")
    monkeypatch.setenv("OAUTH_ID_GITHUB", "client-id-123")
    monkeypatch.setenv("OAUTH_SECRET_GITHUB", "super-secret")
    monkeypatch.setenv("BACKEND_URL", "https://backend.example.com")

    project_root = Path(__file__).resolve().parent.parent
    project_root_str = str(project_root)
    if project_root_str not in sys.path:
        sys.path.insert(0, project_root_str)

    modules_to_clear = [
        "secret_manager.router",
        "secret_manager.models",
        "auth.router",
        "auth.service",
        "auth.models",
        "database",
    ]
    for name in modules_to_clear:
        sys.modules.pop(name, None)

    database = importlib.import_module("database")
    auth_router = importlib.import_module("auth.router")

    database.init_db()

    app = FastAPI()
    app.include_router(auth_router.router)
    return TestClient(app)


@pytest.fixture()
def auth_test_client(monkeypatch):
    return _build_auth_test_client(monkeypatch)


def test_login_route_returns_auth_link(auth_test_client):
    response = auth_test_client.post("/auth/login", params={"scope": "read:org"})

    assert response.status_code == 200

    payload = response.json()
    assert "session_id" in payload and payload["session_id"]
    assert "auth_url" in payload and payload["auth_url"]

    parsed = urllib.parse.urlparse(payload["auth_url"])
    assert parsed.scheme == "https"
    assert parsed.netloc == "github.com"
    assert parsed.path == "/login/oauth/authorize"

    query = urllib.parse.parse_qs(parsed.query)
    assert query["client_id"] == ["client-id-123"]
    assert query["redirect_uri"] == ["https://backend.example.com/auth/callback"]
    assert query["scope"] == ["read:org"]
    assert query["allow_signup"] == ["false"]
    assert query["state"][0]




def test_verify_access_token_caches_github_lookups(monkeypatch, auth_service_module):
    service = auth_service_module["service"]
    monkeypatch.setenv("TOKEN_CACHE_TTL_SECONDS", "300")
    service.TOKEN_CACHE.clear()

    calls = []

    def fake_fetch(access_token, token_kind="oauth"):
        calls.append(access_token)
        return {"id": 7, "login": "cached", "name": None, "avatar_url": None}

    monkeypatch.setattr(service, "fetch_github_user", fake_fetch)

    first = service.verify_access_token("tok")
    second = service.verify_access_token("tok")

    assert first == second
    assert calls == ["tok"], "second verification should be served from cache"


def test_verify_access_token_revalidates_after_ttl(monkeypatch, auth_service_module):
    service = auth_service_module["service"]
    monkeypatch.setenv("TOKEN_CACHE_TTL_SECONDS", "300")
    service.TOKEN_CACHE.clear()

    calls = []
    monkeypatch.setattr(
        service,
        "fetch_github_user",
        lambda access_token, token_kind="oauth": (
            calls.append(access_token),
            {"id": 7, "login": "cached", "name": None, "avatar_url": None},
        )[1],
    )

    service.verify_access_token("tok")
    # Age the entry past its TTL.
    cached_at, details = service.TOKEN_CACHE[service._token_cache_key("tok", "oauth")]
    service.TOKEN_CACHE[service._token_cache_key("tok", "oauth")] = (cached_at - 3600, details)
    service.verify_access_token("tok")

    assert len(calls) == 2, "an expired entry must trigger a fresh GitHub lookup"


def test_token_cache_can_be_disabled(monkeypatch, auth_service_module):
    service = auth_service_module["service"]
    monkeypatch.setenv("TOKEN_CACHE_TTL_SECONDS", "0")
    service.TOKEN_CACHE.clear()

    calls = []
    monkeypatch.setattr(
        service,
        "fetch_github_user",
        lambda access_token, token_kind="oauth": (
            calls.append(access_token),
            {"id": 7, "login": "u", "name": None, "avatar_url": None},
        )[1],
    )

    service.verify_access_token("tok")
    service.verify_access_token("tok")

    assert len(calls) == 2
    assert service.TOKEN_CACHE == {}


def test_token_cache_keys_do_not_contain_the_raw_token(auth_service_module):
    service = auth_service_module["service"]

    key = service._token_cache_key("super-secret-token", "oauth")

    assert "super-secret-token" not in key
    assert len(key) == 64
