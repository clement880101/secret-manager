import importlib
import json
import os
import sys
from pathlib import Path
from typing import Optional

import pytest
from typer.testing import CliRunner

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cli


class DummyResponse:
    def __init__(self, status_code: int, json_data: Optional[dict] = None, text: str = ""):
        self.status_code = status_code
        self._json = json_data or {}
        self.text = text

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise AssertionError("raise_for_status should not be called for error responses in these tests.")


def test_resolve_login_url_selects_first_known_key():
    payload = {
        "url": "https://example.com/fallback",
        "auth_url": "https://example.com/auth",
        "login_url": "https://example.com/login",
        "verification_url": "https://example.com/verify",
    }
    assert cli._resolve_login_url(payload) == "https://example.com/verify"


def test_resolve_login_url_returns_none_when_missing():
    assert cli._resolve_login_url({"unexpected": "value"}) is None


def test_write_and_load_token_roundtrip(monkeypatch, tmp_path):
    token_file = tmp_path / "token.json"
    monkeypatch.setattr(cli, "TOKEN_FILE", token_file)

    cli._write_token("token-123", "octocat")

    stored = json.loads(token_file.read_text())
    assert stored["access_token"] == "token-123"
    assert stored["github_id"] == "octocat"
    assert isinstance(stored["created_at"], int)

    loaded = cli._load_token()
    assert loaded == stored


def test_logout_without_session(monkeypatch, tmp_path):
    token_file = tmp_path / "token.json"
    monkeypatch.setattr(cli, "TOKEN_FILE", token_file)

    runner = CliRunner()
    result = runner.invoke(cli.app, ["logout"])

    assert result.exit_code == 0
    assert "No session found." in result.stdout


def test_logout_removes_token_file(monkeypatch, tmp_path):
    token_file = tmp_path / "token.json"
    monkeypatch.setattr(cli, "TOKEN_FILE", token_file)

    token_file.write_text(json.dumps({"access_token": "abc", "github_id": "octocat", "created_at": 0}))

    runner = CliRunner()
    result = runner.invoke(cli.app, ["logout"])

    assert result.exit_code == 0
    assert "Logging out octocat" in result.stdout
    assert not token_file.exists()


def test_commands_require_login_when_no_token(monkeypatch, tmp_path):
    token_file = tmp_path / "token.json"
    monkeypatch.setattr(cli, "TOKEN_FILE", token_file)

    runner = CliRunner()
    result = runner.invoke(cli.app, ["list"])

    assert result.exit_code == 1
    assert "Not logged in" in result.stdout


def test_request_with_auth_attaches_bearer_token(monkeypatch):
    captured_headers = {}

    def fake_ensure_token(scope=cli.DEFAULT_SCOPE):
        return {"access_token": "secret-token"}

    def fake_request(method, url, **kwargs):
        captured_headers.update(kwargs.get("headers", {}))
        return DummyResponse(200, {"ok": True})

    monkeypatch.setattr(cli, "_ensure_token", fake_ensure_token)
    monkeypatch.setattr(cli.httpx, "request", fake_request)

    response = cli._request_with_auth("GET", "/secrets")

    assert isinstance(response, DummyResponse)
    assert captured_headers.get("Authorization") == "Bearer secret-token"


def test_create_secret_duplicate_key(monkeypatch):
    def fake_request(method, path, **kwargs):
        assert method == "POST"
        assert path == "/secrets"
        return DummyResponse(409, {"detail": "duplicate"})

    monkeypatch.setattr(cli, "_request_with_auth", fake_request)

    runner = CliRunner()
    result = runner.invoke(cli.app, ["create", "api_key", "secret"])

    assert result.exit_code == 1
    assert "Secret `api_key` already exists." in result.stdout


def test_loads_dotenv_if_present(monkeypatch, tmp_path):
    for key in ("BACKEND_URL", "SECRETS_HTTP_TIMEOUT"):
        monkeypatch.delenv(key, raising=False)

    dotenv_file = tmp_path / ".env"
    dotenv_file.write_text("BACKEND_URL=https://dotenv.example\nSECRETS_HTTP_TIMEOUT=2.5\n")

    original_cwd = Path.cwd()
    monkeypatch.chdir(tmp_path)

    importlib.reload(cli)

    assert cli.API_URL == "https://dotenv.example"
    assert cli.HTTP_TIMEOUT == 2.5

    monkeypatch.delenv("BACKEND_URL", raising=False)
    monkeypatch.delenv("SECRETS_HTTP_TIMEOUT", raising=False)
    os.chdir(original_cwd)
    importlib.reload(cli)



def test_token_file_is_not_readable_by_others(monkeypatch, tmp_path):
    import stat as stat_module

    token_file = tmp_path / "token.json"
    monkeypatch.setattr(cli, "TOKEN_FILE", token_file)

    cli._write_token("ghp-secret", "octocat")

    mode = stat_module.S_IMODE(token_file.stat().st_mode)
    assert mode == 0o600, f"token file holds a live credential but is mode {oct(mode)}"


def test_token_file_written_over_a_loose_file_is_tightened(monkeypatch, tmp_path):
    import stat as stat_module

    token_file = tmp_path / "token.json"
    monkeypatch.setattr(cli, "TOKEN_FILE", token_file)
    token_file.write_text("{}")
    token_file.chmod(0o644)

    cli._write_token("ghp-secret", "octocat")

    assert stat_module.S_IMODE(token_file.stat().st_mode) == 0o600


def test_loading_a_legacy_world_readable_token_repairs_it(monkeypatch, tmp_path):
    import stat as stat_module

    token_file = tmp_path / "token.json"
    monkeypatch.setattr(cli, "TOKEN_FILE", token_file)
    token_file.write_text(json.dumps({"access_token": "abc", "github_id": "octocat"}))
    token_file.chmod(0o644)

    loaded = cli._load_token()

    assert loaded["github_id"] == "octocat"
    assert stat_module.S_IMODE(token_file.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://example.com:8000", True),
        ("http://203.0.113.10:8000", True),
        ("https://example.com", False),
        ("http://localhost:8000", False),
        ("http://127.0.0.1:8000", False),
        ("http://[::1]:8000", False),
    ],
)
def test_cleartext_remote_detection(url, expected):
    assert cli._is_cleartext_remote(url) is expected


def test_insecure_warning_can_be_silenced(monkeypatch, capsys):
    monkeypatch.setattr(cli, "API_URL", "http://example.com:8000")
    monkeypatch.setenv("SECRETS_ALLOW_INSECURE", "1")

    cli._warn_if_insecure()

    assert capsys.readouterr().err == ""


def test_insecure_warning_is_emitted_for_remote_http(monkeypatch, capsys):
    monkeypatch.setattr(cli, "API_URL", "http://example.com:8000")
    monkeypatch.delenv("SECRETS_ALLOW_INSECURE", raising=False)

    cli._warn_if_insecure()

    assert "plain HTTP" in capsys.readouterr().err
