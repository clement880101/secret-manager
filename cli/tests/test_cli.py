import importlib
import json
import os
import sys
from pathlib import Path
from typing import Optional

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

