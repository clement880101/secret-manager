import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict
from uuid import uuid4

import pytest
from dotenv import load_dotenv


CLI_BINARY = Path(__file__).resolve().parent / "cli"
TOKEN_NAME = ".token"


def _run_cli(env: Dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [str(CLI_BINARY), *args],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    return result


def _ensure_success(result: subprocess.CompletedProcess[str]) -> None:
    if result.returncode != 0:
        details = f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        pytest.fail(f"CLI command failed with exit code {result.returncode}\n{details}")


@dataclass
class CLIContext:
    env: Dict[str, str]
    home: Path
    tokens: Dict[str, str]

    @property
    def token_path(self) -> Path:
        return self.home / TOKEN_NAME

    def login(self, user_key: str) -> Dict[str, str]:
        if user_key not in self.tokens:
            raise KeyError(f"Unknown user key: {user_key}")
        if self.token_path.exists():
            self.token_path.unlink()
        self.env["GH_ACCESS_TOKEN"] = self.tokens[user_key]
        result = _run_cli(self.env, "login")
        _ensure_success(result)
        return json.loads(self.token_path.read_text())

    def logout(self) -> None:
        result = _run_cli(self.env, "logout")
        if result.returncode != 0 and "No session found" not in result.stdout:
            _ensure_success(result)
        if self.token_path.exists():
            self.token_path.unlink()


@pytest.fixture(scope="session")
def cli_context(tmp_path_factory):
    load_dotenv()
    token1 = os.environ.get("GH_ACCESS_TOKEN_1")
    token2 = os.environ.get("GH_ACCESS_TOKEN_2")
    if not token1 or not token2:
        pytest.skip(
            "GH_ACCESS_TOKEN_1 and GH_ACCESS_TOKEN_2 must be set (optionally via .env) to exercise the CLI binary."
        )

    home_dir = tmp_path_factory.mktemp("cli-home")
    env = os.environ.copy()
    env["HOME"] = str(home_dir)

    context = CLIContext(env=env, home=Path(home_dir), tokens={"user1": token1, "user2": token2})

    # Validate backend availability using user1 credentials
    context.login("user1")
    ping_result = _run_cli(context.env, "ping")
    if ping_result.returncode != 0:
        pytest.skip(
            "CLI backend is not reachable. Ensure the backend service is running before executing these tests."
        )
    context.logout()

    return context


@pytest.fixture
def ensure_user1(cli_context: CLIContext):
    cli_context.logout()
    user_info = cli_context.login("user1")
    yield cli_context, user_info
    cli_context.logout()


@pytest.fixture
def ensure_user2(cli_context: CLIContext):
    cli_context.logout()
    user_info = cli_context.login("user2")
    yield cli_context, user_info
    cli_context.logout()


def test_login_creates_token(cli_context: CLIContext):
    cli_context.logout()
    if cli_context.token_path.exists():
        cli_context.token_path.unlink()

    user_info = cli_context.login("user1")

    assert cli_context.token_path.exists()
    assert user_info.get("access_token"), "Token file missing access_token"
    assert user_info.get("github_id"), "Token file missing github_id"


def test_authentication_flow(cli_context: CLIContext):
    cli_context.logout()
    if cli_context.token_path.exists():
        cli_context.token_path.unlink()

    user_info = cli_context.login("user1")
    assert user_info.get("github_id"), "Login did not return github_id"

    list_result = _run_cli(cli_context.env, "list")
    _ensure_success(list_result)

    cli_context.logout()
    assert not cli_context.token_path.exists()


def test_ping(ensure_user1):
    context, _ = ensure_user1

    result = _run_cli(context.env, "ping")
    _ensure_success(result)
    assert "API healthy" in result.stdout


def test_create_list_delete_secret(ensure_user1):
    context, _ = ensure_user1
    secret_key = f"pytest-secret-{uuid4().hex[:8]}"
    secret_value = "temporary-value"

    try:
        create_result = _run_cli(context.env, "create", secret_key, secret_value)
        _ensure_success(create_result)
        assert f"Stored secret `{secret_key}`." in create_result.stdout

        list_result = _run_cli(context.env, "list")
        _ensure_success(list_result)
        assert secret_key in list_result.stdout
        assert secret_value in list_result.stdout
    finally:
        delete_result = _run_cli(context.env, "delete", secret_key)
        if delete_result.returncode == 0:
            assert f"Deleted secret `{secret_key}`." in delete_result.stdout
        else:
            pytest.fail(
                "Cleanup failed: unable to delete secret.\n"
                f"STDOUT:\n{delete_result.stdout}\nSTDERR:\n{delete_result.stderr}"
            )


def test_share_secret(ensure_user1, ensure_user2):
    context_user1, user1_info = ensure_user1
    context_user2, user2_info = ensure_user2

    assert context_user1 is context_user2, "Fixtures should share the same CLI context"

    # Switch back to user1 after obtaining user2 info
    context_user1.logout()
    context_user1.login("user1")

    share_target = user2_info["github_id"]
    secret_key = f"pytest-share-{uuid4().hex[:8]}"
    secret_value = "share-value"

    try:
        create_result = _run_cli(context_user1.env, "create", secret_key, secret_value)
        _ensure_success(create_result)

        share_result = _run_cli(context_user1.env, "share", secret_key, share_target)
        _ensure_success(share_result)
        assert f"Granted access to `{secret_key}`" in share_result.stdout
        assert share_target in share_result.stdout
    finally:
        delete_result = _run_cli(context_user1.env, "delete", secret_key)
        if delete_result.returncode != 0:
            pytest.fail(
                "Cleanup failed: unable to delete shared secret.\n"
                f"STDOUT:\n{delete_result.stdout}\nSTDERR:\n{delete_result.stderr}"
            )


def test_rbac_enforcement(cli_context: CLIContext):
    cli_context.logout()
    user1_info = cli_context.login("user1")
    user1_id = user1_info["github_id"]
    cli_context.logout()

    user2_info = cli_context.login("user2")
    user2_id = user2_info["github_id"]
    cli_context.logout()

    secret_key = f"pytest-rbac-{uuid4().hex[:8]}"
    secret_value = "rbac-secret"

    try:
        # user1 creates the secret
        cli_context.login("user1")
        create_result = _run_cli(cli_context.env, "create", secret_key, secret_value)
        _ensure_success(create_result)
        cli_context.logout()

        # user2 cannot see the secret before it is shared
        cli_context.login("user2")
        list_pre_share = _run_cli(cli_context.env, "list")
        _ensure_success(list_pre_share)
        assert secret_key not in list_pre_share.stdout
        cli_context.logout()

        # user1 shares read access with user2
        cli_context.login("user1")
        share_result = _run_cli(
            cli_context.env,
            "share",
            secret_key,
            user2_id,
        )
        _ensure_success(share_result)
        assert f"Granted access to `{secret_key}`" in share_result.stdout
        assert user2_id in share_result.stdout
        cli_context.logout()

        # user2 can now read but not write
        cli_context.login("user2")
        list_post_share = _run_cli(cli_context.env, "list")
        _ensure_success(list_post_share)
        assert secret_key in list_post_share.stdout

        write_attempt = _run_cli(cli_context.env, "create", secret_key, "updated-value")
        assert write_attempt.returncode != 0
        assert "403" in write_attempt.stderr or "Forbidden" in write_attempt.stderr or "permission" in write_attempt.stderr.lower()
        cli_context.logout()

    finally:
        cli_context.login("user1")
        delete_result = _run_cli(cli_context.env, "delete", secret_key)
        if delete_result.returncode != 0:
            pytest.fail(
                "Cleanup failed: unable to delete RBAC test secret.\n"
                f"STDOUT:\n{delete_result.stdout}\nSTDERR:\n{delete_result.stderr}"
            )
        cli_context.logout()


def test_logout_removes_token(ensure_user1):
    context, user_info = ensure_user1
    assert user_info.get("github_id")

    logout_result = _run_cli(context.env, "logout")
    _ensure_success(logout_result)
    assert "Logging out" in logout_result.stdout or "No session found" in logout_result.stdout
    assert not context.token_path.exists()
