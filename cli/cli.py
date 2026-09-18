import json
import os
import stat
import time
import urllib.parse
import webbrowser
from pathlib import Path
from typing import Dict, Optional, Tuple

import httpx
import typer
from dotenv import load_dotenv

DOTENV_PATH = Path(".env")
if DOTENV_PATH.exists():
    load_dotenv(DOTENV_PATH)

app = typer.Typer(add_completion=False)

DEFAULT_BACKEND_URL = "http://secretmgr-nlb-750c1ac03b1b7c1f.elb.us-west-1.amazonaws.com:8000"
# An env var that is set but empty must fall back to the default rather than
# producing a hostless URL. CI passes BACKEND_URL from a repository variable,
# which expands to "" on a fork that has not defined one.
API_URL = (os.environ.get("BACKEND_URL") or "").strip().rstrip("/") or DEFAULT_BACKEND_URL
DEFAULT_SCOPE = "read:user user:email"
SESSION_TTL_SECONDS = 600
POLL_INTERVAL_SECONDS = 3.0
_TOKEN_FILE_ENV = os.environ.get("SECRET_MANAGER_TOKEN_FILE")
if _TOKEN_FILE_ENV:
    TOKEN_FILE = Path(_TOKEN_FILE_ENV).expanduser()
else:
    TOKEN_FILE = Path.home() / ".token"
HTTP_TIMEOUT = float(os.environ.get("SECRETS_HTTP_TIMEOUT", "10.0"))
VERSION = "0.4.0"
TOKEN_FILE_MODE = 0o600

# Talking to a remote backend over plain HTTP puts the access token and every
# secret value on the wire in the clear. Loopback is exempt: it never leaves
# the machine, and it is how the backend is developed locally.
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}


def _is_cleartext_remote(url: str) -> bool:
    """True when `url` would send credentials unencrypted to another host."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "http":
        return False
    return (parsed.hostname or "") not in LOCAL_HOSTS


def _warn_if_insecure() -> None:
    """Print a one-line warning when the configured backend is cleartext HTTP."""
    if not _is_cleartext_remote(API_URL):
        return
    if os.environ.get("SECRETS_ALLOW_INSECURE", "").strip().lower() in {"1", "true", "yes", "on"}:
        return
    typer.echo(
        f"Warning: {API_URL} is plain HTTP. Your access token and secret values "
        "will cross the network unencrypted. Set BACKEND_URL to an https:// "
        "endpoint, or set SECRETS_ALLOW_INSECURE=1 to silence this.",
        err=True,
    )


def _secure_token_file() -> None:
    """Restrict the token file to the current user (best effort)."""
    try:
        TOKEN_FILE.chmod(TOKEN_FILE_MODE)
    except OSError:
        pass


def _write_token(token: str, github_id: str) -> None:
    """Persist the access token readable only by the current user.

    The file holds a live GitHub credential, so it is created with mode 0600
    rather than whatever the process umask would give it. os.open with O_CREAT
    sets the mode at creation time, closing the window in which a fresh file
    would briefly be world-readable.
    """
    payload = {"access_token": token, "github_id": github_id, "created_at": int(time.time())}
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, TOKEN_FILE_MODE)
    with os.fdopen(fd, "w") as handle:
        handle.write(json.dumps(payload, indent=2))
    # An existing file keeps its old mode through O_CREAT, so tighten it too.
    _secure_token_file()


def _load_token() -> Optional[Dict[str, str]]:
    if not TOKEN_FILE.exists():
        return None
    # Tokens written by an older build were left world-readable; repair on read.
    if stat.S_IMODE(TOKEN_FILE.stat().st_mode) != TOKEN_FILE_MODE:
        _secure_token_file()
    try:
        data = json.loads(TOKEN_FILE.read_text())
    except json.JSONDecodeError:
        return None
    if "access_token" not in data or "github_id" not in data:
        return None
    return data


def _auth_headers(token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _resolve_login_url(payload: Dict[str, str]) -> Optional[str]:
    for key in ("verification_url", "verification_uri", "login_url", "auth_url", "url"):
        if key in payload and payload[key]:
            return payload[key]
    return None


def _parse_login_payload(payload: Dict[str, str]) -> Optional[Tuple[str, str]]:
    token = payload.get("access_token") or payload.get("token")
    github_id = payload.get("github_id") or payload.get("user_id")
    if token and github_id:
        return token, github_id

    nested = payload.get("data")
    if isinstance(nested, dict):
        return _parse_login_payload(nested)

    return None


def _poll_login(session_id: str, scope: str) -> Dict[str, str]:
    deadline = time.time() + SESSION_TTL_SECONDS
    typer.echo("Waiting for authentication...")
    pending_notice_shown = False
    while time.time() < deadline:
        time.sleep(POLL_INTERVAL_SECONDS)
        try:
            response = httpx.get(
                f"{API_URL}/auth/login/{session_id}",
                params={"scope": scope},
                timeout=HTTP_TIMEOUT,
            )
        except httpx.RequestError as exc:
            typer.echo(f"Unable to reach API at {API_URL}: {exc}")
            raise typer.Exit(1)
        if response.status_code == 200:
            data = response.json()
            auth_info = _parse_login_payload(data)
            if not auth_info:
                if not pending_notice_shown:
                    typer.echo("Authorization pending. Please finish the login in your browser...")
                    pending_notice_shown = True
                continue
            token, github_id = auth_info
            _write_token(token, github_id)
            typer.echo(f"Logged in as {github_id}")
            return {"access_token": token, "github_id": github_id}
        if response.status_code in (401, 403, 404, 410):
            typer.echo("Login session is no longer valid. Please run login again.")
            raise typer.Exit(1)
    typer.echo("Login timed out. Please start a new login session.")
    raise typer.Exit(1)


def _start_login(scope: str) -> Dict[str, str]:
    typer.echo(f"Starting login")
    try:
        response = httpx.post(
            f"{API_URL}/auth/login",
            params={"scope": scope},
            timeout=HTTP_TIMEOUT,
        )
    except httpx.RequestError as exc:
        typer.echo(f"Unable to reach API at {API_URL}: {exc}")
        typer.echo("Ensure the backend is running or set BACKEND_URL to a reachable server.")
        raise typer.Exit(1)
    response.raise_for_status()
    payload = response.json()
    session_id = payload.get("session_id")
    if not session_id:
        typer.echo("Login response missing session_id.")
        raise typer.Exit(1)

    login_url = _resolve_login_url(payload)
    if login_url:
        typer.echo(f"Open the following link in a browser to continue:\n{login_url}")
        try:
            webbrowser.open(login_url)
        except webbrowser.Error:
            typer.echo("Unable to open browser automatically. Please open the link manually.")
    return _poll_login(session_id, scope)


def _login_with_access_token(access_token: str) -> Dict[str, str]:
    access_token = access_token.strip()
    if not access_token:
        typer.echo("GH_ACCESS_TOKEN is set but empty.")
        raise typer.Exit(1)

    typer.echo("Logging in with GH_ACCESS_TOKEN...")
    try:
        response = httpx.post(
            f"{API_URL}/auth/login-test",
            json={"token": access_token},
            timeout=HTTP_TIMEOUT,
        )
    except httpx.RequestError as exc:
        typer.echo(f"Unable to reach API at {API_URL}: {exc}")
        typer.echo("Ensure the backend is running or set BACKEND_URL to a reachable server.")
        raise typer.Exit(1)
    response.raise_for_status()
    data = response.json()
    auth_info = _parse_login_payload(data)
    if not auth_info:
        typer.echo("Login test response missing required fields.")
        raise typer.Exit(1)
    token, github_id = auth_info

    _write_token(token, github_id)
    typer.echo(f"Logged in as {github_id}")
    return {"access_token": token, "github_id": github_id}


def _ensure_token(scope: str = DEFAULT_SCOPE) -> Dict[str, str]:
    token_data = _load_token()
    if token_data:
        return token_data
    typer.echo("Not logged in. Run `cli login` to authenticate.")
    raise typer.Exit(1)


def _request_with_auth(method: str, path: str, scope: str = DEFAULT_SCOPE, **kwargs) -> httpx.Response:
    token_data = _ensure_token(scope)
    headers = kwargs.pop("headers", {})
    headers.update(_auth_headers(token_data["access_token"]))
    kwargs["headers"] = headers

    url = f"{API_URL}{path}"
    kwargs.setdefault("timeout", HTTP_TIMEOUT)
    response = httpx.request(method, url, **kwargs)
    if response.status_code == 401:
        typer.echo("Session expired or invalid. Run `cli login` to authenticate again.")
        if TOKEN_FILE.exists():
            TOKEN_FILE.unlink()
        raise typer.Exit(1)
    return response


@app.callback()
def main() -> None:
    """A lightweight, distributed secret manager.

    Store secrets, share them with other GitHub users, and read them back from
    any machine. Set BACKEND_URL to point at your own deployment.
    """
    _warn_if_insecure()


def _login_with_api_token(token: str) -> Dict[str, str]:
    """Store a token the server issued, after confirming who it identifies."""
    token = token.strip()
    if not token:
        typer.echo("Token is empty.")
        raise typer.Exit(1)
    try:
        response = httpx.get(
            f"{API_URL}/auth/whoami",
            headers=_auth_headers(token),
            timeout=HTTP_TIMEOUT,
        )
    except httpx.RequestError as exc:
        typer.echo(f"Unable to reach API at {API_URL}: {exc}")
        raise typer.Exit(1)
    if response.status_code == 401:
        typer.echo("That token was rejected. It may have been revoked.")
        raise typer.Exit(1)
    response.raise_for_status()
    user_id = response.json().get("user_id")
    if not user_id:
        typer.echo("Server did not say who this token belongs to.")
        raise typer.Exit(1)
    _write_token(token, user_id)
    typer.echo(f"Logged in as {user_id}")
    return {"access_token": token, "github_id": user_id}


def _post_credentials(path: str, username: str, password: str) -> Dict[str, str]:
    """Send a username and password, store whatever token comes back."""
    try:
        response = httpx.post(
            f"{API_URL}{path}",
            json={"username": username, "password": password},
            timeout=HTTP_TIMEOUT,
        )
    except httpx.RequestError as exc:
        typer.echo(f"Unable to reach API at {API_URL}: {exc}")
        raise typer.Exit(1)

    if response.status_code in (400, 401, 403):
        detail = ""
        try:
            detail = response.json().get("detail", "")
        except ValueError:
            pass
        typer.echo(detail or "Login failed.")
        raise typer.Exit(1)
    if response.status_code == 404:
        typer.echo(
            "This deployment does not manage its own accounts. "
            "Run `secretmgr login` to sign in through GitHub."
        )
        raise typer.Exit(1)
    response.raise_for_status()

    payload = response.json()
    _write_token(payload["token"], payload["user_id"])
    return payload


@app.command()
def register(
    username: str = typer.Argument(..., help="The name to register."),
    password: str = typer.Option(
        None, "--password", help="Skip the prompt. Avoid on shared machines: it lands in shell history."
    ),
):
    """
    Create an account on this deployment and log in.

    No GitHub account and no invitation required, where the deployment allows
    it.
    """
    if password is None:
        password = typer.prompt("Choose a password", hide_input=True, confirmation_prompt=True)
    payload = _post_credentials("/auth/register", username, password)
    typer.echo(f"Registered and logged in as {payload['user_id']}")


@app.command()
def login(
    username: str = typer.Argument(None, help="Your username on this deployment."),
    password: str = typer.Option(
        None, "--password", help="Skip the prompt. Avoid on shared machines: it lands in shell history."
    ),
    token: str = typer.Option(
        None, "--token", help="Log in with a token the server issued."
    ),
    scope: str = typer.Option(DEFAULT_SCOPE, help="GitHub OAuth scopes to request"),
):
    """
    Log in and store the resulting token.

    Give a username to sign in with a password, --token to use a token the
    server issued, or neither to go through GitHub where the deployment is
    configured for it.
    """
    if TOKEN_FILE.exists():
        typer.echo("Existing session detected; starting fresh login.")
        TOKEN_FILE.unlink()

    if token:
        _login_with_api_token(token)
        return

    if username:
        if password is None:
            password = typer.prompt("Password", hide_input=True)
        payload = _post_credentials("/auth/sessions", username, password)
        typer.echo(f"Logged in as {payload['user_id']}")
        return

    gh_access_token = os.environ.get("GH_ACCESS_TOKEN")
    if gh_access_token:
        _login_with_access_token(gh_access_token)
        return
    _start_login(scope)


@app.command("token")
def issue_token(
    user_id: str = typer.Argument(..., help="Who the new token is for."),
    label: str = typer.Option("", "--label", help="A note to identify it later."),
):
    """
    Issue a token for someone else, so they can use this deployment.
    """
    response = _request_with_auth(
        "POST", "/auth/tokens", json={"user_id": user_id, "label": label}
    )
    if response.status_code == 404:
        typer.echo("This deployment uses GitHub logins, so it does not issue tokens.")
        raise typer.Exit(1)
    response.raise_for_status()
    payload = response.json()
    typer.echo(f"Token for {payload['user_id']}:\n\n    {payload['token']}\n")
    typer.echo("It cannot be shown again. Share it over something private.")


@app.command()
def passwd(
    current: str = typer.Option(None, "--current", help="Skip the prompt."),
    new: str = typer.Option(None, "--new", help="Skip the prompt."),
):
    """
    Change your password.
    """
    if current is None:
        current = typer.prompt("Current password", hide_input=True)
    if new is None:
        new = typer.prompt("New password", hide_input=True, confirmation_prompt=True)
    response = _request_with_auth(
        "POST", "/auth/password", json={"current_password": current, "new_password": new}
    )
    if response.status_code in (400, 401, 429):
        detail = ""
        try:
            detail = response.json().get("detail", "")
        except ValueError:
            pass
        typer.echo(detail or "Could not change password.")
        raise typer.Exit(1)
    response.raise_for_status()
    typer.echo("Password changed. Existing tokens still work; revoke any you no longer trust.")


@app.command()
def revoke(token: str = typer.Argument(..., help="The token to revoke.")):
    """
    Revoke a token, for instance after losing a machine.
    """
    response = _request_with_auth("DELETE", "/auth/tokens", json={"token": token})
    response.raise_for_status()
    if response.json().get("revoked"):
        typer.echo("Token revoked.")
    else:
        typer.echo("No such token; nothing to revoke.")


@app.command()
def whoami():
    """
    Show who the stored token identifies, and how this deployment authenticates.
    """
    response = _request_with_auth("GET", "/auth/whoami")
    response.raise_for_status()
    payload = response.json()
    typer.echo(f"{payload['user_id']} (auth: {payload.get('auth_mode', 'unknown')})")


@app.command()
def logout():
    """
    Remove any stored access token.
    """
    token_data = _load_token()
    if not token_data:
        typer.echo("No session found.")
        return
    typer.echo(f"Logging out {token_data['github_id']}")
    TOKEN_FILE.unlink()


@app.command("create")
def create_secret(key: str, value: str):
    """
    Create or update a secret key/value pair.
    """
    response = _request_with_auth("POST", "/secrets", json={"key": key, "value": value})
    if response.status_code == 200:
        typer.echo(f"Stored secret `{key}`.")
        return
    if response.status_code == 409:
        typer.echo(f"Secret `{key}` already exists.")
        raise typer.Exit(1)
    response.raise_for_status()


@app.command("delete")
def delete_secret(key: str):
    """
    Delete a secret key/value pair you have access to.
    """
    response = _request_with_auth("DELETE", f"/secrets/{key}")
    if response.status_code == 200:
        typer.echo(f"Deleted secret `{key}`.")
        return
    if response.status_code == 404:
        typer.echo(f"Secret `{key}` not found.")
        return
    response.raise_for_status()


@app.command("list")
def list_secrets():
    """
    List secrets visible to the current user.
    """
    response = _request_with_auth("GET", "/secrets")
    response.raise_for_status()
    payload = response.json()
    if isinstance(payload, dict):
        items = payload.get("items") or payload.get("results") or payload.get("data")
        if items is None:
            items = []
    elif isinstance(payload, list):
        items = payload
    else:
        items = []

    if not items:
        typer.echo("No secrets found.")
        return

    for item in items:
        key = item.get("key", "<unknown>")
        value = item.get("value", "<hidden>")
        owner = item.get("owner_id") or item.get("owner") or "unknown"
        typer.echo(f"{key} = {value} (owner: {owner})")


@app.command("share")
def share_secret(
    key: str,
    github_id: str,
):
    """
    Share a secret with another GitHub user.
    """
    response = _request_with_auth(
        "POST",
        f"/secrets/{key}/share",
        json={"github_id": github_id},
    )
    if response.status_code == 200:
        typer.echo(f"Granted access to `{key}` for {github_id}.")
        return
    if response.status_code == 404:
        typer.echo(f"Secret `{key}` not found.")
        return
    response.raise_for_status()


@app.command()
def version():
    """Print the CLI version."""
    typer.echo(VERSION)


@app.command()
def ping():
    """
    Check backend health status.
    """
    try:
        response = httpx.get(f"{API_URL}/healthz", timeout=HTTP_TIMEOUT)
    except httpx.RequestError as exc:
        typer.echo(f"Unable to reach API: {exc}")
        raise typer.Exit(1)

    if response.status_code == 200:
        try:
            payload = response.json()
        except ValueError:
            payload = {}

        status = payload.get("ok")
        if status is True:
            typer.echo("API healthy.")
        elif status is False:
            typer.echo("API unhealthy response.")
            raise typer.Exit(1)
        else:
            typer.echo(f"API responded with unexpected payload: {payload}")
        return

    typer.echo(f"Unexpected response ({response.status_code}): {response.text}")
    raise typer.Exit(1)


if __name__ == "__main__":
    app()
