import json
import os
import time
import webbrowser
from pathlib import Path
from typing import Dict, Optional

import typer
import httpx

app = typer.Typer(add_completion=False)

API_URL = os.environ.get("BACKEND_URL", "http://localhost:8000").rstrip("/")
DEFAULT_SCOPE = "read:user user:email"
SESSION_TTL_SECONDS = 600
POLL_INTERVAL_SECONDS = 3.0
TOKEN_FILE = Path.home() / ".token"
HTTP_TIMEOUT = float(os.environ.get("SECRETS_HTTP_TIMEOUT", "10.0"))


def _write_token(token: str, github_id: str) -> None:
    payload = {"access_token": token, "github_id": github_id, "created_at": int(time.time())}
    TOKEN_FILE.write_text(json.dumps(payload, indent=2))


def _load_token() -> Optional[Dict[str, str]]:
    if not TOKEN_FILE.exists():
        return None
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


def _poll_login(session_id: str, scope: str) -> Dict[str, str]:
    deadline = time.time() + SESSION_TTL_SECONDS
    typer.echo("Waiting for authentication...")
    pending_notice_shown = False
    while time.time() < deadline:
        time.sleep(POLL_INTERVAL_SECONDS)
        response = httpx.get(
            f"{API_URL}/auth/login/{session_id}",
            params={"scope": scope},
            timeout=HTTP_TIMEOUT,
        )
        if response.status_code == 200:
            data = response.json()
            token = data.get("access_token") or data.get("token")
            github_id = data.get("github_id") or data.get("user_id")
            if not token or not github_id:
                if not pending_notice_shown:
                    typer.echo("Authorization pending. Please finish the login in your browser...")
                    pending_notice_shown = True
                continue
            _write_token(token, github_id)
            typer.echo(f"Logged in as {github_id}")
            return data
        if response.status_code in (401, 403, 404, 410):
            typer.echo("Login session is no longer valid. Please run login again.")
            raise typer.Exit(1)
    typer.echo("Login timed out. Please start a new login session.")
    raise typer.Exit(1)


def _start_login(scope: str) -> Dict[str, str]:
    typer.echo(f"Starting login (scope: {scope})")
    response = httpx.post(
        f"{API_URL}/auth/login",
        params={"scope": scope},
        timeout=HTTP_TIMEOUT,
    )
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
    response = httpx.post(
        f"{API_URL}/auth/login-test",
        json={"token": access_token},
        timeout=HTTP_TIMEOUT,
    )
    response.raise_for_status()
    data = response.json()

    token = data.get("access_token") or data.get("token")
    github_id = data.get("github_id") or data.get("user_id")
    if not token or not github_id:
        typer.echo("Login test response missing required fields.")
        raise typer.Exit(1)

    _write_token(token, github_id)
    typer.echo(f"Logged in as {github_id}")
    return data


def _ensure_token(scope: str = DEFAULT_SCOPE) -> Dict[str, str]:
    token_data = _load_token()
    if token_data:
        return token_data
    gh_access_token = os.environ.get("GH_ACCESS_TOKEN")
    if gh_access_token:
        return _login_with_access_token(gh_access_token)
    typer.echo("You are not logged in. Starting login flow...")
    return _start_login(scope)


def _request_with_auth(method: str, path: str, scope: str = DEFAULT_SCOPE, **kwargs) -> httpx.Response:
    token_data = _ensure_token(scope)
    headers = kwargs.pop("headers", {})
    headers.update(_auth_headers(token_data["access_token"]))
    kwargs["headers"] = headers

    url = f"{API_URL}{path}"
    kwargs.setdefault("timeout", HTTP_TIMEOUT)
    response = httpx.request(method, url, **kwargs)
    if response.status_code == 401:
        typer.echo("Session expired or invalid. Re-authenticating...")
        if TOKEN_FILE.exists():
            TOKEN_FILE.unlink()
        token_data = _start_login(scope)
        headers.update(_auth_headers(token_data["access_token"]))
        kwargs["headers"] = headers
        response = httpx.request(method, url, **kwargs)
    return response


@app.command()
def login(scope: str = typer.Option(DEFAULT_SCOPE, help="GitHub OAuth scopes to request")):
    """
    Initiate the login flow and store the resulting access token.
    """
    if TOKEN_FILE.exists():
        typer.echo("Existing session detected; starting fresh login.")
        TOKEN_FILE.unlink()
    gh_access_token = os.environ.get("GH_ACCESS_TOKEN")
    if gh_access_token:
        _login_with_access_token(gh_access_token)
        return
    _start_login(scope)


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
    can_write: bool = typer.Option(True, help="Allow the user to update the shared secret."),
):
    """
    Share a secret with another GitHub user.
    """
    response = _request_with_auth(
        "POST",
        f"/secrets/{key}/share",
        json={"github_id": github_id, "can_write": can_write},
    )
    if response.status_code == 200:
        access = "write" if can_write else "read"
        typer.echo(f"Granted {access} access to `{key}` for {github_id}.")
        return
    if response.status_code == 404:
        typer.echo(f"Secret `{key}` not found.")
        return
    response.raise_for_status()


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
