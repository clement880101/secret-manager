import os
import time
import secrets
import urllib.parse
from typing import Any, Dict, Literal, Tuple


import httpx
from fastapi import HTTPException

from database import session_scope
from .models import User


STATE_TTL_SECONDS = 300
SESSION_TTL_SECONDS = 600
OAUTH_STATE_STORE: Dict[str, Dict[str, Any]] = {} # State token store for preventing CSRF attacks
SESSION_STORE: Dict[str, Dict[str, Any]] = {} # Session store for storing login sessions

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize" # GitHub OAuth authorize URL
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token" # GitHub OAuth token URL
GITHUB_USER_API = "https://api.github.com/user" # GitHub user API


def _get_github_config() -> Dict[str, str]:
    """Return GitHub OAuth client configuration loaded from environment.

    Inputs:
        None (reads environment variables).
    Outputs:
        Dict[str, str]: OAuth settings with `client_id`, `client_secret`, and `redirect_uri`.
    """
    client_id = os.getenv("OAUTH_ID_GITHUB")
    client_secret = os.getenv("OAUTH_SECRET_GITHUB")
    backend_url = os.getenv("BACKEND_URL")
    if not client_id or not client_secret or not backend_url:
        raise HTTPException(500, "GitHub OAuth configuration is incomplete")
    redirect_uri = urllib.parse.urljoin(backend_url.rstrip("/") + "/", "auth/callback")
    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
    }


def _cleanup_states(now: float) -> None:
    """Remove expired state entries from the in-memory OAuth state store.

    Inputs:
        now (float): Current timestamp used to compare with stored state timestamps.
    Outputs:
        None: Mutates `OAUTH_STATE_STORE` in place.
    """
    expired = [
        state
        for state, metadata in OAUTH_STATE_STORE.items()
        if now - metadata.get("created_at", 0) > STATE_TTL_SECONDS
    ]
    for state in expired:
        OAUTH_STATE_STORE.pop(state, None)


def _cleanup_sessions(now: float) -> None:
    """Remove expired login sessions from the in-memory session store."""
    expired = [
        session_id
        for session_id, metadata in SESSION_STORE.items()
        if now - metadata.get("created_at", 0) > SESSION_TTL_SECONDS
    ]
    for session_id in expired:
        SESSION_STORE.pop(session_id, None)


def initiate_login(scope: str = "read:user user:email") -> Dict[str, str]:
    """Create a short-lived login session and corresponding GitHub authorize URL."""
    config = _get_github_config()
    state = secrets.token_urlsafe(32)
    session_id = secrets.token_urlsafe(16)
    now = time.time()
    _cleanup_states(now)
    _cleanup_sessions(now)
    SESSION_STORE[session_id] = {
        "created_at": now,
        "status": "pending",
        "scope": scope,
        "state": state,
        "token": None,
        "error_message": None,
    }
    OAUTH_STATE_STORE[state] = {"created_at": now, "session_id": session_id}
    params = {
        "client_id": config["client_id"],
        "redirect_uri": config["redirect_uri"],
        "scope": scope,
        "state": state,
        "allow_signup": "false",
    }
    authorization_url = f"{GITHUB_AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"
    return {"session_id": session_id, "auth_url": authorization_url}


def _validate_state(state: str) -> str:
    """Ensure the provided OAuth state exists and return its associated session id."""
    now = time.time()
    metadata = OAUTH_STATE_STORE.pop(state, None)
    if metadata is None or now - metadata.get("created_at", 0) > STATE_TTL_SECONDS:
        raise HTTPException(400, "Invalid or expired OAuth state")
    session_id = metadata.get("session_id")
    if session_id is None or session_id not in SESSION_STORE:
        raise HTTPException(400, "Login session not found or expired")
    _cleanup_states(now)
    _cleanup_sessions(now)
    return session_id


def _set_session_error(session_id: str, message: str) -> None:
    session = SESSION_STORE.get(session_id)
    if session is None:
        return
    session["status"] = "error"
    session["error_message"] = message
    session["completed_at"] = time.time()


def exchange_code_for_token(code: str, state: str) -> Tuple[str, Dict[str, Any]]:
    """Trade a GitHub OAuth code for an access token after validating state.

    Inputs:
        code (str): Authorization code received from GitHub.
        state (str): State token to prevent CSRF.
    Outputs:
        Tuple[str, Dict[str, Any]]: The session id and GitHub response payload containing the access token.
    """
    session_id = _validate_state(state)
    session = SESSION_STORE.get(session_id)
    if session is None:
        raise HTTPException(400, "Login session not found or expired")
    config = _get_github_config()
    data = {
        "client_id": config["client_id"],
        "client_secret": config["client_secret"],
        "code": code,
        "redirect_uri": config["redirect_uri"],
    }
    headers = {"Accept": "application/json"}
    try:
        response = httpx.post(GITHUB_TOKEN_URL, data=data, headers=headers, timeout=10.0)
    except httpx.HTTPError as exc:
        _set_session_error(session_id, "Failed to reach GitHub for token exchange")
        raise HTTPException(502, "Failed to reach GitHub for token exchange") from exc
    if response.status_code != 200:
        detail = (
            response.json().get("error_description")
            if response.headers.get("content-type", "").startswith("application/json")
            else response.text
        )
        _set_session_error(session_id, detail or "GitHub declined the authorization request")
        raise HTTPException(400, detail or "GitHub declined the authorization request")
    payload = response.json()
    access_token = payload.get("access_token")
    if not access_token:
        message = payload.get("error_description") or "Missing access token in GitHub response"
        _set_session_error(session_id, message)
        raise HTTPException(400, message)
    return session_id, payload


def fetch_github_user(access_token: str, token_kind: Literal["oauth", "pat"] = "oauth") -> Dict[str, Any]:
    """Retrieve GitHub user profile using a provided access token.

    Inputs:
        access_token (str): GitHub access token issued after login.
        token_kind (Literal["oauth", "pat"]): Indicates whether the token is an OAuth access
            token (default) or a personal access token. GitHub classic PATs expect the `token`
            auth scheme, whereas OAuth tokens use the `Bearer` scheme.
    Outputs:
        Dict[str, Any]: Parsed JSON payload representing the GitHub user.
    """
    schemes: tuple[str, ...]
    if token_kind == "pat":
        schemes = ("token", "Bearer")
    else:
        schemes = ("Bearer",)
    last_response: httpx.Response | None = None
    for scheme in schemes:
        headers = {
            "Authorization": f"{scheme} {access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        try:
            response = httpx.get(GITHUB_USER_API, headers=headers, timeout=10.0)
        except httpx.HTTPError as exc:
            raise HTTPException(502, "Failed to reach GitHub to validate token") from exc
        if response.status_code == 200:
            return response.json()
        last_response = response
        if response.status_code == 401:
            continue
        break
    if last_response is not None and last_response.status_code == 401:
        raise HTTPException(401, "Invalid GitHub access token")
    raise HTTPException(502, "Unexpected response from GitHub when validating token")


def verify_access_token(access_token: str, token_kind: Literal["oauth", "pat"] = "oauth") -> Dict[str, Any]:
    """Validate an access token and return normalized user details.

    Inputs:
        access_token (str): GitHub OAuth access token to verify.
    Outputs:
        Dict[str, Any]: Minimal user information dict with `id`, `login`, `name`, and `avatar_url`.
    """
    user = fetch_github_user(access_token, token_kind=token_kind)
    if "id" not in user:
        raise HTTPException(502, "GitHub user payload missing 'id'")
    return {
        "id": str(user["id"]),
        "login": user.get("login"),
        "name": user.get("name"),
        "avatar_url": user.get("avatar_url"),
    }


def parse_token(auth_header: str | None) -> str:
    """Extract and validate bearer token from Authorization header.

    Inputs:
        auth_header (str | None): Raw Authorization header string.
    Outputs:
        str: GitHub user id associated with the verified token.
    """
    if not auth_header or not auth_header.lower().startswith("bearer "):
        raise HTTPException(401, "Missing bearer token")
    token = auth_header.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(401, "Missing bearer token")
    user = verify_access_token(token, token_kind="oauth")
    get_or_create_user(user["id"])
    return user["id"]


def login_with_personal_token(token: str) -> Dict[str, Any]:
    """Validate a personal access token and return session details.

    Inputs:
        token (str): GitHub personal access token provided by the client.
    Outputs:
        Dict[str, Any]: Minimal session payload containing token and user info.
    """
    if not token:
        raise HTTPException(400, "GitHub personal access token required")
    user = verify_access_token(token, token_kind="pat")
    get_or_create_user(user["id"])
    return {
        "access_token": token,
        "token_type": "bearer",
        "scope": "",
        "user": user,
    }


def complete_session(session_id: str, token_payload: Dict[str, Any], user: Dict[str, Any]) -> None:
    session = SESSION_STORE.get(session_id)
    if session is None:
        raise HTTPException(404, "Login session not found or expired")
    get_or_create_user(user["id"])
    session["status"] = "ready"
    session["completed_at"] = time.time()
    session["token"] = {
        "access_token": token_payload["access_token"],
        "token_type": token_payload.get("token_type", "bearer"),
        "scope": token_payload.get("scope", ""),
        "user": user,
    }


def get_session_status(session_id: str) -> Dict[str, Any]:
    now = time.time()
    _cleanup_sessions(now)
    session = SESSION_STORE.get(session_id)
    if session is None:
        raise HTTPException(404, "Login session not found or expired")
    status = session.get("status", "pending")
    if status == "ready":
        token = session.get("token")
        SESSION_STORE.pop(session_id, None)
        return {"status": "ready", "token": token}
    if status == "error":
        message = session.get("error_message") or "Login failed"
        SESSION_STORE.pop(session_id, None)
        return {"status": "error", "message": message}
    return {"status": "pending"}


def fail_session(session_id: str, message: str) -> None:
    _set_session_error(session_id, message)


def get_or_create_user(ext_user_id: str) -> User:
    with session_scope() as session:
        user = session.query(User).filter_by(github_id=ext_user_id).first()
        if user:
            return user
        user = User(github_id=ext_user_id)
        session.add(user)
        session.flush()
        return user

