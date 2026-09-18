import hashlib
import os
import time
import secrets
import urllib.parse
from typing import Any, Dict, Literal, Tuple


import httpx
from fastapi import HTTPException

import crypto
import settings
from database import session_scope
from .models import LoginSession, User


STATE_TTL_SECONDS = 300
SESSION_TTL_SECONDS = 600
# Login state lives in the database, not in this process: see LoginSession.

# Verified tokens, keyed by digest rather than by the token itself so the raw
# credential is not held in memory any longer than the request needs it.
TOKEN_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}

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


def _purge_expired(now: float) -> None:
    """Drop login sessions past their lifetime, in a transaction of its own.

    It has to commit independently: session_scope rolls back on exception, so
    purging inside a block that then raises 404 for a missing session would
    undo the cleanup every time it mattered. Running it on the paths that
    already touch this table avoids needing a scheduled job on whatever
    platform this is deployed to.
    """
    with session_scope() as db:
        db.query(LoginSession).filter(
            LoginSession.created_at < now - SESSION_TTL_SECONDS
        ).delete(synchronize_session=False)


def initiate_login(scope: str = "read:user user:email") -> Dict[str, str]:
    """Create a short-lived login session and corresponding GitHub authorize URL."""
    config = _get_github_config()
    state = secrets.token_urlsafe(32)
    session_id = secrets.token_urlsafe(16)
    now = time.time()

    _purge_expired(now)
    with session_scope() as db:
        db.add(
            LoginSession(
                session_id=session_id,
                state=state,
                status="pending",
                scope=scope,
                created_at=now,
            )
        )

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
    """Redeem an OAuth state and return the login session it belongs to.

    The state is cleared as part of redeeming it, so a replayed callback is
    rejected even if it arrives within the TTL.
    """
    now = time.time()
    _purge_expired(now)
    with session_scope() as db:
        record = db.query(LoginSession).filter_by(state=state).first()
        if record is None or now - record.created_at > STATE_TTL_SECONDS:
            raise HTTPException(400, "Invalid or expired OAuth state")
        session_id = record.session_id
        record.state = None
        return session_id


def _set_session_error(session_id: str, message: str) -> None:
    with session_scope() as db:
        record = db.get(LoginSession, session_id)
        if record is None:
            return
        record.status = "error"
        record.error_message = message
        record.completed_at = time.time()


def exchange_code_for_token(code: str, state: str) -> Tuple[str, Dict[str, Any]]:
    """Trade a GitHub OAuth code for an access token after validating state.

    Inputs:
        code (str): Authorization code received from GitHub.
        state (str): State token to prevent CSRF.
    Outputs:
        Tuple[str, Dict[str, Any]]: The session id and GitHub response payload containing the access token.
    """
    session_id = _validate_state(state)
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


def _token_cache_key(access_token: str, token_kind: str) -> str:
    """Digest a token for use as a cache key, so the raw value is not stored."""
    return hashlib.sha256(f"{token_kind}:{access_token}".encode("utf-8")).hexdigest()


def _prune_token_cache(now: float, ttl: int) -> None:
    """Drop expired entries so the cache cannot grow without bound."""
    expired = [key for key, (cached_at, _) in TOKEN_CACHE.items() if now - cached_at >= ttl]
    for key in expired:
        TOKEN_CACHE.pop(key, None)


def verify_access_token(access_token: str, token_kind: Literal["oauth", "pat"] = "oauth") -> Dict[str, Any]:
    """Validate an access token and return normalized user details.

    Results are cached for TOKEN_CACHE_TTL_SECONDS. Without a cache the API
    calls GitHub once per request, which exhausts the deployment's rate limit
    and lets a caller amplify traffic against it. The tradeoff is that a token
    revoked on GitHub stays accepted here until its entry expires, so deployments
    wanting immediate revocation set the TTL to 0.

    Inputs:
        access_token (str): GitHub OAuth access token to verify.
        token_kind (Literal["oauth", "pat"]): Auth scheme the token expects.
    Outputs:
        Dict[str, Any]: Minimal user information dict with `id`, `login`, `name`, and `avatar_url`.
    """
    ttl = settings.token_cache_ttl_seconds()
    key = _token_cache_key(access_token, token_kind)
    now = time.time()

    if ttl:
        cached = TOKEN_CACHE.get(key)
        if cached is not None and now - cached[0] < ttl:
            return cached[1]

    user = fetch_github_user(access_token, token_kind=token_kind)
    if "id" not in user:
        raise HTTPException(502, "GitHub user payload missing 'id'")
    details = {
        "id": str(user["id"]),
        "login": user.get("login"),
        "name": user.get("name"),
        "avatar_url": user.get("avatar_url"),
    }

    if ttl:
        _prune_token_cache(now, ttl)
        TOKEN_CACHE[key] = (now, details)
    return details


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
    """Mark a login finished and stash the issued token for the CLI to collect."""
    get_or_create_user(user["id"])
    with session_scope() as db:
        record = db.get(LoginSession, session_id)
        if record is None:
            raise HTTPException(404, "Login session not found or expired")
        record.status = "ready"
        record.user_id = user["id"]
        record.completed_at = time.time()
        # A live GitHub token at rest gets the same protection as a secret.
        record.access_token = crypto.encrypt_value(token_payload["access_token"])
        record.token_type = token_payload.get("token_type", "bearer")
        record.token_scope = token_payload.get("scope", "")


def get_session_status(session_id: str) -> Dict[str, Any]:
    """Report on a login, handing over the token exactly once.

    The row is deleted as it is read, so a polled token cannot be collected
    twice and does not linger in the database after the CLI has it.
    """
    now = time.time()
    _purge_expired(now)
    with session_scope() as db:
        record = db.get(LoginSession, session_id)
        if record is None:
            raise HTTPException(404, "Login session not found or expired")

        if record.status == "ready":
            stored = record.access_token
            user_id = record.user_id
            db.delete(record)
            if not stored:
                raise HTTPException(500, "Login session missing access token")
            response = {"status": "ready", "token": crypto.decrypt_value(stored)}
            if user_id is not None:
                response["user_id"] = user_id
            return response

        if record.status == "error":
            message = record.error_message or "Login failed"
            db.delete(record)
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

