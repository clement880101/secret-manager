from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

import settings
from . import local, schemas, service

router = APIRouter(prefix="/auth", tags=["auth"])


class TokenRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=64)
    label: str = Field(default="", max_length=128)


class CredentialsRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=1024)


def _require_local_mode() -> None:
    if settings.auth_mode() != "local":
        raise HTTPException(404, "Not Found")


def _require_github_mode() -> None:
    if settings.auth_mode() != "github":
        raise HTTPException(404, "Not Found")


@router.post("/register")
def register(payload: CredentialsRequest):
    """Create an account on this deployment and return a token for it."""
    _require_local_mode()
    if not settings.registration_open():
        raise HTTPException(403, "Registration is closed on this deployment")
    try:
        token = local.register_user(payload.username, payload.password)
    except local.RegistrationError as exc:
        raise HTTPException(400, str(exc))
    return {"token": token, "user_id": payload.username.strip()}


@router.post("/sessions")
def create_session(payload: CredentialsRequest):
    """Exchange a username and password for a token."""
    _require_local_mode()
    token = local.authenticate(payload.username, payload.password)
    if token is None:
        # One message for both a missing account and a wrong password, so this
        # cannot be used to find out which usernames exist.
        raise HTTPException(401, "Incorrect username or password")
    return {"token": token, "user_id": payload.username.strip()}


@router.get("/whoami")
def whoami(request: Request):
    """Identify the caller. Works in either mode; used by the CLI after login."""
    user_id = service.parse_token(request.headers.get("Authorization"))
    return {"user_id": user_id, "auth_mode": settings.auth_mode()}


@router.post("/tokens")
def create_token(request: Request, payload: TokenRequest):
    """Issue a token for a user. Requires a token already, so it chains from the
    bootstrap token the server prints on first start."""
    _require_local_mode()
    service.parse_token(request.headers.get("Authorization"))
    token = local.issue_token(payload.user_id, label=payload.label)
    return {"token": token, "user_id": payload.user_id}


@router.get("/tokens")
def list_tokens(request: Request):
    """List the caller's tokens. Values are never shown again once issued."""
    _require_local_mode()
    user_id = service.parse_token(request.headers.get("Authorization"))
    return {"items": local.list_tokens(user_id)}


@router.post("/login")
def login(scope: str = Query(default="read:user user:email", description="GitHub OAuth scopes")):
    _require_github_mode()
    try:
        return service.initiate_login(scope=scope)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, "Failed to prepare GitHub login") from exc


@router.get("/login/{session_id}")
def poll_login(session_id: str):
    _require_github_mode()
    try:
        return service.get_session_status(session_id)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, "Failed to load login session") from exc


@router.get("/callback", response_class=HTMLResponse)
def callback(code: str, state: str):
    _require_github_mode()
    session_id = None
    try:
        session_id, token_payload = service.exchange_code_for_token(code, state)
        user = service.verify_access_token(token_payload["access_token"])
        service.get_or_create_user(user["id"])
        service.complete_session(session_id, token_payload, user)
    except HTTPException as exc:
        if session_id:
            service.fail_session(session_id, str(exc.detail) if hasattr(exc, "detail") else "Login failed")
        raise
    except Exception as exc:
        if session_id:
            service.fail_session(session_id, "Unexpected error during login")
        raise HTTPException(500, "Failed to finalize GitHub login") from exc
    return HTMLResponse(
        content="<html><body><h1>Authentication Complete</h1><p>You can close this window and return to the CLI.</p></body></html>"
    )


@router.post("/login-test")
def login_test(payload: schemas.LoginTestRequest):
    _require_github_mode()
    if not settings.test_login_enabled():
        raise HTTPException(404, "Not Found")
    try:
        token = service.login_with_personal_token(payload.token)
        return {"status": "ready", "token": token["access_token"], "user_id": token["user"]["id"]}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, "Failed to verify GitHub token") from exc

