from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

import settings
from . import local, ratelimit, service

router = APIRouter(prefix="/auth", tags=["auth"])


class TokenRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=64)
    label: str = Field(default="", max_length=128)


class CredentialsRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=1024)


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=1024)
    new_password: str = Field(..., min_length=1, max_length=1024)


class RevokeRequest(BaseModel):
    token: str = Field(..., min_length=1, max_length=256)


def _client_address(request: Request) -> str:
    """Best guess at who is calling, trusting the proxy header when present."""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _guard(request: Request, username: str) -> None:
    """Refuse an attempt that has already failed too often."""
    blocked = ratelimit.blocked_key(username, _client_address(request))
    if blocked is not None:
        raise HTTPException(
            429,
            "Too many failed attempts. Wait a few minutes and try again.",
            headers={"Retry-After": str(settings.auth_rate_window_seconds())},
        )


@router.post("/register")
def register(request: Request, payload: CredentialsRequest):
    """Create an account on this deployment and return a token for it."""
    if not settings.registration_open():
        raise HTTPException(403, "Registration is closed on this deployment")
    _guard(request, payload.username)
    try:
        token = local.register_user(payload.username, payload.password)
    except local.RegistrationError as exc:
        # Counted: otherwise registration is an unlimited way to probe which
        # usernames are taken.
        ratelimit.record_failure(payload.username, _client_address(request))
        raise HTTPException(400, str(exc))
    return {"token": token, "user_id": payload.username.strip()}


@router.post("/sessions")
def create_session(request: Request, payload: CredentialsRequest):
    """Exchange a username and password for a token."""
    _guard(request, payload.username)

    token = local.authenticate(payload.username, payload.password)
    if token is None:
        ratelimit.record_failure(payload.username, _client_address(request))
        # One message for both a missing account and a wrong password, so this
        # cannot be used to find out which usernames exist.
        raise HTTPException(401, "Incorrect username or password")

    ratelimit.clear(payload.username, _client_address(request))
    return {"token": token, "user_id": payload.username.strip()}


@router.post("/password")
def change_password(request: Request, payload: PasswordChangeRequest):
    """Change your own password. Requires the current one."""
    user_id = service.parse_token(request.headers.get("Authorization"))
    _guard(request, user_id)

    if local.authenticate(user_id, payload.current_password) is None:
        ratelimit.record_failure(user_id, _client_address(request))
        raise HTTPException(401, "Current password is incorrect")
    try:
        local.set_password(user_id, payload.new_password)
    except local.RegistrationError as exc:
        raise HTTPException(400, str(exc))
    ratelimit.clear(user_id, _client_address(request))
    return {"ok": True}


@router.delete("/tokens")
def revoke_token(request: Request, payload: RevokeRequest):
    """Revoke a token. Used to sign out a lost machine."""
    service.parse_token(request.headers.get("Authorization"))
    return {"revoked": local.revoke_token(payload.token)}


@router.get("/whoami")
def whoami(request: Request):
    """Identify the caller. Works in either mode; used by the CLI after login."""
    user_id = service.parse_token(request.headers.get("Authorization"))
    return {"user_id": user_id}


@router.post("/tokens")
def create_token(request: Request, payload: TokenRequest):
    """Issue a token for a user. Requires a token already, so it chains from the
    bootstrap token the server prints on first start."""
    service.parse_token(request.headers.get("Authorization"))
    token = local.issue_token(payload.user_id, label=payload.label)
    return {"token": token, "user_id": payload.user_id}


@router.get("/tokens")
def list_tokens(request: Request):
    """List the caller's tokens. Values are never shown again once issued."""
    user_id = service.parse_token(request.headers.get("Authorization"))
    return {"items": local.list_tokens(user_id)}
