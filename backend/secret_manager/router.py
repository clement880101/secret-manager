from fastapi import APIRouter, HTTPException, Request

import audit
from auth.service import parse_token
from . import service
from .schemas import SecretIn, SecretValueIn, ShareIn

router = APIRouter(prefix="/secrets", tags=["secrets"])


def current_user_id(request: Request) -> str:
    return parse_token(request.headers.get("Authorization"))


def client_address(request: Request) -> str:
    """Best guess at who is calling, trusting the proxy header when present."""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@router.post("")
def create_secret(request: Request, payload: SecretIn):
    user_id = current_user_id(request)
    try:
        service.put_secret(user_id, payload.key, payload.value)
    except ValueError:
        raise HTTPException(409, "Key exists for this owner")
    audit.record(audit.SECRET_CREATE, user_id, payload.key, client_address(request))
    return {"ok": True}


@router.put("/{key}")
def update_secret(request: Request, key: str, payload: SecretValueIn):
    """Change the value of a secret without disturbing who it is shared with."""
    user_id = current_user_id(request)
    try:
        service.update_secret(user_id, key, payload.value)
    except LookupError:
        raise HTTPException(404, "Secret not found")
    audit.record(audit.SECRET_UPDATE, user_id, key, client_address(request))
    return {"ok": True}


@router.get("")
def list_secrets(request: Request):
    user_id = current_user_id(request)
    items = service.list_visible(user_id)
    audit.record(audit.SECRET_LIST, user_id, None, client_address(request))
    return {"items": items}

@router.get("/{key}")
def get_secret(request: Request, key: str):
    user_id = current_user_id(request)
    secret = service.get_secret_for_user(user_id, key)
    if not secret:
        raise HTTPException(403, "Forbidden or not found")
    # Recorded after the access check, so the trail shows reads that happened
    # rather than attempts that were refused.
    audit.record(audit.SECRET_READ, user_id, key, client_address(request))
    return secret


@router.post("/{key}/share")
def share_secret(request: Request, key: str, payload: ShareIn):
    user_id = current_user_id(request)
    try:
        service.share_secret(user_id, key, payload.user_id)
    except service.UnknownUser:
        # Distinct from "secret not found", so a typo in the recipient reads
        # differently from a typo in the key.
        raise HTTPException(404, f"No user named {payload.user_id!r} on this deployment")
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    audit.record(audit.SECRET_SHARE, user_id, f"{key} -> {payload.user_id}", client_address(request))
    return {"ok": True}


@router.delete("/{key}")
def delete_secret(request: Request, key: str):
    user_id = current_user_id(request)
    try:
        service.delete_secret(user_id, key)
    except LookupError:
        raise HTTPException(404, "Secret not found")
    audit.record(audit.SECRET_DELETE, user_id, key, client_address(request))
    return {"ok": True}

