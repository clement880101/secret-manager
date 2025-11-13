from fastapi import APIRouter, HTTPException, Request

from auth.service import parse_token
from . import service
from .schemas import SecretIn, ShareIn

router = APIRouter(prefix="/secrets", tags=["secrets"])


def current_user_id(request: Request) -> str:
    return parse_token(request.headers.get("Authorization"))


@router.post("")
def create_secret(request: Request, payload: SecretIn):
    user_id = current_user_id(request)
    try:
        service.put_secret(user_id, payload.key, payload.value)
    except ValueError:
        raise HTTPException(409, "Key exists for this owner")
    return {"ok": True}


@router.get("")
def list_secrets(request: Request):
    user_id = current_user_id(request)
    return {"items": service.list_visible(user_id)}


@router.get("/{key}")
def get_secret(request: Request, key: str):
    user_id = current_user_id(request)
    secret = service.get_secret_for_user(user_id, key)
    if not secret:
        raise HTTPException(403, "Forbidden or not found")
    owner = secret.owner.github_id  # resolved by ORM
    return {"key": secret.key, "value": secret.value, "owner_id": owner}


@router.post("/{key}/share")
def share_secret(request: Request, key: str, payload: ShareIn):
    user_id = current_user_id(request)
    try:
        service.share_secret(user_id, key, payload.github_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {"ok": True}


@router.delete("/{key}")
def delete_secret(request: Request, key: str):
    user_id = current_user_id(request)
    try:
        service.delete_secret(user_id, key)
    except LookupError:
        raise HTTPException(404, "Secret not found")
    return {"ok": True}

