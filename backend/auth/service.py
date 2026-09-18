"""Turning a request's Authorization header into a user.

This service issues its own tokens and resolves them against its own database.
It does not call out to anyone: no OAuth provider, no external identity, no
outbound network access at all. That is what makes the image runnable anywhere
with nothing configured.
"""

from typing import Optional

from fastapi import HTTPException

from . import local
from .models import User, ensure_user  # noqa: F401  (re-exported for callers)


def parse_token(auth_header: Optional[str]) -> str:
    """Extract the bearer token and return the user it identifies.

    Inputs:
        auth_header (str | None): Raw Authorization header.
    Outputs:
        str: The user the token belongs to.
    Raises:
        HTTPException: 401 when the header is missing or malformed, or the
            token is unknown or has been revoked.
    """
    if not auth_header or not auth_header.lower().startswith("bearer "):
        raise HTTPException(401, "Missing bearer token")

    token = auth_header.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(401, "Missing bearer token")

    user_id = local.resolve_token(token)
    if user_id is None:
        raise HTTPException(401, "Invalid or revoked token")
    return user_id


def get_or_create_user(user_id: str) -> None:
    """Ensure a user row exists. Safe to call from several replicas at once."""
    ensure_user(user_id)
