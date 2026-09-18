"""Tokens this service issues itself, for deployments with no GitHub.

Local mode is the default when no GitHub OAuth app is configured, so a freshly
pulled image works immediately: no OAuth registration, no accounts on another
platform, no outbound network access.

Tokens are stored only as a SHA-256 digest. A copy of the database is therefore
not a set of working credentials, and a token cannot be shown again once it has
been issued.
"""

import hashlib
import hmac
import logging
import secrets
import time

from sqlalchemy.exc import IntegrityError
from typing import Optional

from database import session_scope

from . import passwords
from .models import ApiToken, Credential, ensure_user


LOGGER = logging.getLogger(__name__)

TOKEN_BYTES = 32
TOKEN_PREFIX = "smt_"


def hash_token(token: str) -> str:
    """Digest a token for storage and lookup."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_token() -> str:
    """Mint a token with enough entropy that guessing is not a concern."""
    return TOKEN_PREFIX + secrets.token_urlsafe(TOKEN_BYTES)


def issue_token(user_id: str, label: str = "") -> str:
    """Create a token for `user_id` and return it. It cannot be retrieved later."""
    ensure_user(user_id)
    token = generate_token()
    with session_scope() as db:
        db.add(
            ApiToken(
                token_hash=hash_token(token),
                user_id=user_id,
                label=label[:128],
                created_at=time.time(),
            )
        )
    return token


def resolve_token(token: str) -> Optional[str]:
    """Return the user a token belongs to, or None.

    The digest is what is looked up, so the comparison the database performs is
    over hashes rather than secrets. The extra constant-time check guards the
    final confirmation against a timing signal.
    """
    if not token:
        return None
    digest = hash_token(token)
    with session_scope() as db:
        record = db.get(ApiToken, digest)
        if record is None:
            return None
        if not hmac.compare_digest(record.token_hash, digest):
            return None
        return record.user_id


def revoke_token(token: str) -> bool:
    """Delete a token. Returns whether one was removed."""
    with session_scope() as db:
        record = db.get(ApiToken, hash_token(token))
        if record is None:
            return False
        db.delete(record)
        return True


def list_tokens(user_id: str) -> list[dict]:
    """Describe a user's tokens without revealing them."""
    with session_scope() as db:
        rows = db.query(ApiToken).filter_by(user_id=user_id).order_by(ApiToken.created_at).all()
        return [
            {"label": row.label, "created_at": row.created_at, "id": row.token_hash[:12]}
            for row in rows
        ]


def ensure_bootstrap_token(user_id: str = "admin") -> Optional[str]:
    """Create a first token if the deployment has none, so it is usable at all.

    Without this a fresh local-mode deployment would have no way in: every route
    that issues a token requires a token. Returns the new token the first time
    only, so restarting does not keep minting credentials.
    """
    from . import service as _service  # noqa: F401  (kept for import symmetry)

    with session_scope() as db:
        if db.query(ApiToken).count() > 0:
            return None

    from settings import bootstrap_token as configured

    preset = configured()
    if preset:
        ensure_user(user_id)
        with session_scope() as db:
            db.add(
                ApiToken(
                    token_hash=hash_token(preset),
                    user_id=user_id,
                    label="bootstrap (from BOOTSTRAP_TOKEN)",
                    created_at=time.time(),
                )
            )
        LOGGER.warning("Bootstrap token taken from BOOTSTRAP_TOKEN for user %r.", user_id)
        return preset

    token = issue_token(user_id, label="bootstrap")
    LOGGER.warning(
        "No API tokens existed, so one was created for user %r. "
        "This is shown once and cannot be recovered:\n\n    %s\n\n"
        "Log in with:  secretmgr login --token %s",
        user_id,
        token,
        token,
    )
    return token


USERNAME_MAX = 64


class RegistrationError(Exception):
    """Registration was refused. The message is safe to show the caller."""


def _normalise_username(username: str) -> str:
    name = (username or "").strip()
    if not name:
        raise RegistrationError("Username is required.")
    if len(name) > USERNAME_MAX:
        raise RegistrationError(f"Username must be at most {USERNAME_MAX} characters.")
    if any(c.isspace() for c in name):
        raise RegistrationError("Username cannot contain spaces.")
    return name


def register_user(username: str, password: str) -> str:
    """Create an account and return a token for it.

    Raises:
        RegistrationError: the name is unusable or already taken, or the
            password is too short.
    """
    name = _normalise_username(username)
    if len(password or "") < passwords.MIN_PASSWORD_LENGTH:
        raise RegistrationError(
            f"Password must be at least {passwords.MIN_PASSWORD_LENGTH} characters."
        )

    with session_scope() as db:
        if db.get(Credential, name) is not None:
            raise RegistrationError("That username is taken.")

    ensure_user(name)
    try:
        with session_scope() as db:
            db.add(
                Credential(
                    user_id=name,
                    password_hash=passwords.hash_password(password),
                    created_at=time.time(),
                )
            )
    except IntegrityError:
        # Someone registered the same name between the check and the insert.
        raise RegistrationError("That username is taken.") from None

    return issue_token(name, label="registration")


def authenticate(username: str, password: str) -> Optional[str]:
    """Return a fresh token when the password is right, otherwise None."""
    name = (username or "").strip()
    with session_scope() as db:
        credential = db.get(Credential, name)
        encoded = credential.password_hash if credential else None

    if encoded is None:
        # Hash anyway, so a missing account and a wrong password take the same
        # time and the response cannot be used to enumerate usernames.
        passwords.verify_password(password or "", passwords.hash_password("dummy"))
        return None

    if not passwords.verify_password(password or "", encoded):
        return None
    return issue_token(name, label="password login")


def set_password(username: str, password: str) -> None:
    """Set or replace a user's password."""
    name = _normalise_username(username)
    if len(password or "") < passwords.MIN_PASSWORD_LENGTH:
        raise RegistrationError(
            f"Password must be at least {passwords.MIN_PASSWORD_LENGTH} characters."
        )
    ensure_user(name)
    with session_scope() as db:
        credential = db.get(Credential, name)
        if credential is None:
            db.add(
                Credential(
                    user_id=name,
                    password_hash=passwords.hash_password(password),
                    created_at=time.time(),
                )
            )
        else:
            credential.password_hash = passwords.hash_password(password)
