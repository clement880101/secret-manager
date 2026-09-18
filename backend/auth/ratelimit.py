"""Slow down repeated failed authentications.

Without this, open registration plus password login is a brute-force target:
scrypt makes each guess cost about 30ms, which is a speed bump, not a defence.

Two keys are counted separately. A username key stops one account being ground
down. An address key stops one source spraying many usernames, which the
username key alone would not catch.

Only failures count. A user logging in successfully forty times is not an
attack, and counting successes would lock people out of their own accounts.
"""

import time
from typing import Optional

import settings
from database import session_scope

from .models import AuthAttempt


def _prune(now: float, window: int) -> None:
    """Drop attempts that have aged out, in a transaction of its own.

    Separate because callers raise on the blocked path, and session_scope rolls
    back on exception -- cleanup inside that block would be undone exactly when
    the table is busiest.
    """
    with session_scope() as db:
        db.query(AuthAttempt).filter(AuthAttempt.at < now - window).delete(
            synchronize_session=False
        )


def _count(key: str, now: float, window: int) -> int:
    with session_scope() as db:
        return (
            db.query(AuthAttempt)
            .filter(AuthAttempt.key == key, AuthAttempt.at >= now - window)
            .count()
        )


def blocked_key(username: Optional[str], address: Optional[str]) -> Optional[str]:
    """Return the key that is over its limit, or None to let the attempt through."""
    limit = settings.auth_rate_limit()
    if limit == 0:
        return None
    window = settings.auth_rate_window_seconds()
    now = time.time()
    _prune(now, window)

    for key in _keys(username, address):
        if _count(key, now, window) >= limit:
            return key
    return None


def record_failure(username: Optional[str], address: Optional[str]) -> None:
    """Count a failed attempt against both its keys."""
    if settings.auth_rate_limit() == 0:
        return
    now = time.time()
    with session_scope() as db:
        for key in _keys(username, address):
            db.add(AuthAttempt(key=key, at=now))


def clear(username: Optional[str], address: Optional[str]) -> None:
    """Forget an identity's failures, after it authenticates successfully."""
    if settings.auth_rate_limit() == 0:
        return
    with session_scope() as db:
        for key in _keys(username, address):
            db.query(AuthAttempt).filter(AuthAttempt.key == key).delete(
                synchronize_session=False
            )


def _keys(username: Optional[str], address: Optional[str]) -> list[str]:
    keys = []
    if username:
        keys.append(f"user:{username.strip()[:128]}")
    if address:
        keys.append(f"ip:{address[:128]}")
    return keys
