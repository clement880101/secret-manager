"""A record of who did what, and when.

A secret manager that cannot answer "who read this, and when" is missing
something its users will eventually need: after someone leaves, after a laptop
goes missing, or when a value turns up somewhere it should not have.

Events are kept in the database like everything else, so every replica writes
to the same trail and reading it back does not depend on which instance
answers. They are written on the paths that matter -- reads, writes, sharing,
deletion, and anything that changes credentials -- and never contain a secret
value or a token.
"""

import logging
import time
from typing import List, Optional

import settings
from database import session_scope

from audit_models import AuditEvent  # noqa: F401  (re-exported)


LOGGER = logging.getLogger(__name__)

# Actions worth being able to answer questions about later.
SECRET_READ = "secret.read"
SECRET_LIST = "secret.list"
SECRET_CREATE = "secret.create"
SECRET_SHARE = "secret.share"
SECRET_DELETE = "secret.delete"
AUTH_REGISTER = "auth.register"
AUTH_LOGIN = "auth.login"
AUTH_PASSWORD_CHANGE = "auth.password_change"
TOKEN_ISSUE = "token.issue"
TOKEN_REVOKE = "token.revoke"


def record(action: str, actor: str, target: Optional[str] = None, address: Optional[str] = None) -> None:
    """Append an event. Never raises: an audit failure must not fail the request.

    Losing one line is better than refusing a legitimate operation, but a
    failure to write is itself worth knowing about, so it is logged.
    """
    if not settings.audit_enabled():
        return
    try:
        with session_scope() as db:
            db.add(
                AuditEvent(
                    at=time.time(),
                    actor=(actor or "")[:64],
                    action=action[:32],
                    target=(target or None) and target[:128],
                    address=(address or None) and address[:64],
                )
            )
    except Exception:  # noqa: BLE001 - deliberately swallowed, see docstring
        LOGGER.exception("Failed to write an audit event for %s by %s", action, actor)


def prune(now: Optional[float] = None) -> int:
    """Drop events past the retention window. Returns how many went."""
    days = settings.audit_retention_days()
    if days <= 0:
        return 0
    cutoff = (now or time.time()) - days * 86400
    with session_scope() as db:
        return db.query(AuditEvent).filter(AuditEvent.at < cutoff).delete(
            synchronize_session=False
        )


def for_actor(actor: str, limit: int = 100) -> List[dict]:
    """The most recent events for one user, newest first."""
    limit = max(1, min(limit, 1000))
    with session_scope() as db:
        rows = (
            db.query(AuditEvent)
            .filter(AuditEvent.actor == actor)
            .order_by(AuditEvent.at.desc())
            .limit(limit)
            .all()
        )
        return [
            {"at": row.at, "action": row.action, "target": row.target, "address": row.address}
            for row in rows
        ]
