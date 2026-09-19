from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

import crypto
from auth.models import User, ensure_user
from database import session_scope
from .models import Secret, Share


def put_secret(owner_id: str, key: str, value: str) -> None:
    ensure_user(owner_id)
    with session_scope() as session:
        owner = session.get(User, owner_id)
        existing = session.scalars(
            select(Secret).where(Secret.owner == owner, Secret.key == key)
        ).first()
        if existing:
            raise ValueError("Key exists for this owner")
        session.add(Secret(key=key, value=crypto.encrypt_value(value), owner=owner))
        try:
            session.flush()
        except IntegrityError:
            # Two callers passed the check above before either inserted. The
            # unique constraint on (owner_id, key) is the authority, so treat
            # losing that race as what it is: the key already exists.
            session.rollback()
            raise ValueError("Key exists for this owner") from None


def update_secret(owner_id: str, key: str, value: str) -> None:
    """Replace the value of an existing secret, keeping who it is shared with.

    Without this the only way to change a value was to delete the secret and
    create it again -- and deleting cascades to the shares, so rotating a
    credential silently revoked every teammate's access to it. The row is
    updated in place here, so the shares are untouched.

    Raises:
        LookupError: no such key owned by this user.
    """
    with session_scope() as session:
        owner = session.get(User, owner_id)
        if owner is None:
            raise LookupError("Secret not found")
        secret = session.scalars(
            select(Secret).where(Secret.owner == owner, Secret.key == key)
        ).first()
        if secret is None:
            raise LookupError("Secret not found")
        secret.value = crypto.encrypt_value(value)


def get_secret_for_user(ext_user_id: str, key: str) -> Optional[dict]:
    """Return the secret as a plain dict so callers are not tied to the session."""
    with session_scope() as session:
        me = session.get(User, ext_user_id)
        if me is None:
            return None
        secret = session.scalars(
            select(Secret).where(Secret.key == key, Secret.owner == me)
        ).first()
        if secret is None:
            secret = session.scalars(
                select(Secret)
                .join(Secret.shares)
                .where(Secret.key == key, Share.user == me)
            ).first()
        if secret is None:
            return None
        return {
            "key": secret.key,
            "value": crypto.decrypt_value(secret.value),
            "owner_id": secret.owner_id,
        }


def list_visible(ext_user_id: str) -> List[dict]:
    """List what a user can see, without the values.

    Returning every value here meant one stolen token exposed everything that
    account could reach in a single request, and nothing in the audit trail
    could distinguish "listed their keys" from "read all their secrets".
    Reading a value is now a deliberate request for one key at a time.
    """
    with session_scope() as session:
        me = session.get(User, ext_user_id)
        if me is None:
            return []
        # Select the three columns that go into the response, not whole rows.
        # Selecting whole Secrets pulled the ciphertext of everything this user
        # can reach into memory on every list call -- values this endpoint
        # exists precisely to withhold. They were dropped again immediately,
        # having cost a read of the entire column.
        columns = select(Secret.id, Secret.key, Secret.owner_id)
        owned = session.execute(columns.where(Secret.owner_id == ext_user_id)).all()
        shared = session.execute(
            columns.join(Secret.shares).where(Share.user_id == ext_user_id)
        ).all()
        results = []
        seen = set()
        for secret_id, key, owner_id in owned + shared:
            if secret_id in seen:
                continue
            seen.add(secret_id)
            results.append(
                {
                    "key": key,
                    "owner_id": owner_id,
                    "shared": owner_id != ext_user_id,
                }
            )
        return results


class UnknownUser(Exception):
    """The person a secret was being shared with does not exist here."""


def share_secret(owner_ext_id: str, key: str, target_ext_id: str) -> None:
    """Grant read access to an existing user.

    The recipient has to exist already. Creating them on demand meant a typo
    looked like success: the secret was shared with an account nobody held, and
    whoever registered that name next would inherit it.
    """
    with session_scope() as session:
        owner = session.get(User, owner_ext_id)
        if owner is None:
            raise ValueError("Owner missing")
        secret = session.scalars(
            select(Secret).where(Secret.owner == owner, Secret.key == key)
        ).first()
        if secret is None:
            raise ValueError("Secret not found for owner")
        target = session.get(User, target_ext_id)
        if target is None:
            raise UnknownUser(target_ext_id)
        duplicate = session.scalars(
            select(Share).where(Share.secret == secret, Share.user == target)
        ).first()
        if duplicate is not None:
            return
        session.add(Share(secret=secret, user=target))
        try:
            session.flush()
        except IntegrityError:
            # Another replica shared it first. Sharing is idempotent, so that
            # is the outcome the caller asked for.
            session.rollback()


def delete_secret(owner_id: str, key: str) -> None:
    with session_scope() as session:
        owner = session.get(User, owner_id)
        if owner is None:
            raise LookupError("Secret not found")
        secret = session.scalars(
            select(Secret).where(Secret.owner == owner, Secret.key == key)
        ).first()
        if secret is None:
            raise LookupError("Secret not found")
        session.delete(secret)

