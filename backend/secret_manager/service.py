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
        secret = Secret(key=key, value=crypto.encrypt_value(value), owner=owner)
        session.add(secret)


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
    with session_scope() as session:
        me = session.get(User, ext_user_id)
        if me is None:
            return []
        owned = session.scalars(select(Secret).where(Secret.owner == me)).all()
        shared = session.scalars(
            select(Secret).join(Secret.shares).where(Share.user == me)
        ).all()
        results = []
        seen = set()
        for secret in owned + shared:
            if secret.id in seen:
                continue
            seen.add(secret.id)
            owner = secret.owner
            results.append(
                {
                    "key": secret.key,
                    "value": crypto.decrypt_value(secret.value),
                    "owner_id": owner.user_id,
                }
            )
        return results


def share_secret(owner_ext_id: str, key: str, target_ext_id: str) -> None:
    ensure_user(target_ext_id)
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

