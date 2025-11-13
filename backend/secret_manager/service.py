from typing import List, Optional

from sqlalchemy import select

from auth.models import User
from database import session_scope
from .models import Secret, Share


def put_secret(owner_id: str, key: str, value: str) -> None:
    with session_scope() as session:
        owner = session.get(User, owner_id)
        if owner is None:
            owner = User(github_id=owner_id)
            session.add(owner)
            session.flush()
        existing = session.scalars(
            select(Secret).where(Secret.owner == owner, Secret.key == key)
        ).first()
        if existing:
            raise ValueError("Key exists for this owner")
        secret = Secret(key=key, value=value, owner=owner)
        session.add(secret)


def get_secret_for_user(ext_user_id: str, key: str) -> Optional[Secret]:
    with session_scope() as session:
        me = session.get(User, ext_user_id)
        if me is None:
            return None
        secret = session.scalars(
            select(Secret).where(Secret.key == key, Secret.owner == me)
        ).first()
        if secret:
            return secret
        return session.scalars(
            select(Secret)
            .join(Secret.shares)
            .where(Secret.key == key, Share.user == me)
        ).first()


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
        for secret in owned + shared:
            owner = secret.owner
            results.append({"key": secret.key, "value": secret.value, "owner_id": owner.github_id})
        return results


def share_secret(owner_ext_id: str, key: str, target_ext_id: str) -> None:
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
            target = User(github_id=target_ext_id)
            session.add(target)
            session.flush()
        duplicate = session.scalars(
            select(Share).where(Share.secret == secret, Share.user == target)
        ).first()
        if duplicate is not None:
            return
        session.add(Share(secret=secret, user=target))


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

