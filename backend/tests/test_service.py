from sqlalchemy import select

import pytest


def test_put_secret_creates_secret_and_user(service_modules):
    service = service_modules["service"]
    database = service_modules["database"]
    Secret = service_modules["Secret"]
    User = service_modules["User"]

    service.put_secret("alice", "api_token", "super-secret")

    with database.session_scope() as session:
        secret = session.scalars(select(Secret)).one()
        assert secret.key == "api_token"
        assert secret.value == "super-secret"
        assert secret.owner.github_id == "alice"
        assert session.get(User, "alice") is not None


def test_put_secret_with_duplicate_key_raises(service_modules):
    service = service_modules["service"]

    service.put_secret("alice", "api_token", "value-1")

    with pytest.raises(ValueError, match="Key exists for this owner"):
        service.put_secret("alice", "api_token", "value-2")


def test_get_secret_for_user_returns_owned_secret(service_modules):
    service = service_modules["service"]
    database = service_modules["database"]

    service.put_secret("alice", "db-password", "pw")

    secret = service.get_secret_for_user("alice", "db-password")

    assert secret is not None
    with database.session_scope() as session:
        merged = session.merge(secret)
        assert merged.key == "db-password"
        assert merged.value == "pw"


def test_get_secret_for_user_returns_shared_secret(service_modules):
    service = service_modules["service"]
    database = service_modules["database"]

    service.put_secret("owner", "shared-key", "shared-value")
    service.share_secret("owner", "shared-key", "bob")

    secret = service.get_secret_for_user("bob", "shared-key")

    assert secret is not None
    with database.session_scope() as session:
        merged = session.merge(secret)
        assert merged.owner.github_id == "owner"
        assert merged.value == "shared-value"


def test_list_visible_includes_owned_and_shared(service_modules):
    service = service_modules["service"]

    service.put_secret("alice", "personal", "alice-secret")
    service.put_secret("carol", "shared", "carol-secret")
    service.share_secret("carol", "shared", "alice")

    visible = service.list_visible("alice")

    assert len(visible) == 2
    assert {"key": "personal", "value": "alice-secret", "owner_id": "alice"} in visible
    assert {"key": "shared", "value": "carol-secret", "owner_id": "carol"} in visible


def test_share_secret_is_idempotent_and_creates_user(service_modules):
    service = service_modules["service"]
    database = service_modules["database"]
    Share = service_modules["Share"]
    User = service_modules["User"]

    service.put_secret("owner", "key", "value")
    service.share_secret("owner", "key", "target")
    service.share_secret("owner", "key", "target")

    with database.session_scope() as session:
        shares = session.scalars(select(Share)).all()
        assert len(shares) == 1
        share = shares[0]
        assert share.user.github_id == "target"
        assert session.get(User, "target") is not None


def test_delete_secret_removes_secret(service_modules):
    service = service_modules["service"]
    database = service_modules["database"]
    Secret = service_modules["Secret"]

    service.put_secret("alice", "doomed", "value")

    service.delete_secret("alice", "doomed")

    with database.session_scope() as session:
        secret = session.scalars(select(Secret)).first()
        assert secret is None


def test_delete_secret_missing_owner_raises(service_modules):
    service = service_modules["service"]

    with pytest.raises(LookupError, match="Secret not found"):
        service.delete_secret("missing", "key")


