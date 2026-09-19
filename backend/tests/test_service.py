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
        assert secret.owner.user_id == "alice"
        assert session.get(User, "alice") is not None


def test_put_secret_with_duplicate_key_raises(service_modules):
    service = service_modules["service"]

    service.put_secret("alice", "api_token", "value-1")

    with pytest.raises(ValueError, match="Key exists for this owner"):
        service.put_secret("alice", "api_token", "value-2")


def test_get_secret_for_user_returns_owned_secret(service_modules):
    service = service_modules["service"]

    service.put_secret("alice", "db-password", "pw")

    secret = service.get_secret_for_user("alice", "db-password")

    assert secret == {"key": "db-password", "value": "pw", "owner_id": "alice"}


def test_get_secret_for_user_returns_shared_secret(service_modules):
    service = service_modules["service"]

    service.put_secret("owner", "shared-key", "shared-value")
    service.put_secret("bob", "own", "bob-value")  # bob has to exist to be shared with
    service.share_secret("owner", "shared-key", "bob")

    secret = service.get_secret_for_user("bob", "shared-key")

    assert secret == {"key": "shared-key", "value": "shared-value", "owner_id": "owner"}


def test_get_secret_for_user_hides_unshared_secret(service_modules):
    service = service_modules["service"]

    service.put_secret("owner", "private-key", "private-value")
    service.put_secret("bob", "other-key", "other-value")

    assert service.get_secret_for_user("bob", "private-key") is None


def test_list_visible_includes_owned_and_shared(service_modules):
    service = service_modules["service"]

    service.put_secret("alice", "personal", "alice-secret")
    service.put_secret("carol", "shared", "carol-secret")
    service.share_secret("carol", "shared", "alice")

    visible = service.list_visible("alice")

    assert len(visible) == 2
    assert {"key": "personal", "owner_id": "alice", "shared": False} in visible
    assert {"key": "shared", "owner_id": "carol", "shared": True} in visible


def test_share_secret_is_idempotent(service_modules):
    service = service_modules["service"]
    database = service_modules["database"]
    Share = service_modules["Share"]

    service.put_secret("owner", "key", "value")
    service.put_secret("target", "own", "value")
    service.share_secret("owner", "key", "target")
    service.share_secret("owner", "key", "target")

    with database.session_scope() as session:
        shares = session.scalars(select(Share)).all()
        assert len(shares) == 1
        assert shares[0].user.user_id == "target"


def test_sharing_with_an_unknown_user_is_refused(service_modules):
    """A typo used to create the account silently, so the secret was shared
    with nobody -- until someone registered that name and inherited it."""
    service = service_modules["service"]
    database = service_modules["database"]
    User = service_modules["User"]
    service.put_secret("owner", "key", "value")

    with pytest.raises(service.UnknownUser):
        service.share_secret("owner", "key", "nosuchuser")

    with database.session_scope() as session:
        assert session.get(User, "nosuchuser") is None


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




def test_list_never_returns_values(service_modules):
    """One stolen token should not hand over everything in a single request."""
    service = service_modules["service"]
    service.put_secret("alice", "k1", "hunter2")
    service.put_secret("alice", "k2", "correct-horse")

    visible = service.list_visible("alice")

    assert {item["key"] for item in visible} == {"k1", "k2"}
    assert "hunter2" not in str(visible)
    assert "correct-horse" not in str(visible)
    assert all("value" not in item for item in visible)


def test_list_does_not_even_read_the_values(service_modules):
    """Withholding the values is not the same as not fetching them.

    list_visible returned the right three fields while selecting whole Secret
    rows, so every list call read the ciphertext of everything the caller could
    reach out of the database and then dropped it. The previous test passes
    against that version, because it only inspects the response.
    """
    from sqlalchemy import event

    service = service_modules["service"]
    database = service_modules["database"]
    service.put_secret("alice", "k1", "hunter2")
    service.put_secret("bob", "own", "bobs-own")  # also creates bob
    service.share_secret("alice", "k1", "bob")

    statements = []

    def record(conn, cursor, statement, params, context, executemany):
        statements.append(statement)

    event.listen(database.engine, "before_cursor_execute", record)
    try:
        visible = service.list_visible("bob")
    finally:
        event.remove(database.engine, "before_cursor_execute", record)

    assert {item["key"] for item in visible} == {"own", "k1"}

    selects = [s for s in statements if s.lstrip().upper().startswith("SELECT")]
    assert selects, "expected the listing to query something"
    assert not [s for s in selects if "secrets.value" in s], (
        "listing read the secret values it exists to withhold:\n"
        + "\n".join(s for s in selects if "secrets.value" in s)
    )


def test_update_keeps_the_secret_shared(service_modules):
    """Rotating a value must not revoke everyone's access to it.

    There was no way to change a value: you deleted the secret and created it
    again. Deleting cascades to the shares, so the only available way to
    rotate a credential silently cut off every teammate it was shared with,
    and nothing said so.
    """
    service = service_modules["service"]

    service.put_secret("alice", "db-pw", "v1")
    service.put_secret("bob", "unrelated", "x")  # also creates bob
    service.share_secret("alice", "db-pw", "bob")
    assert service.get_secret_for_user("bob", "db-pw")["value"] == "v1"

    service.update_secret("alice", "db-pw", "v2")

    assert service.get_secret_for_user("alice", "db-pw")["value"] == "v2"
    assert service.get_secret_for_user("bob", "db-pw")["value"] == "v2", (
        "the share did not survive the update"
    )


def test_update_of_a_missing_secret_raises(service_modules):
    service = service_modules["service"]
    service.put_secret("alice", "other", "v")

    with pytest.raises(LookupError):
        service.update_secret("alice", "no-such-key", "v2")


def test_update_will_not_touch_someone_elses_secret(service_modules):
    service = service_modules["service"]

    service.put_secret("alice", "db-pw", "v1")
    service.put_secret("bob", "unrelated", "x")
    service.share_secret("alice", "db-pw", "bob")

    # bob can read it, but reading is not writing.
    with pytest.raises(LookupError):
        service.update_secret("bob", "db-pw", "hijacked")

    assert service.get_secret_for_user("alice", "db-pw")["value"] == "v1"
