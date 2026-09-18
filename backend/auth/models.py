from datetime import datetime, timezone

from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base, session_scope

if TYPE_CHECKING:
    from secret_manager.models import Secret, Share


class User(Base):
    __tablename__ = "users"

    # A username on this deployment. Named user_id because that is what it is.
    user_id: Mapped[str] = mapped_column("github_id", String, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    secrets: Mapped[List["Secret"]] = relationship(
        "Secret",
        back_populates="owner",
        cascade="all, delete-orphan",
    )
    secret_shares: Mapped[List["Share"]] = relationship(
        "Share",
        back_populates="user",
        cascade="all, delete-orphan",
    )


def ensure_user(user_id: str) -> None:
    """Create the user row if it is missing, tolerating a concurrent creator.

    Check-then-insert is not safe once more than one replica is serving
    traffic: both see no row, both insert, and the loser gets an
    IntegrityError. Every authenticated request runs this, so under
    concurrency a user's first requests would fail with a 500.

    The insert runs in its own transaction so that losing the race does not
    poison the caller's, and a duplicate simply means someone else got there
    first -- which is the outcome we wanted anyway.
    """
    with session_scope() as session:
        if session.get(User, user_id) is not None:
            return
    try:
        with session_scope() as session:
            session.add(User(user_id=user_id))
    except IntegrityError:
        pass


class ApiToken(Base):
    """A bearer token this service issued.

    Only the SHA-256 of the token is stored. A leaked database therefore does
    not hand over working credentials, and there is no way to display a token
    again after it is issued.
    """

    __tablename__ = "api_tokens"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.github_id"), index=True)
    label: Mapped[str] = mapped_column(String(128), default="")
    created_at: Mapped[float] = mapped_column(Float)


class Credential(Base):
    """A username and password for a user of this deployment.

    Deliberately a table of its own rather than a column on User. There is no
    migration step in this project -- create_all() adds missing tables but will
    not add a column to one that already exists -- so a new table is the change
    that applies cleanly to databases that are already out there.

    A user may have no row here: tokens issued by an administrator work without
    a password, and GitHub-mode users never have one.
    """

    __tablename__ = "credentials"

    user_id: Mapped[str] = mapped_column(ForeignKey("users.github_id"), primary_key=True)
    # scrypt, encoded with its parameters and salt. See auth.passwords.
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[float] = mapped_column(Float)


class AuthAttempt(Base):
    """A failed authentication, recorded so repeated ones can be slowed down.

    Kept in the database rather than in process memory because the limit has to
    hold across replicas: a per-process counter would let an attacker get N
    tries per replica, and the whole point of this service is that it scales
    horizontally. Auth endpoints are low volume, so the write cost is fine.
    """

    __tablename__ = "auth_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # Either "user:<name>" or "ip:<address>", so one row type covers both limits.
    key: Mapped[str] = mapped_column(String(160), index=True)
    at: Mapped[float] = mapped_column(Float, index=True)
