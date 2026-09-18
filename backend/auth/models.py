from datetime import datetime, timezone

from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import DateTime, Float, ForeignKey, String, Text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base, session_scope

if TYPE_CHECKING:
    from secret_manager.models import Secret, Share


class User(Base):
    __tablename__ = "users"

    github_id: Mapped[str] = mapped_column(String, primary_key=True)
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



class LoginSession(Base):
    """An in-progress or completed OAuth login.

    Login state used to live in two module-level dicts, which meant it was lost
    whenever the process restarted and was invisible to any other replica. That
    made the service impossible to run with more than one instance, and it made
    a routine redeploy break every login in flight. Keeping it in the database
    lets the service be deployed anywhere, including platforms that move
    containers around freely.
    """

    __tablename__ = "login_sessions"

    session_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    # The OAuth state parameter, which guards against CSRF. Cleared once
    # redeemed so a state cannot be replayed.
    state: Mapped[Optional[str]] = mapped_column(String(128), unique=True, index=True, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    scope: Mapped[str] = mapped_column(String(255), default="")
    # Encrypted with the same key as stored secrets: this is a live GitHub token.
    access_token: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    token_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    token_scope: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[float] = mapped_column(Float)
    completed_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True)


def ensure_user(github_id: str) -> None:
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
        if session.get(User, github_id) is not None:
            return
    try:
        with session_scope() as session:
            session.add(User(github_id=github_id))
    except IntegrityError:
        pass


class ApiToken(Base):
    """A bearer token this service issued itself.

    Local mode exists so the service depends on nothing outside itself: no
    OAuth app to register, no accounts on someone else's platform, and no
    outbound network access. That is what makes "pull the image and run it"
    actually true.

    Only the SHA-256 of the token is stored. A leaked database therefore does
    not hand over working credentials, and there is no way to display a token
    again after it is issued.
    """

    __tablename__ = "api_tokens"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    # Matches users.github_id, which in local mode is simply a user name.
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
