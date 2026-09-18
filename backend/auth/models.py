from datetime import datetime, timezone

from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import DateTime, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base

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
