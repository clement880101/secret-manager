from datetime import datetime, timezone

from typing import TYPE_CHECKING, List

from sqlalchemy import DateTime, String
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

