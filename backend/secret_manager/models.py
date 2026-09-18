from typing import List

from sqlalchemy import ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from auth.models import User
from database import Base


class Secret(Base):
    __tablename__ = "secrets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String)
    value: Mapped[str] = mapped_column(String)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.user_id"))
    shares: Mapped[List["Share"]] = relationship(
        "Share",
        back_populates="secret",
        cascade="all, delete-orphan",
    )

    owner: Mapped["User"] = relationship("User", back_populates="secrets")

    __table_args__ = (UniqueConstraint("owner_id", "key", name="uix_owner_key"),)


class Share(Base):
    __tablename__ = "shares"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    secret_id: Mapped[int] = mapped_column(ForeignKey("secrets.id"))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.user_id"))

    secret: Mapped["Secret"] = relationship("Secret", back_populates="shares")
    user: Mapped["User"] = relationship("User", back_populates="secret_shares")

    # Concurrent shares of the same secret to the same person otherwise each
    # pass the "already shared?" check and all insert. Applied to databases
    # created from here on; existing ones keep whatever rows they have, which
    # list_visible de-duplicates on read.
    __table_args__ = (UniqueConstraint("secret_id", "user_id", name="uix_share_secret_user"),)

