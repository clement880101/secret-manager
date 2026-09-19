"""The audit table, kept apart from the module that writes it.

Its own module because both auth and secret_manager record events, and having
either own the table would make the other import it sideways.
"""

from typing import Optional

from sqlalchemy import Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[float] = mapped_column(Float, index=True)
    # Who did it.
    actor: Mapped[str] = mapped_column(String(64), index=True)
    # What they did, e.g. secret.read.
    action: Mapped[str] = mapped_column(String(32), index=True)
    # The secret key or the user shared with. Never a value or a token.
    target: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
