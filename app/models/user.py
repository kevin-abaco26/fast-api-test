from __future__ import annotations

import enum
import uuid as uuid_lib
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base
from app.models.role import user_roles

if TYPE_CHECKING:
    from app.models.failed_login import FailedLogin
    from app.models.role import Role


class UserStatus(str, enum.Enum):
    active = "active"
    locked = "locked"
    inactive = "inactive"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    uuid: Mapped[str] = mapped_column(
        String(36), unique=True, index=True, default=lambda: str(uuid_lib.uuid4())
    )
    names: Mapped[str]
    last_names: Mapped[str]
    email: Mapped[str] = mapped_column(unique=True, index=True)
    password: Mapped[str]
    phone_number: Mapped[str | None]
    status: Mapped[UserStatus] = mapped_column(default=UserStatus.active)
    email_verified_at: Mapped[datetime | None]
    verification_code: Mapped[str | None]
    verification_expiry: Mapped[datetime | None]
    pep: Mapped[bool] = mapped_column(default=False)
    country_iso_code: Mapped[str | None]
    password_reset_token_hash: Mapped[str | None]
    unlock_token_hash: Mapped[str | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())
    deleted_at: Mapped[datetime | None]

    roles: Mapped[list[Role]] = relationship(
        secondary=user_roles,
        back_populates="users",
        lazy="selectin",
    )
    failed_logins: Mapped[list[FailedLogin]] = relationship(
        back_populates="user",
        foreign_keys="FailedLogin.user_id",
    )

    @property
    def role_names(self) -> list[str]:
        return [r.name for r in self.roles]
