from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr

from app.models.user import UserStatus


class RoleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    guard_name: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    uuid: str
    names: str
    last_names: str
    email: EmailStr
    status: UserStatus
    email_verified_at: datetime | None
    phone_number: str | None
    pep: bool
    country_iso_code: str | None
    roles: list[RoleOut]
    created_at: datetime


class UserSessionInfo(BaseModel):
    user: UserOut
