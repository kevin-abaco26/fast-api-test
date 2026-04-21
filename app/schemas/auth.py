from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RegisterRequest(BaseModel):
    names: str = Field(min_length=1)
    last_names: str = Field(min_length=1)
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)
    phone_number: str | None = None
    country_iso_code: str | None = None


class VerifyCodeRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class PasswordRecoveryRequest(BaseModel):
    email: EmailStr


class UpdatePasswordRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=8, max_length=72)


class UnlockUserRequest(BaseModel):
    token: str


class RefreshRequest(BaseModel):
    """Used when refresh token is sent in the body (fallback — cookie is preferred)."""
    refresh_token: str | None = None


class MessageResponse(BaseModel):
    message: str
