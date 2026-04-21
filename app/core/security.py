from datetime import UTC, datetime, timedelta

import bcrypt
from jose import JWTError, jwt

from app.core.config import settings

ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7
RECOVERY_TOKEN_EXPIRE_MINUTES = 15


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def hash_code(code: str) -> str:
    return bcrypt.hashpw(code.encode(), bcrypt.gensalt()).decode()


def verify_code(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def _create_token(payload: dict, expires_delta: timedelta) -> str:
    data = payload.copy()
    data["exp"] = datetime.now(UTC) + expires_delta
    return jwt.encode(data, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_access_token(user_id: int, user_uuid: str, email: str, roles: list[str]) -> str:
    return _create_token(
        {"sub": str(user_id), "uuid": user_uuid, "email": email, "roles": roles, "type": "access"},
        timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )


def create_refresh_token(user_id: int) -> str:
    return _create_token(
        {"sub": str(user_id), "type": "refresh"},
        timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    )


def create_recovery_token(user_id: int, token_type: str) -> str:
    """token_type: 'password_recovery' | 'unlock_user'"""
    return _create_token(
        {"sub": str(user_id), "type": token_type},
        timedelta(minutes=RECOVERY_TOKEN_EXPIRE_MINUTES),
    )


def decode_token(token: str) -> dict:
    """Raises JWTError on invalid/expired token."""
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])


def safe_decode_token(token: str) -> dict | None:
    try:
        return decode_token(token)
    except JWTError:
        return None
