import hashlib
import random
import string
from datetime import UTC, datetime, timedelta

from jose import JWTError
from sqlalchemy.orm import Session

from app.core import exceptions as exc
from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_recovery_token,
    create_refresh_token,
    decode_token,
    hash_code,
    hash_password,
    verify_code,
    verify_password,
)
from app.models.failed_login import FailedLogin
from app.models.user import User, UserStatus
from app.schemas.auth import RegisterRequest
from app.services import email_service, user_service


def _generate_verification_code() -> str:
    return "".join(random.choices(string.digits, k=6))


def _count_active_failed_logins(db: Session, email: str) -> int:
    return (
        db.query(FailedLogin)
        .filter(FailedLogin.email == email, FailedLogin.deleted_at.is_(None))
        .count()
    )


def _clear_failed_logins(db: Session, email: str) -> None:
    now = datetime.now(UTC)
    db.query(FailedLogin).filter(
        FailedLogin.email == email, FailedLogin.deleted_at.is_(None)
    ).update({"deleted_at": now})


def _lock_user(db: Session, user: User) -> None:
    user.status = UserStatus.locked


def login(
    db: Session, *, email: str, password: str, ip_address: str | None = None
) -> tuple[str, str]:
    """Returns (access_token, refresh_token). Raises AppException on failure."""
    user = user_service.get_by_email(db, email)
    if not user:
        raise exc.invalid_credentials()

    if user.status == UserStatus.locked:
        raise exc.locked_user()
    if user.status == UserStatus.inactive:
        raise exc.inactive_user()

    if not verify_password(password, user.password):
        failed = FailedLogin(email=email, ip_address=ip_address, user_id=user.id)
        db.add(failed)
        db.flush()
        count = _count_active_failed_logins(db, email)
        if count >= settings.FAILED_LOGIN_THRESHOLD:
            _lock_user(db, user)
            db.commit()
            raise exc.locked_user()
        db.commit()
        raise exc.invalid_credentials()

    _clear_failed_logins(db, email)
    db.commit()
    db.refresh(user)

    access = create_access_token(user.id, str(user.uuid), user.email, user.role_names)
    refresh = create_refresh_token(user.id)
    return access, refresh


def register(db: Session, *, data: RegisterRequest) -> tuple[User, str, str]:
    """Returns (user, access_token, refresh_token). Raises AppException on duplicate email."""
    if user_service.get_by_email(db, data.email):
        raise exc.already_exists("Email")

    user = user_service.create_user(
        db,
        names=data.names,
        last_names=data.last_names,
        email=data.email,
        plain_password=data.password,
        phone_number=data.phone_number,
        country_iso_code=data.country_iso_code,
    )
    user_service.assign_role(db, user, "customer-admin")

    code = _generate_verification_code()
    user.verification_code = hash_code(code)
    user.verification_expiry = datetime.now(UTC) + timedelta(
        minutes=settings.VERIFICATION_CODE_TTL_MINUTES
    )
    db.commit()
    db.refresh(user)

    email_service.send_verification_code(user.email, code, names=user.names)

    access = create_access_token(user.id, str(user.uuid), user.email, user.role_names)
    refresh = create_refresh_token(user.id)
    return user, access, refresh


def verify_email(db: Session, *, user: User, code: str) -> User:
    if not user.verification_expiry or datetime.now(UTC) > user.verification_expiry.replace(
        tzinfo=UTC
    ):
        raise exc.verification_code_expired()
    if not user.verification_code or not verify_code(code, user.verification_code):
        raise exc.verification_code_invalid()

    user.email_verified_at = datetime.now(UTC)
    user.verification_code = None
    user.verification_expiry = None
    db.commit()
    db.refresh(user)
    return user


def resend_verification(db: Session, *, user: User) -> None:
    code = _generate_verification_code()
    user.verification_code = hash_code(code)
    user.verification_expiry = datetime.now(UTC) + timedelta(
        minutes=settings.VERIFICATION_CODE_TTL_MINUTES
    )
    db.commit()
    email_service.send_verification_code(user.email, code, names=user.names)


def refresh_access_token(db: Session, *, refresh_token: str) -> str:
    try:
        payload = decode_token(refresh_token)
    except JWTError:
        raise exc.token_invalid()

    if payload.get("type") != "refresh":
        raise exc.token_invalid()

    user = user_service.get_by_id(db, int(payload["sub"]))
    if not user:
        raise exc.token_invalid()
    if user.status != UserStatus.active:
        raise exc.inactive_user()

    return create_access_token(user.id, str(user.uuid), user.email, user.role_names)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def request_password_recovery(db: Session, *, email: str) -> None:
    user = user_service.get_by_email(db, email)
    if not user:
        return  # don't leak existence

    token = create_recovery_token(user.id, "password_recovery")
    user.password_reset_token_hash = _sha256(token)
    db.commit()
    email_service.send_password_recovery(user.email, token, names=user.names)


def update_password(db: Session, *, recovery_token: str, new_password: str) -> None:
    try:
        payload = decode_token(recovery_token)
    except JWTError:
        raise exc.token_invalid()

    if payload.get("type") != "password_recovery":
        raise exc.token_invalid()

    user = user_service.get_by_id(db, int(payload["sub"]))
    if not user:
        raise exc.not_found("User")

    if not user.password_reset_token_hash or user.password_reset_token_hash != _sha256(recovery_token):
        raise exc.token_invalid()

    user.password = hash_password(new_password)
    user.password_reset_token_hash = None  # single-use: invalidate immediately
    db.commit()


def request_unlock(db: Session, *, email: str) -> None:
    user = user_service.get_by_email(db, email)
    if not user or user.status != UserStatus.locked:
        return  # don't leak state

    token = create_recovery_token(user.id, "unlock_user")
    user.unlock_token_hash = _sha256(token)
    db.commit()
    email_service.send_unlock_email(user.email, token, names=user.names)


def unlock_user(db: Session, *, unlock_token: str) -> None:
    try:
        payload = decode_token(unlock_token)
    except JWTError:
        raise exc.token_invalid()

    if payload.get("type") != "unlock_user":
        raise exc.token_invalid()

    user = user_service.get_by_id(db, int(payload["sub"]))
    if not user:
        raise exc.not_found("User")

    if not user.unlock_token_hash or user.unlock_token_hash != _sha256(unlock_token):
        raise exc.token_invalid()

    user.status = UserStatus.active
    user.unlock_token_hash = None  # single-use: invalidate immediately
    _clear_failed_logins(db, user.email)
    db.commit()
