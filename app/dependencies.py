from typing import Annotated

from fastapi import Depends, Request, Response
from jose import JWTError
from sqlalchemy.orm import Session

from app.core import exceptions as exc
from app.core.config import settings
from app.core.security import decode_token
from app.db.session import get_db
from app.models.user import User, UserStatus
from app.services import user_service

DBSession = Annotated[Session, Depends(get_db)]


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get("access_token")
    if not token:
        raise exc.token_invalid()

    try:
        payload = decode_token(token)
    except JWTError:
        raise exc.token_invalid()

    if payload.get("type") != "access":
        raise exc.token_invalid()

    user = user_service.get_by_id(db, int(payload["sub"]))
    if not user:
        raise exc.token_invalid()
    if user.status == UserStatus.locked:
        raise exc.locked_user()
    if user.status == UserStatus.inactive:
        raise exc.inactive_user()
    return user


def get_current_verified_user(user: User = Depends(get_current_user)) -> User:
    if not user.email_verified_at:
        raise exc.email_not_verified()
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
CurrentVerifiedUser = Annotated[User, Depends(get_current_verified_user)]


def set_auth_cookies(response: Response, access_token: str, refresh_token: str) -> None:
    secure = settings.ENVIRONMENT == "production"
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=secure,
        samesite="lax",
        max_age=1800,
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=secure,
        samesite="lax",
        max_age=604800,
    )


def clear_auth_cookies(response: Response) -> None:
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
