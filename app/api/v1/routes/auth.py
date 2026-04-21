from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.core import exceptions as exc
from app.core.config import settings
from app.core.security import decode_token
from app.db.session import get_db
from app.dependencies import CurrentUser, clear_auth_cookies, set_auth_cookies
from app.schemas.auth import (
    LoginRequest,
    MessageResponse,
    PasswordRecoveryRequest,
    RegisterRequest,
    UnlockUserRequest,
    UpdatePasswordRequest,
    VerifyCodeRequest,
)
from app.schemas.user import UserOut, UserSessionInfo
from app.services import auth_service

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=UserSessionInfo)
def login(body: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else None
    access, refresh = auth_service.login(db, email=body.email, password=body.password, ip_address=ip)
    set_auth_cookies(response, access, refresh)
    from app.services.user_service import get_by_email
    user = get_by_email(db, body.email)
    return UserSessionInfo(user=UserOut.model_validate(user))


@router.post("/logout", response_model=MessageResponse)
def logout(response: Response, _: CurrentUser):
    clear_auth_cookies(response)
    return MessageResponse(message="Logged out.")


@router.post("/refresh", response_model=MessageResponse)
def refresh(request: Request, response: Response, db: Session = Depends(get_db)):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise exc.token_invalid()
    access = auth_service.refresh_access_token(db, refresh_token=refresh_token)
    response.set_cookie(
        key="access_token",
        value=access,
        httponly=True,
        secure=settings.ENVIRONMENT == "production",
        samesite="lax",
        max_age=1800,
    )
    return MessageResponse(message="Token refreshed.")


@router.post("/register", response_model=UserSessionInfo, status_code=201)
def register(body: RegisterRequest, response: Response, db: Session = Depends(get_db)):
    user, access, refresh = auth_service.register(db, data=body)
    set_auth_cookies(response, access, refresh)
    return UserSessionInfo(user=UserOut.model_validate(user))


@router.get("", response_model=UserSessionInfo)
def me(current_user: CurrentUser):
    return UserSessionInfo(user=UserOut.model_validate(current_user))


@router.post("/verification", response_model=UserSessionInfo)
def verify_email(body: VerifyCodeRequest, current_user: CurrentUser, db: Session = Depends(get_db)):
    user = auth_service.verify_email(db, user=current_user, code=body.code)
    return UserSessionInfo(user=UserOut.model_validate(user))


@router.get("/verification", response_model=MessageResponse)
def resend_verification(current_user: CurrentUser, db: Session = Depends(get_db)):
    auth_service.resend_verification(db, user=current_user)
    return MessageResponse(message="Verification code sent.")


@router.post("/request/password-recovery", response_model=MessageResponse)
def request_password_recovery(body: PasswordRecoveryRequest, db: Session = Depends(get_db)):
    auth_service.request_password_recovery(db, email=body.email)
    return MessageResponse(message="If the account exists, a recovery email has been sent.")


@router.post("/user/update-password", response_model=MessageResponse)
def update_password(body: UpdatePasswordRequest, db: Session = Depends(get_db)):
    auth_service.update_password(db, recovery_token=body.token, new_password=body.new_password)
    return MessageResponse(message="Password updated.")


@router.post("/request/unlock-user", response_model=MessageResponse)
def request_unlock(body: PasswordRecoveryRequest, db: Session = Depends(get_db)):
    auth_service.request_unlock(db, email=body.email)
    return MessageResponse(message="If the account is locked, an unlock email has been sent.")


@router.post("/user/unlock", response_model=MessageResponse)
def unlock_user(body: UnlockUserRequest, db: Session = Depends(get_db)):
    auth_service.unlock_user(db, unlock_token=body.token)
    return MessageResponse(message="Account unlocked.")
