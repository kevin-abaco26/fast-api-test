from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.status import (
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN,
    HTTP_404_NOT_FOUND,
    HTTP_409_CONFLICT,
)


class AppException(Exception):
    def __init__(self, status_code: int, error_code: str, message: str = ""):
        self.status_code = status_code
        self.error_code = error_code
        self.message = message
        super().__init__(message)


# Auth errors
def invalid_credentials() -> AppException:
    return AppException(HTTP_401_UNAUTHORIZED, "invalid_credentials", "Invalid email or password.")


def token_invalid() -> AppException:
    return AppException(HTTP_401_UNAUTHORIZED, "token_invalid", "Authentication token is invalid.")


def token_expired() -> AppException:
    return AppException(HTTP_401_UNAUTHORIZED, "token_expired", "Authentication token has expired.")


def locked_user() -> AppException:
    return AppException(HTTP_403_FORBIDDEN, "locked_user", "Account is locked.")


def inactive_user() -> AppException:
    return AppException(HTTP_403_FORBIDDEN, "inactive_user", "Account is inactive.")


def email_not_verified() -> AppException:
    return AppException(HTTP_403_FORBIDDEN, "email_not_verified", "Email address is not verified.")


def role_access_forbidden() -> AppException:
    return AppException(HTTP_403_FORBIDDEN, "role_access_forbidden", "Insufficient role.")


def resource_access_forbidden() -> AppException:
    return AppException(HTTP_403_FORBIDDEN, "resource_access_forbidden", "Insufficient permissions.")


# Validation errors
def verification_code_invalid() -> AppException:
    return AppException(422, "verification_code_invalid", "Invalid verification code.")


def verification_code_expired() -> AppException:
    return AppException(422, "verification_code_expired", "Verification code has expired.")


# Resource errors
def not_found(resource: str = "Resource") -> AppException:
    return AppException(HTTP_404_NOT_FOUND, "not_found", f"{resource} not found.")


def already_exists(resource: str = "Resource") -> AppException:
    return AppException(HTTP_409_CONFLICT, "already_exists", f"{resource} already exists.")


def register_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppException)
    async def app_exception_handler(request: Request, exc: AppException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error_code": exc.error_code, "message": exc.message},
        )
