"""Tests for all /api/v1/auth/* endpoints."""
from app.models.user import UserStatus
from tests.conftest import (
    DEFAULT_EMAIL,
    DEFAULT_PASSWORD,
    db_expire_verification_code,
    db_get_user,
    db_set_status,
    db_set_verification_code,
    do_login,
    do_register,
    make_token,
)

REGISTER_URL = "/api/v1/auth/register"
LOGIN_URL = "/api/v1/auth/login"
LOGOUT_URL = "/api/v1/auth/logout"
REFRESH_URL = "/api/v1/auth/refresh"
ME_URL = "/api/v1/auth"
VERIFY_URL = "/api/v1/auth/verification"
RECOVERY_URL = "/api/v1/auth/request/password-recovery"
UPDATE_PW_URL = "/api/v1/auth/user/update-password"
UNLOCK_REQ_URL = "/api/v1/auth/request/unlock-user"
UNLOCK_URL = "/api/v1/auth/user/unlock"


# ===========================================================================
# POST /auth/register
# ===========================================================================


class TestRegister:
    def test_success_status_and_cookies(self, client):
        resp = do_register(client)
        assert resp.status_code == 201
        assert "access_token" in resp.cookies
        assert "refresh_token" in resp.cookies

    def test_success_user_fields(self, client):
        resp = do_register(client)
        user = resp.json()["user"]
        assert user["email"] == DEFAULT_EMAIL
        assert user["names"] == "Test"
        assert user["last_names"] == "User"
        assert user["email_verified_at"] is None
        assert user["pep"] is False

    def test_success_assigns_customer_admin_role(self, client):
        resp = do_register(client)
        roles = resp.json()["user"]["roles"]
        assert any(r["name"] == "customer-admin" for r in roles)

    def test_success_with_optional_fields(self, client):
        resp = client.post(
            REGISTER_URL,
            json={
                "names": "Ana",
                "last_names": "Lopez",
                "email": "ana@example.com",
                "password": "password123",
                "phone_number": "+503-1234-5678",
                "country_iso_code": "SV",
            },
        )
        assert resp.status_code == 201
        user = resp.json()["user"]
        assert user["phone_number"] == "+503-1234-5678"
        assert user["country_iso_code"] == "SV"

    def test_duplicate_email(self, client):
        do_register(client)
        resp = do_register(client)
        assert resp.status_code == 409
        assert resp.json()["error_code"] == "already_exists"

    def test_invalid_email_format(self, client):
        resp = client.post(
            REGISTER_URL,
            json={"names": "X", "last_names": "Y", "email": "not-an-email", "password": "password123"},
        )
        assert resp.status_code == 422

    def test_password_too_short(self, client):
        resp = client.post(
            REGISTER_URL,
            json={"names": "X", "last_names": "Y", "email": "x@example.com", "password": "short"},
        )
        assert resp.status_code == 422

    def test_missing_email(self, client):
        resp = client.post(
            REGISTER_URL,
            json={"names": "X", "last_names": "Y", "password": "password123"},
        )
        assert resp.status_code == 422

    def test_missing_names(self, client):
        resp = client.post(
            REGISTER_URL,
            json={"last_names": "Y", "email": "x@example.com", "password": "password123"},
        )
        assert resp.status_code == 422


# ===========================================================================
# POST /auth/login
# ===========================================================================


class TestLogin:
    def test_success_status_and_cookies(self, client):
        do_register(client)
        resp = do_login(client)
        assert resp.status_code == 200
        assert "access_token" in resp.cookies
        assert "refresh_token" in resp.cookies

    def test_success_returns_user(self, client):
        do_register(client)
        resp = do_login(client)
        assert resp.json()["user"]["email"] == DEFAULT_EMAIL

    def test_wrong_password(self, client):
        do_register(client)
        resp = do_login(client, password="wrongpassword")
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "invalid_credentials"

    def test_unknown_email(self, client):
        resp = do_login(client, email="nobody@example.com")
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "invalid_credentials"

    def test_4_failures_do_not_lock(self, client):
        do_register(client)
        for _ in range(4):
            do_login(client, password="wrong")
        resp = do_login(client)
        assert resp.status_code == 200

    def test_5th_failure_locks_account(self, client):
        do_register(client)
        for _ in range(5):
            do_login(client, password="wrong")
        resp = do_login(client)
        assert resp.status_code == 403
        assert resp.json()["error_code"] == "locked_user"

    def test_locked_user_rejected_even_with_correct_password(self, client, db):
        do_register(client)
        db_set_status(db, UserStatus.locked)
        resp = do_login(client)
        assert resp.status_code == 403
        assert resp.json()["error_code"] == "locked_user"

    def test_inactive_user_rejected(self, client, db):
        do_register(client)
        db_set_status(db, UserStatus.inactive)
        resp = do_login(client)
        assert resp.status_code == 403
        assert resp.json()["error_code"] == "inactive_user"

    def test_success_clears_failed_attempts(self, client):
        do_register(client)
        for _ in range(4):
            do_login(client, password="wrong")
        do_login(client)  # success → clears attempts
        for _ in range(4):
            do_login(client, password="wrong")
        # after 4 more bad attempts the account must still allow login
        resp = do_login(client)
        assert resp.status_code == 200


# ===========================================================================
# POST /auth/logout
# ===========================================================================


class TestLogout:
    def test_success_clears_cookies(self, client):
        do_register(client)
        resp = client.post(LOGOUT_URL)
        assert resp.status_code == 200
        assert resp.cookies.get("access_token", "") == ""
        assert resp.cookies.get("refresh_token", "") == ""

    def test_unauthenticated(self, client):
        resp = client.post(LOGOUT_URL)
        assert resp.status_code == 401

    def test_after_logout_me_is_unauthorized(self, client):
        do_register(client)
        client.post(LOGOUT_URL)
        resp = client.get(ME_URL)
        assert resp.status_code == 401


# ===========================================================================
# POST /auth/refresh
# ===========================================================================


class TestRefresh:
    def test_success_sets_new_access_token(self, client):
        do_register(client)
        resp = client.post(REFRESH_URL)
        assert resp.status_code == 200
        assert "access_token" in resp.cookies

    def test_no_cookie_returns_401(self, client):
        resp = client.post(REFRESH_URL)
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "token_invalid"

    def test_garbage_token_returns_401(self, client):
        client.cookies.set("refresh_token", "not.a.jwt.at.all")
        resp = client.post(REFRESH_URL)
        assert resp.status_code == 401

    def test_access_token_used_as_refresh_rejected(self, client, db):
        do_register(client)
        # grab access token and use it in the refresh_token cookie slot
        access = client.cookies.get("access_token")
        client.cookies.set("refresh_token", access)
        # clear access token so the server won't be confused
        client.cookies.delete("access_token")
        resp = client.post(REFRESH_URL)
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "token_invalid"


# ===========================================================================
# GET /auth  (me)
# ===========================================================================


class TestMe:
    def test_authenticated_returns_user(self, client):
        do_register(client)
        resp = client.get(ME_URL)
        assert resp.status_code == 200
        assert resp.json()["user"]["email"] == DEFAULT_EMAIL

    def test_unauthenticated_returns_401(self, client):
        resp = client.get(ME_URL)
        assert resp.status_code == 401

    def test_after_logout_returns_401(self, client):
        do_register(client)
        client.post(LOGOUT_URL)
        resp = client.get(ME_URL)
        assert resp.status_code == 401


# ===========================================================================
# GET /auth/verification  (resend code)
# ===========================================================================


class TestResendVerification:
    def test_success(self, client):
        do_register(client)
        resp = client.get(VERIFY_URL)
        assert resp.status_code == 200
        assert resp.json()["message"] == "Verification code sent."

    def test_unauthenticated(self, client):
        resp = client.get(VERIFY_URL)
        assert resp.status_code == 401


# ===========================================================================
# POST /auth/verification  (verify code)
# ===========================================================================


class TestVerifyEmail:
    def test_success(self, client, db):
        do_register(client)
        db_set_verification_code(db, code="654321")
        resp = client.post(VERIFY_URL, json={"code": "654321"})
        assert resp.status_code == 200
        assert resp.json()["user"]["email_verified_at"] is not None

    def test_wrong_code(self, client):
        do_register(client)
        resp = client.post(VERIFY_URL, json={"code": "000000"})
        assert resp.status_code == 422
        assert resp.json()["error_code"] in ("verification_code_invalid", "verification_code_expired")

    def test_expired_code(self, client, db):
        do_register(client)
        db_expire_verification_code(db)
        resp = client.post(VERIFY_URL, json={"code": "999999"})
        assert resp.status_code == 422
        assert resp.json()["error_code"] == "verification_code_expired"

    def test_unauthenticated(self, client):
        resp = client.post(VERIFY_URL, json={"code": "123456"})
        assert resp.status_code == 401

    def test_code_must_be_6_digits(self, client):
        do_register(client)
        resp = client.post(VERIFY_URL, json={"code": "12345"})  # 5 digits
        assert resp.status_code == 422

    def test_code_must_be_numeric(self, client):
        do_register(client)
        resp = client.post(VERIFY_URL, json={"code": "abcdef"})
        assert resp.status_code == 422


# ===========================================================================
# POST /auth/request/password-recovery
# ===========================================================================


class TestRequestPasswordRecovery:
    def test_known_email_returns_200(self, client):
        do_register(client)
        resp = client.post(RECOVERY_URL, json={"email": DEFAULT_EMAIL})
        assert resp.status_code == 200

    def test_unknown_email_also_returns_200(self, client):
        resp = client.post(RECOVERY_URL, json={"email": "ghost@example.com"})
        assert resp.status_code == 200

    def test_invalid_email_format(self, client):
        resp = client.post(RECOVERY_URL, json={"email": "not-an-email"})
        assert resp.status_code == 422


# ===========================================================================
# POST /auth/user/update-password
# ===========================================================================


class TestUpdatePassword:
    def test_success_can_login_with_new_password(self, client, db):
        do_register(client)
        token = make_token(db, "password_recovery")
        resp = client.post(UPDATE_PW_URL, json={"token": token, "new_password": "newpassword1"})
        assert resp.status_code == 200
        # old password must fail
        r = do_login(client, password=DEFAULT_PASSWORD)
        assert r.status_code == 401
        # new password must succeed
        r = do_login(client, password="newpassword1")
        assert r.status_code == 200

    def test_invalid_token(self, client):
        resp = client.post(UPDATE_PW_URL, json={"token": "bad.token.here", "new_password": "newpassword1"})
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "token_invalid"

    def test_wrong_token_type_rejected(self, client, db):
        do_register(client)
        # unlock token must not work as a recovery token
        wrong_token = make_token(db, "unlock_user")
        resp = client.post(UPDATE_PW_URL, json={"token": wrong_token, "new_password": "newpassword1"})
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "token_invalid"

    def test_new_password_too_short(self, client, db):
        do_register(client)
        token = make_token(db, "password_recovery")
        resp = client.post(UPDATE_PW_URL, json={"token": token, "new_password": "short"})
        assert resp.status_code == 422


# ===========================================================================
# POST /auth/request/unlock-user
# ===========================================================================


class TestRequestUnlock:
    def test_locked_user_returns_200(self, client, db):
        do_register(client)
        db_set_status(db, UserStatus.locked)
        resp = client.post(UNLOCK_REQ_URL, json={"email": DEFAULT_EMAIL})
        assert resp.status_code == 200

    def test_active_user_also_returns_200(self, client):
        do_register(client)
        resp = client.post(UNLOCK_REQ_URL, json={"email": DEFAULT_EMAIL})
        assert resp.status_code == 200

    def test_unknown_email_returns_200(self, client):
        resp = client.post(UNLOCK_REQ_URL, json={"email": "ghost@example.com"})
        assert resp.status_code == 200

    def test_invalid_email_format(self, client):
        resp = client.post(UNLOCK_REQ_URL, json={"email": "not-email"})
        assert resp.status_code == 422


# ===========================================================================
# POST /auth/user/unlock
# ===========================================================================


class TestUnlockUser:
    def test_success_allows_login(self, client, db):
        do_register(client)
        db_set_status(db, UserStatus.locked)
        token = make_token(db, "unlock_user")
        resp = client.post(UNLOCK_URL, json={"token": token})
        assert resp.status_code == 200
        # user can now login
        r = do_login(client)
        assert r.status_code == 200

    def test_success_resets_failed_login_counter(self, client, db):
        do_register(client)
        # lock via 5 failures
        for _ in range(5):
            do_login(client, password="wrong")
        token = make_token(db, "unlock_user")
        client.post(UNLOCK_URL, json={"token": token})
        # 4 more failures after unlock must NOT lock
        for _ in range(4):
            do_login(client, password="wrong")
        resp = do_login(client)
        assert resp.status_code == 200

    def test_invalid_token(self, client):
        resp = client.post(UNLOCK_URL, json={"token": "garbage.token.here"})
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "token_invalid"

    def test_wrong_token_type_rejected(self, client, db):
        do_register(client)
        wrong_token = make_token(db, "password_recovery")
        resp = client.post(UNLOCK_URL, json={"token": wrong_token})
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "token_invalid"
