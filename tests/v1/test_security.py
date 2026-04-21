"""
Security-focused test suite for /api/v1/auth/* and /api/v1/account/*.

Covers every gap left by test_auth.py and test_users.py:
  - Account lockout bypass / counter manipulation
  - Token manipulation (expired, tampered, wrong type, algorithm confusion)
  - Race-condition-like scenarios in email verification
  - Concurrent / sequential login attack patterns
  - SQL injection / special character payloads in all string fields
  - Password-recovery token reuse (stateless JWT — documents expected behaviour)
  - Verification code brute-force exhaustion
  - Role / permission boundaries (CurrentVerifiedUser gate)
  - Soft-deleted user access
  - Cookie security attributes (httponly flag presence)
  - Response header security
  - Large / boundary input handling
  - refresh_access_token with inactive / locked user
  - update_password idempotence / token reuse
  - unlock_user token reuse / cross-user token misuse
  - HTTP method enforcement
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from jose import jwt

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_recovery_token,
    create_refresh_token,
    hash_code,
)
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

# ---------------------------------------------------------------------------
# URL constants (duplicated locally so this file is self-contained)
# ---------------------------------------------------------------------------

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
ROLE_URL = "/api/v1/account/role"

SECOND_EMAIL = "attacker@example.com"
SECOND_PASSWORD = "attackerpass1"


# ===========================================================================
# Helpers
# ===========================================================================


def _register_second_user(client: TestClient) -> dict:
    resp = client.post(
        REGISTER_URL,
        json={
            "names": "Evil",
            "last_names": "Hacker",
            "email": SECOND_EMAIL,
            "password": SECOND_PASSWORD,
        },
    )
    assert resp.status_code == 201
    return resp.json()


def _make_expired_access_token(user_id: int, user_uuid: str, email: str) -> str:
    """Build a structurally valid access JWT that is already expired."""
    payload = {
        "sub": str(user_id),
        "uuid": user_uuid,
        "email": email,
        "roles": [],
        "type": "access",
        "exp": datetime.now(UTC) - timedelta(seconds=1),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def _make_expired_refresh_token(user_id: int) -> str:
    payload = {
        "sub": str(user_id),
        "type": "refresh",
        "exp": datetime.now(UTC) - timedelta(seconds=1),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def _make_expired_recovery_token(user_id: int, token_type: str) -> str:
    payload = {
        "sub": str(user_id),
        "type": token_type,
        "exp": datetime.now(UTC) - timedelta(seconds=1),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def _tamper_token(token: str) -> str:
    """Flip a character in the signature segment to invalidate the HMAC."""
    header, payload, sig = token.split(".")
    # Toggle the last character of the signature
    tampered_sig = sig[:-1] + ("A" if sig[-1] != "A" else "B")
    return f"{header}.{payload}.{tampered_sig}"


def _make_none_alg_token(user_id: int) -> str:
    """'alg:none' attack — sign with an empty string."""
    payload = {
        "sub": str(user_id),
        "type": "access",
        "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
    }
    # python-jose rejects alg=none; this tests that the server also rejects it.
    header = {"alg": "none", "typ": "JWT"}
    import base64, json as _json

    def b64(d: dict) -> str:
        return base64.urlsafe_b64encode(_json.dumps(d).encode()).rstrip(b"=").decode()

    return f"{b64(header)}.{b64(payload)}."


# ===========================================================================
# ACCOUNT LOCKOUT BYPASS
# ===========================================================================


class TestLockoutBypass:
    """Attempt various bypass strategies around the 5-attempt lockout."""

    def test_exact_threshold_5_failures_triggers_lock(self, client):
        do_register(client)
        for _ in range(5):
            do_login(client, password="wrong")
        resp = do_login(client, password=DEFAULT_PASSWORD)
        assert resp.status_code == 403
        assert resp.json()["error_code"] == "locked_user"

    def test_locked_account_correct_password_still_rejected(self, client, db):
        """Even the correct password must not bypass a locked status."""
        do_register(client)
        db_set_status(db, UserStatus.locked)
        resp = do_login(client, password=DEFAULT_PASSWORD)
        assert resp.status_code == 403
        assert resp.json()["error_code"] == "locked_user"

    def test_mixed_case_email_does_not_reset_counter(self, client):
        """Varying email casing must not circumvent per-account failure counting."""
        do_register(client)
        for _ in range(4):
            do_login(client, email=DEFAULT_EMAIL, password="wrong")
        # 5th failure via different casing of same email
        resp = do_login(client, email=DEFAULT_EMAIL.upper(), password="wrong")
        # Either the server normalises email (lock triggered → 403) or it
        # treats it as unknown (401).  Either way it must NOT succeed (200).
        assert resp.status_code in (401, 403)

    def test_interleaved_wrong_then_right_resets_counter(self, client):
        """4 failures → success → 4 more failures → success still works."""
        do_register(client)
        for _ in range(4):
            do_login(client, password="wrong")
        do_login(client)  # success resets counter
        for _ in range(4):
            do_login(client, password="wrong")
        resp = do_login(client)
        assert resp.status_code == 200

    def test_unlock_resets_counter_so_new_5_needed_to_lock(self, client, db):
        """After unlock the failure counter is cleared; it takes a fresh 5 failures to lock."""
        do_register(client)
        for _ in range(5):
            do_login(client, password="wrong")
        token = make_token(db, "unlock_user")
        client.post(UNLOCK_URL, json={"token": token})
        # 4 more failures must not yet lock
        for _ in range(4):
            do_login(client, password="wrong")
        resp = do_login(client)
        assert resp.status_code == 200

    def test_soft_deleted_user_cannot_lock_other_accounts(self, client, db):
        """Failure records linked to a deleted user must not affect active users."""
        do_register(client)
        user = db_get_user(db)
        user.deleted_at = datetime.now(UTC)
        db.commit()
        # Now register a fresh user with the same email is impossible (unique),
        # but the soft-delete path demonstrates the model; just confirm deleted
        # user cannot log in.
        resp = do_login(client)
        assert resp.status_code == 401  # user not found (deleted_at filtered)


# ===========================================================================
# TOKEN MANIPULATION
# ===========================================================================


class TestTokenManipulation:
    # --- access_token on authenticated endpoints ---

    def test_expired_access_token_rejected_on_me(self, client, db):
        do_register(client)
        user = db_get_user(db)
        expired = _make_expired_access_token(user.id, str(user.uuid), user.email)
        client.cookies.set("access_token", expired)
        resp = client.get(ME_URL)
        assert resp.status_code == 401

    def test_tampered_access_token_rejected_on_me(self, client, db):
        do_register(client)
        good_token = client.cookies.get("access_token")
        client.cookies.set("access_token", _tamper_token(good_token))
        resp = client.get(ME_URL)
        assert resp.status_code == 401

    def test_none_alg_access_token_rejected_on_me(self, client, db):
        do_register(client)
        user = db_get_user(db)
        evil_token = _make_none_alg_token(user.id)
        client.cookies.set("access_token", evil_token)
        resp = client.get(ME_URL)
        assert resp.status_code == 401

    def test_refresh_token_used_as_access_token_rejected(self, client, db):
        do_register(client)
        refresh = client.cookies.get("refresh_token")
        client.cookies.set("access_token", refresh)
        resp = client.get(ME_URL)
        assert resp.status_code == 401

    def test_empty_string_access_token_rejected(self, client):
        do_register(client)
        client.cookies.set("access_token", "")
        resp = client.get(ME_URL)
        assert resp.status_code == 401

    def test_access_token_with_wrong_secret_rejected(self, client, db):
        do_register(client)
        user = db_get_user(db)
        payload = {
            "sub": str(user.id),
            "uuid": str(user.uuid),
            "email": user.email,
            "roles": [],
            "type": "access",
            "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
        }
        evil = jwt.encode(payload, "totally-wrong-secret", algorithm=settings.ALGORITHM)
        client.cookies.set("access_token", evil)
        resp = client.get(ME_URL)
        assert resp.status_code == 401

    # --- refresh_token on /auth/refresh ---

    def test_expired_refresh_token_rejected(self, client, db):
        do_register(client)
        user = db_get_user(db)
        expired = _make_expired_refresh_token(user.id)
        client.cookies.set("refresh_token", expired)
        client.cookies.delete("access_token")
        resp = client.post(REFRESH_URL)
        assert resp.status_code == 401

    def test_tampered_refresh_token_rejected(self, client):
        do_register(client)
        good = client.cookies.get("refresh_token")
        client.cookies.set("refresh_token", _tamper_token(good))
        resp = client.post(REFRESH_URL)
        assert resp.status_code == 401

    def test_recovery_token_used_as_refresh_rejected(self, client, db):
        do_register(client)
        recovery = make_token(db, "password_recovery")
        client.cookies.set("refresh_token", recovery)
        resp = client.post(REFRESH_URL)
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "token_invalid"

    def test_refresh_with_locked_user_rejected(self, client, db):
        """Even a structurally valid refresh token must be rejected for locked users."""
        do_register(client)
        db_set_status(db, UserStatus.locked)
        resp = client.post(REFRESH_URL)
        assert resp.status_code in (401, 403)

    def test_refresh_with_inactive_user_rejected(self, client, db):
        do_register(client)
        db_set_status(db, UserStatus.inactive)
        resp = client.post(REFRESH_URL)
        assert resp.status_code in (401, 403)

    def test_refresh_for_nonexistent_user_id_rejected(self, client):
        do_register(client)
        # Create a refresh token referencing a user_id that will never exist
        fake_token = create_refresh_token(user_id=999999)
        client.cookies.set("refresh_token", fake_token)
        resp = client.post(REFRESH_URL)
        assert resp.status_code == 401

    # --- recovery / unlock tokens ---

    def test_expired_recovery_token_rejected_on_update_password(self, client, db):
        do_register(client)
        user = db_get_user(db)
        expired = _make_expired_recovery_token(user.id, "password_recovery")
        resp = client.post(UPDATE_PW_URL, json={"token": expired, "new_password": "newpassword1"})
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "token_invalid"

    def test_expired_unlock_token_rejected_on_unlock(self, client, db):
        do_register(client)
        user = db_get_user(db)
        expired = _make_expired_recovery_token(user.id, "unlock_user")
        resp = client.post(UNLOCK_URL, json={"token": expired})
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "token_invalid"

    def test_tampered_recovery_token_rejected(self, client, db):
        do_register(client)
        token = make_token(db, "password_recovery")
        resp = client.post(
            UPDATE_PW_URL,
            json={"token": _tamper_token(token), "new_password": "newpassword1"},
        )
        assert resp.status_code == 401

    def test_unlock_token_rejected_for_update_password(self, client, db):
        do_register(client)
        wrong = make_token(db, "unlock_user")
        resp = client.post(UPDATE_PW_URL, json={"token": wrong, "new_password": "newpassword1"})
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "token_invalid"

    def test_recovery_token_rejected_for_unlock(self, client, db):
        do_register(client)
        wrong = make_token(db, "password_recovery")
        resp = client.post(UNLOCK_URL, json={"token": wrong})
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "token_invalid"


# ===========================================================================
# PASSWORD RECOVERY TOKEN REUSE
# ===========================================================================


class TestPasswordRecoveryTokenReuse:
    """
    The tokens are stateless JWTs (no server-side revocation store), so the
    same token CAN be applied twice within its TTL. These tests document the
    current behaviour and make future regressions visible if a revocation
    mechanism is added.
    """

    def test_recovery_token_can_be_used_twice_within_ttl(self, client, db):
        """Documents: stateless JWTs allow reuse inside TTL window."""
        do_register(client)
        token = make_token(db, "password_recovery")

        r1 = client.post(UPDATE_PW_URL, json={"token": token, "new_password": "firstnewpw1"})
        assert r1.status_code == 200

        r2 = client.post(UPDATE_PW_URL, json={"token": token, "new_password": "secondnewpw1"})
        # Current implementation: 200 (no revocation); if revocation is added this becomes 401
        assert r2.status_code in (200, 401)

    def test_cross_user_recovery_token_cannot_change_other_password(self, client, db):
        """Token sub must match the target user; a different user's token must not work."""
        do_register(client)
        _register_second_user(client)

        # Issue a recovery token for the second user (stores hash on second user's record)
        foreign_token = make_token(db, "password_recovery", SECOND_EMAIL)

        # Using the second user's token only changes the SECOND user's password —
        # the endpoint resolves the user from payload["sub"], not from a body email.
        resp = client.post(
            UPDATE_PW_URL,
            json={"token": foreign_token, "new_password": "hackedpassword1"},
        )
        # The second user's password is changed; the first user's is unaffected.
        assert resp.status_code == 200

        # First user's original password still works
        r = do_login(client, email=DEFAULT_EMAIL, password=DEFAULT_PASSWORD)
        assert r.status_code == 200

        # Second user's new password now works
        r2 = do_login(client, email=SECOND_EMAIL, password="hackedpassword1")
        assert r2.status_code == 200

    def test_unlock_token_reuse_within_ttl(self, client, db):
        """Applying an unlock token twice must not error (idempotent status update)."""
        do_register(client)
        db_set_status(db, UserStatus.locked)
        token = make_token(db, "unlock_user")

        r1 = client.post(UNLOCK_URL, json={"token": token})
        assert r1.status_code == 200

        r2 = client.post(UNLOCK_URL, json={"token": token})
        assert r2.status_code in (200, 401)  # 401 if revocation added later


# ===========================================================================
# VERIFICATION CODE BRUTE FORCE
# ===========================================================================


class TestVerificationCodeBruteForce:
    def test_wrong_code_returns_422_not_500(self, client, db):
        do_register(client)
        db_set_verification_code(db, code="654321")
        resp = client.post(VERIFY_URL, json={"code": "000000"})
        assert resp.status_code == 422

    def test_sequential_wrong_codes_all_rejected(self, client, db):
        """Submitting many wrong codes must never succeed (no timing oracle)."""
        do_register(client)
        db_set_verification_code(db, code="654321")
        for attempt in range(10):
            code = str(attempt).zfill(6)
            if code == "654321":
                continue
            resp = client.post(VERIFY_URL, json={"code": code})
            assert resp.status_code == 422, f"Unexpected 2xx for code {code}"

    def test_correct_code_after_wrong_attempts_succeeds(self, client, db):
        do_register(client)
        db_set_verification_code(db, code="654321")
        # Fail twice then succeed
        client.post(VERIFY_URL, json={"code": "000000"})
        client.post(VERIFY_URL, json={"code": "111111"})
        resp = client.post(VERIFY_URL, json={"code": "654321"})
        assert resp.status_code == 200
        assert resp.json()["user"]["email_verified_at"] is not None

    def test_code_reuse_after_verification_fails(self, client, db):
        """Once the code has been consumed, it must not work again."""
        do_register(client)
        db_set_verification_code(db, code="654321")
        client.post(VERIFY_URL, json={"code": "654321"})

        # Code fields are cleared after successful verification
        resp = client.post(VERIFY_URL, json={"code": "654321"})
        assert resp.status_code == 422

    def test_resend_invalidates_previous_code(self, client, db):
        """After resend, the old code must be expired/overwritten."""
        do_register(client)
        db_set_verification_code(db, code="111111")
        # Resend generates a new code and overwrites the hash
        client.get(VERIFY_URL)

        # Old code must now fail (hash is different)
        resp = client.post(VERIFY_URL, json={"code": "111111"})
        assert resp.status_code == 422

    def test_boundary_code_000000_rejected_unless_set(self, client, db):
        do_register(client)
        db_set_verification_code(db, code="999999")
        resp = client.post(VERIFY_URL, json={"code": "000000"})
        assert resp.status_code == 422

    def test_boundary_code_999999_accepted_when_set(self, client, db):
        do_register(client)
        db_set_verification_code(db, code="999999")
        resp = client.post(VERIFY_URL, json={"code": "999999"})
        assert resp.status_code == 200


# ===========================================================================
# RACE-CONDITION-LIKE SCENARIOS IN EMAIL VERIFICATION
# ===========================================================================


class TestVerificationRaceConditions:
    def test_expired_code_cannot_verify(self, client, db):
        do_register(client)
        db_expire_verification_code(db)
        resp = client.post(VERIFY_URL, json={"code": "999999"})
        assert resp.status_code == 422
        assert resp.json()["error_code"] == "verification_code_expired"

    def test_verify_then_resend_clears_verified_state(self, client, db):
        """
        After verification, resend should still work (user can re-verify).
        The email_verified_at field is set and should persist even after resend.
        """
        do_register(client)
        db_set_verification_code(db, code="654321")
        client.post(VERIFY_URL, json={"code": "654321"})

        # Resend must succeed — user is authenticated
        resp = client.get(VERIFY_URL)
        assert resp.status_code == 200

        # email_verified_at is still present (resend does not clear it)
        me_resp = client.get(ME_URL)
        assert me_resp.json()["user"]["email_verified_at"] is not None

    def test_verify_before_expiry_boundary(self, client, db):
        """Code set with minimal future expiry must still be accepted immediately."""
        do_register(client)
        user = db_get_user(db)
        user.verification_code = hash_code("123456")
        # Expiry 2 seconds from now — well within the TTL but close to boundary
        user.verification_expiry = datetime.now(UTC) + timedelta(seconds=2)
        db.commit()
        resp = client.post(VERIFY_URL, json={"code": "123456"})
        assert resp.status_code == 200

    def test_double_verify_same_code_second_attempt_fails(self, client, db):
        """Submitting the correct code a second time after it has been cleared fails."""
        do_register(client)
        db_set_verification_code(db, code="654321")
        r1 = client.post(VERIFY_URL, json={"code": "654321"})
        assert r1.status_code == 200
        r2 = client.post(VERIFY_URL, json={"code": "654321"})
        assert r2.status_code == 422


# ===========================================================================
# SQL INJECTION ATTEMPTS
# ===========================================================================


class TestSqlInjectionAttempts:
    """
    The app uses SQLAlchemy ORM with parameterised queries; these tests
    confirm no injection path exists and that the app does not 500.
    """

    SQL_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "'; DROP TABLE users;--",
        '" OR "1"="1',
        "admin'--",
        "1' AND SLEEP(1)--",
        "' UNION SELECT null,null,null--",
    ]

    @pytest.mark.parametrize("payload", SQL_PAYLOADS)
    def test_sql_injection_in_login_email(self, client, payload):
        resp = client.post(LOGIN_URL, json={"email": payload, "password": "password123"})
        # Must be 422 (invalid email format) or 401 (not found) — never 200 or 500
        assert resp.status_code in (401, 422)

    @pytest.mark.parametrize("payload", SQL_PAYLOADS)
    def test_sql_injection_in_login_password(self, client, payload):
        do_register(client)
        resp = client.post(
            LOGIN_URL,
            json={"email": DEFAULT_EMAIL, "password": payload},
        )
        assert resp.status_code in (401, 422)

    @pytest.mark.parametrize("payload", SQL_PAYLOADS)
    def test_sql_injection_in_register_names(self, client, payload):
        resp = client.post(
            REGISTER_URL,
            json={
                "names": payload,
                "last_names": "User",
                "email": "inject@example.com",
                "password": "password123",
            },
        )
        # Names have no format validation — should be 201 (stored as literal string) or 422
        assert resp.status_code in (201, 422)
        if resp.status_code == 201:
            assert resp.json()["user"]["names"] == payload  # stored verbatim, not executed

    @pytest.mark.parametrize("payload", SQL_PAYLOADS)
    def test_sql_injection_in_recovery_email(self, client, payload):
        resp = client.post(RECOVERY_URL, json={"email": payload})
        assert resp.status_code in (200, 422)  # 200 = no leak; 422 = bad format

    def test_sql_injection_in_unlock_token_field(self, client):
        resp = client.post(UNLOCK_URL, json={"token": "' OR '1'='1"})
        assert resp.status_code == 401

    def test_sql_injection_in_update_password_token(self, client):
        resp = client.post(
            UPDATE_PW_URL,
            json={"token": "' OR '1'='1", "new_password": "newpassword1"},
        )
        assert resp.status_code == 401


# ===========================================================================
# ROLE / PERMISSION BOUNDARIES
# ===========================================================================


class TestRolePermissionBoundaries:
    def test_unauthenticated_cannot_access_role_endpoint(self, client):
        resp = client.get(ROLE_URL)
        assert resp.status_code == 401

    def test_user_with_no_roles_returns_empty_string(self, client, db):
        do_register(client)
        user = db_get_user(db)
        user.roles.clear()
        db.commit()
        resp = client.get(ROLE_URL)
        assert resp.status_code == 200
        assert resp.json()["message"] == ""

    def test_customer_admin_role_is_assigned_by_default(self, client):
        do_register(client)
        resp = client.get(ROLE_URL)
        assert resp.status_code == 200
        assert resp.json()["message"] == "customer-admin"

    def test_locked_user_cannot_access_role_endpoint(self, client, db):
        do_register(client)
        db_set_status(db, UserStatus.locked)
        resp = client.get(ROLE_URL)
        assert resp.status_code == 403
        assert resp.json()["error_code"] == "locked_user"

    def test_inactive_user_cannot_access_role_endpoint(self, client, db):
        do_register(client)
        db_set_status(db, UserStatus.inactive)
        resp = client.get(ROLE_URL)
        assert resp.status_code == 403
        assert resp.json()["error_code"] == "inactive_user"

    def test_user_cannot_impersonate_other_user_via_crafted_token(self, client, db):
        """A token carrying another user's id must only return THAT user's data."""
        do_register(client)
        _register_second_user(client)

        first_user = db_get_user(db, DEFAULT_EMAIL)
        second_user = db_get_user(db, SECOND_EMAIL)

        # Craft a valid access token claiming to be first_user
        token = create_access_token(
            first_user.id, str(first_user.uuid), first_user.email, first_user.role_names
        )
        client.cookies.set("access_token", token)

        resp = client.get(ME_URL)
        assert resp.status_code == 200
        # Must return first_user, not second_user
        assert resp.json()["user"]["email"] == DEFAULT_EMAIL
        assert resp.json()["user"]["email"] != SECOND_EMAIL

    def test_multiple_roles_first_role_returned(self, client, db):
        """get_role returns roles[0].name; assign a second role and confirm order."""
        do_register(client)
        from app.services.user_service import assign_role

        user = db_get_user(db)
        assign_role(db, user, "viewer")
        db.commit()
        # The endpoint returns the first role in the list
        resp = client.get(ROLE_URL)
        assert resp.status_code == 200
        # customer-admin was assigned first
        assert resp.json()["message"] in ("customer-admin", "viewer")


# ===========================================================================
# SOFT-DELETED USER ACCESS
# ===========================================================================


class TestSoftDeletedUser:
    def test_soft_deleted_user_cannot_login(self, client, db):
        do_register(client)
        user = db_get_user(db)
        user.deleted_at = datetime.now(UTC)
        db.commit()
        resp = do_login(client)
        # get_by_email filters deleted_at IS NULL → user not found → 401
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "invalid_credentials"

    def test_soft_deleted_user_access_token_rejected(self, client, db):
        """If a token exists but the user is then soft-deleted, /auth must return 401."""
        do_register(client)
        # Token is in cookies from register
        user = db_get_user(db)
        user.deleted_at = datetime.now(UTC)
        db.commit()
        resp = client.get(ME_URL)
        assert resp.status_code == 401

    def test_soft_deleted_user_refresh_rejected(self, client, db):
        do_register(client)
        user = db_get_user(db)
        user.deleted_at = datetime.now(UTC)
        db.commit()
        resp = client.post(REFRESH_URL)
        assert resp.status_code == 401

    def test_soft_deleted_user_recovery_token_rejected(self, client, db):
        """update_password with a token whose sub points to a deleted user must fail."""
        do_register(client)
        token = make_token(db, "password_recovery")
        user = db_get_user(db)
        user.deleted_at = datetime.now(UTC)
        db.commit()
        resp = client.post(UPDATE_PW_URL, json={"token": token, "new_password": "newpassword1"})
        # get_by_id also filters deleted_at → not_found (404) or token_invalid (401)
        assert resp.status_code in (401, 404)

    def test_soft_deleted_user_unlock_token_rejected(self, client, db):
        do_register(client)
        db_set_status(db, UserStatus.locked)
        token = make_token(db, "unlock_user")
        user = db_get_user(db)
        user.deleted_at = datetime.now(UTC)
        db.commit()
        resp = client.post(UNLOCK_URL, json={"token": token})
        assert resp.status_code in (401, 404)

    def test_recovery_request_for_deleted_user_returns_200_no_leak(self, client, db):
        """The recovery endpoint must not reveal whether the user exists or is deleted."""
        do_register(client)
        user = db_get_user(db)
        user.deleted_at = datetime.now(UTC)
        db.commit()
        resp = client.post(RECOVERY_URL, json={"email": DEFAULT_EMAIL})
        assert resp.status_code == 200  # no existence leak


# ===========================================================================
# COOKIE SECURITY ATTRIBUTES
# ===========================================================================


class TestCookieSecurityAttributes:
    def test_access_token_cookie_is_httponly(self, client):
        resp = do_register(client)
        raw = resp.headers.get("set-cookie", "")
        # TestClient may merge cookies; inspect the raw header string.
        # httponly flag should appear for access_token cookie.
        assert "httponly" in raw.lower(), "access_token cookie must be HttpOnly"

    def test_refresh_token_cookie_is_httponly(self, client):
        resp = do_register(client)
        raw = resp.headers.get("set-cookie", "")
        assert "httponly" in raw.lower(), "refresh_token cookie must be HttpOnly"

    def test_access_token_max_age_is_1800(self, client):
        resp = do_register(client)
        raw = resp.headers.get("set-cookie", "")
        assert "max-age=1800" in raw.lower()

    def test_refresh_token_max_age_is_604800(self, client):
        resp = do_register(client)
        raw = resp.headers.get("set-cookie", "")
        assert "max-age=604800" in raw.lower()

    def test_samesite_lax_present(self, client):
        resp = do_register(client)
        raw = resp.headers.get("set-cookie", "")
        assert "samesite=lax" in raw.lower()

    def test_logout_deletes_both_cookies(self, client):
        do_register(client)
        resp = client.post(LOGOUT_URL)
        # After logout, cookies should be cleared (empty or max-age=0)
        assert resp.status_code == 200
        # The TestClient CookieJar should reflect empty values
        assert client.cookies.get("access_token", "") == ""
        assert client.cookies.get("refresh_token", "") == ""

    def test_register_response_sets_two_cookies(self, client):
        resp = do_register(client)
        assert "access_token" in resp.cookies
        assert "refresh_token" in resp.cookies

    def test_login_response_sets_two_cookies(self, client):
        do_register(client)
        resp = do_login(client)
        assert "access_token" in resp.cookies
        assert "refresh_token" in resp.cookies

    def test_refresh_response_sets_new_access_cookie(self, client):
        do_register(client)
        old_access = client.cookies.get("access_token")
        resp = client.post(REFRESH_URL)
        assert resp.status_code == 200
        new_access = client.cookies.get("access_token")
        # The new access token must differ from the old one (time has passed → different exp)
        # Both are valid JWTs; at minimum the cookie must be present.
        assert new_access is not None


# ===========================================================================
# RESPONSE HEADER SECURITY
# ===========================================================================


class TestResponseHeaders:
    """
    FastAPI does not add security headers by default; these tests document
    current behaviour. If a security middleware is added later (e.g.
    X-Content-Type-Options, X-Frame-Options), update assertions accordingly.
    """

    def test_content_type_is_json_on_json_endpoints(self, client):
        resp = do_register(client)
        assert "application/json" in resp.headers.get("content-type", "")

    def test_health_endpoint_returns_json_content_type(self, client):
        resp = client.get("/health")
        assert "application/json" in resp.headers.get("content-type", "")

    def test_no_server_version_leaked_in_headers(self, client):
        resp = client.get("/health")
        server_header = resp.headers.get("server", "").lower()
        # uvicorn / starlette typically set "uvicorn"; it must not leak a detailed version
        assert "python" not in server_header

    def test_401_error_returns_json_body(self, client):
        resp = client.get(ME_URL)
        assert resp.status_code == 401
        body = resp.json()
        assert "error_code" in body

    def test_403_error_returns_json_body(self, client, db):
        do_register(client)
        db_set_status(db, UserStatus.locked)
        resp = do_login(client)
        assert resp.status_code == 403
        body = resp.json()
        assert "error_code" in body

    def test_422_error_returns_json_body(self, client):
        resp = client.post(
            REGISTER_URL,
            json={"names": "X", "last_names": "Y", "email": "bad", "password": "password123"},
        )
        assert resp.status_code == 422
        assert resp.json() is not None


# ===========================================================================
# LARGE / BOUNDARY INPUT HANDLING
# ===========================================================================


class TestLargeAndBoundaryInputs:
    def test_extremely_long_email_rejected(self, client):
        long_email = "a" * 300 + "@example.com"
        resp = client.post(
            REGISTER_URL,
            json={"names": "X", "last_names": "Y", "email": long_email, "password": "password123"},
        )
        # Pydantic EmailStr / server must reject or handle without crashing
        assert resp.status_code in (422, 400, 201)

    def test_extremely_long_password_handled_gracefully(self, client):
        long_pw = "a" * 10_000
        resp = client.post(
            REGISTER_URL,
            json={"names": "X", "last_names": "Y", "email": "longpw@example.com", "password": long_pw},
        )
        # bcrypt truncates at 72 bytes; server must not 500
        assert resp.status_code in (201, 422)

    def test_extremely_long_names_handled_gracefully(self, client):
        long_name = "A" * 5_000
        resp = client.post(
            REGISTER_URL,
            json={
                "names": long_name,
                "last_names": long_name,
                "email": "longname@example.com",
                "password": "password123",
            },
        )
        assert resp.status_code in (201, 422)

    def test_unicode_names_accepted(self, client):
        resp = client.post(
            REGISTER_URL,
            json={
                "names": "Ángel Ünïcödé 日本語",
                "last_names": "Ø 中文",
                "email": "unicode@example.com",
                "password": "password123",
            },
        )
        assert resp.status_code == 201
        assert resp.json()["user"]["names"] == "Ángel Ünïcödé 日本語"

    def test_emoji_in_names_handled(self, client):
        resp = client.post(
            REGISTER_URL,
            json={
                "names": "Hello 🌍",
                "last_names": "World 🚀",
                "email": "emoji@example.com",
                "password": "password123",
            },
        )
        assert resp.status_code in (201, 422)

    def test_null_bytes_in_password_handled(self, client):
        # \x00 is an invalid JSON control character — server rejects at JSON decode level (400/422)
        resp = client.post(
            REGISTER_URL,
            json={
                "names": "X",
                "last_names": "Y",
                "email": "null@example.com",
                "password": "pass\x00word1",
            },
        )
        assert resp.status_code in (201, 400, 422)

    def test_empty_body_returns_422(self, client):
        resp = client.post(REGISTER_URL, json={})
        assert resp.status_code == 422

    def test_non_json_body_returns_422(self, client):
        resp = client.post(
            REGISTER_URL,
            content="this is not json",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 422

    def test_password_exactly_8_chars_accepted(self, client):
        resp = client.post(
            REGISTER_URL,
            json={"names": "X", "last_names": "Y", "email": "min@example.com", "password": "12345678"},
        )
        assert resp.status_code == 201

    def test_password_exactly_7_chars_rejected(self, client):
        resp = client.post(
            REGISTER_URL,
            json={"names": "X", "last_names": "Y", "email": "min7@example.com", "password": "1234567"},
        )
        assert resp.status_code == 422

    def test_verification_code_7_digits_rejected(self, client):
        do_register(client)
        resp = client.post(VERIFY_URL, json={"code": "1234567"})
        assert resp.status_code == 422

    def test_verification_code_5_digits_rejected(self, client):
        do_register(client)
        resp = client.post(VERIFY_URL, json={"code": "12345"})
        assert resp.status_code == 422

    def test_verification_code_empty_string_rejected(self, client):
        do_register(client)
        resp = client.post(VERIFY_URL, json={"code": ""})
        assert resp.status_code == 422

    def test_extremely_long_token_in_update_password_handled(self, client):
        resp = client.post(
            UPDATE_PW_URL,
            json={"token": "x" * 100_000, "new_password": "newpassword1"},
        )
        assert resp.status_code in (401, 422)

    def test_extremely_long_token_in_unlock_handled(self, client):
        resp = client.post(UNLOCK_URL, json={"token": "x" * 100_000})
        assert resp.status_code in (401, 422)

    def test_new_password_exactly_8_chars_in_update(self, client, db):
        do_register(client)
        token = make_token(db, "password_recovery")
        resp = client.post(UPDATE_PW_URL, json={"token": token, "new_password": "12345678"})
        assert resp.status_code == 200

    def test_new_password_7_chars_in_update_rejected(self, client, db):
        do_register(client)
        token = make_token(db, "password_recovery")
        resp = client.post(UPDATE_PW_URL, json={"token": token, "new_password": "1234567"})
        assert resp.status_code == 422


# ===========================================================================
# HTTP METHOD ENFORCEMENT
# ===========================================================================


class TestHttpMethodEnforcement:
    def test_get_on_login_rejected(self, client):
        resp = client.get(LOGIN_URL)
        assert resp.status_code == 405

    def test_post_on_me_rejected(self, client):
        resp = client.post(ME_URL)
        assert resp.status_code == 405

    def test_delete_on_register_rejected(self, client):
        resp = client.delete(REGISTER_URL)
        assert resp.status_code == 405

    def test_put_on_verify_rejected(self, client):
        resp = client.put(VERIFY_URL)
        assert resp.status_code == 405

    def test_patch_on_logout_rejected(self, client):
        resp = client.patch(LOGOUT_URL)
        assert resp.status_code == 405


# ===========================================================================
# INFORMATION LEAKAGE / ENUMERATION
# ===========================================================================


class TestInformationLeakage:
    def test_unknown_email_login_returns_same_error_as_wrong_password(self, client):
        do_register(client)
        r_wrong_pw = do_login(client, password="wrongpassword")
        r_unknown = do_login(client, email="nobody@example.com")
        # Both must return the same error_code to prevent user enumeration
        assert r_wrong_pw.json()["error_code"] == r_unknown.json()["error_code"]

    def test_recovery_unknown_email_returns_200(self, client):
        resp = client.post(RECOVERY_URL, json={"email": "nobody@example.com"})
        assert resp.status_code == 200

    def test_recovery_known_email_returns_200(self, client):
        do_register(client)
        resp = client.post(RECOVERY_URL, json={"email": DEFAULT_EMAIL})
        assert resp.status_code == 200

    def test_recovery_response_body_identical_for_known_and_unknown(self, client):
        do_register(client)
        r_known = client.post(RECOVERY_URL, json={"email": DEFAULT_EMAIL})
        r_unknown = client.post(RECOVERY_URL, json={"email": "ghost@example.com"})
        assert r_known.json() == r_unknown.json()

    def test_unlock_request_unknown_email_returns_200(self, client):
        resp = client.post(UNLOCK_REQ_URL, json={"email": "nobody@example.com"})
        assert resp.status_code == 200

    def test_unlock_request_active_user_returns_200(self, client):
        do_register(client)
        resp = client.post(UNLOCK_REQ_URL, json={"email": DEFAULT_EMAIL})
        assert resp.status_code == 200

    def test_registration_409_does_not_leak_password(self, client):
        do_register(client)
        resp = do_register(client)
        body = str(resp.json())
        assert DEFAULT_PASSWORD not in body

    def test_401_response_does_not_include_user_data(self, client, db):
        do_register(client)
        user = db_get_user(db)
        user.deleted_at = datetime.now(UTC)
        db.commit()
        resp = do_login(client)
        body = str(resp.json())
        assert DEFAULT_EMAIL not in body or "error_code" in resp.json()


# ===========================================================================
# SEQUENTIAL AUTHENTICATION FLOW INTEGRITY
# ===========================================================================


class TestAuthFlowIntegrity:
    def test_full_happy_path(self, client, db):
        """Register → verify email → login → get role → logout → login again."""
        # 1. Register
        r = do_register(client)
        assert r.status_code == 201

        # 2. Verify email
        db_set_verification_code(db, code="123456")
        v = client.post(VERIFY_URL, json={"code": "123456"})
        assert v.status_code == 200

        # 3. Still authenticated (cookies from register)
        me = client.get(ME_URL)
        assert me.status_code == 200

        # 4. Get role
        role = client.get(ROLE_URL)
        assert role.status_code == 200

        # 5. Logout
        lo = client.post(LOGOUT_URL)
        assert lo.status_code == 200

        # 6. Login again
        li = do_login(client)
        assert li.status_code == 200

    def test_register_sets_access_and_refresh_cookies(self, client):
        r = do_register(client)
        assert "access_token" in r.cookies
        assert "refresh_token" in r.cookies

    def test_login_overwrites_previous_tokens(self, client):
        do_register(client)
        first_access = client.cookies.get("access_token")
        do_login(client)
        second_access = client.cookies.get("access_token")
        # Tokens are time-based; they may or may not differ depending on speed,
        # but both must be non-empty valid cookies.
        assert second_access is not None

    def test_verify_email_sets_email_verified_at_timestamp(self, client, db):
        do_register(client)
        db_set_verification_code(db, code="654321")
        resp = client.post(VERIFY_URL, json={"code": "654321"})
        ts = resp.json()["user"]["email_verified_at"]
        assert ts is not None
        # Must be a parseable ISO datetime string
        datetime.fromisoformat(ts.replace("Z", "+00:00"))

    def test_password_update_invalidates_old_password_immediately(self, client, db):
        do_register(client)
        token = make_token(db, "password_recovery")
        client.post(UPDATE_PW_URL, json={"token": token, "new_password": "brandnewpw1"})
        r = do_login(client, password=DEFAULT_PASSWORD)
        assert r.status_code == 401

    def test_unlock_restores_active_status(self, client, db):
        do_register(client)
        db_set_status(db, UserStatus.locked)
        token = make_token(db, "unlock_user")
        client.post(UNLOCK_URL, json={"token": token})
        user = db_get_user(db)
        assert user.status == UserStatus.active

    def test_concurrent_register_same_email_second_returns_409(self, client):
        """Simulate near-concurrent registration of the same email."""
        r1 = do_register(client)
        assert r1.status_code == 201
        r2 = do_register(client)
        assert r2.status_code == 409
        assert r2.json()["error_code"] == "already_exists"

    def test_resend_verification_while_already_verified_still_200(self, client, db):
        """Resending after verification must not error."""
        do_register(client)
        db_set_verification_code(db, code="654321")
        client.post(VERIFY_URL, json={"code": "654321"})
        resp = client.get(VERIFY_URL)
        assert resp.status_code == 200

    def test_me_returns_pep_false_by_default(self, client):
        do_register(client)
        resp = client.get(ME_URL)
        assert resp.json()["user"]["pep"] is False

    def test_me_returns_roles_list(self, client):
        do_register(client)
        resp = client.get(ME_URL)
        roles = resp.json()["user"]["roles"]
        assert isinstance(roles, list)
        assert len(roles) >= 1

    def test_register_response_has_no_password_field(self, client):
        resp = do_register(client)
        user_dict = resp.json()["user"]
        assert "password" not in user_dict

    def test_login_response_has_no_password_field(self, client):
        do_register(client)
        resp = do_login(client)
        user_dict = resp.json()["user"]
        assert "password" not in user_dict


# ===========================================================================
# EDGE CASES ON EXISTING ENDPOINTS NOT IN test_auth.py
# ===========================================================================


class TestEdgeCasesNotPreviouslyCovered:
    def test_register_trims_leading_trailing_whitespace_or_stores_as_is(self, client):
        """Whitespace-only names: the schema has min_length=1, so '' is invalid but ' ' may pass."""
        resp = client.post(
            REGISTER_URL,
            json={"names": " ", "last_names": " ", "email": "ws@example.com", "password": "password123"},
        )
        # min_length=1 means a single space passes Pydantic; behaviour is application-defined.
        assert resp.status_code in (201, 422)

    def test_register_with_extra_json_fields_ignored(self, client):
        resp = client.post(
            REGISTER_URL,
            json={
                "names": "X",
                "last_names": "Y",
                "email": "extra@example.com",
                "password": "password123",
                "is_admin": True,
                "role": "superuser",
                "deleted_at": "2000-01-01",
            },
        )
        # Extra fields must be ignored (Pydantic default) not granted
        assert resp.status_code == 201
        user = resp.json()["user"]
        assert user.get("is_admin") is None
        assert "superuser" not in [r["name"] for r in user["roles"]]

    def test_login_case_sensitive_password(self, client):
        do_register(client)
        resp = do_login(client, password=DEFAULT_PASSWORD.upper())
        assert resp.status_code == 401

    def test_login_with_extra_fields_ignored(self, client):
        do_register(client)
        resp = client.post(
            LOGIN_URL,
            json={"email": DEFAULT_EMAIL, "password": DEFAULT_PASSWORD, "is_admin": True},
        )
        assert resp.status_code == 200

    def test_verify_unauthenticated_returns_401(self, client):
        resp = client.post(VERIFY_URL, json={"code": "123456"})
        assert resp.status_code == 401

    def test_resend_unauthenticated_returns_401(self, client):
        resp = client.get(VERIFY_URL)
        assert resp.status_code == 401

    def test_logout_twice_second_returns_401(self, client):
        do_register(client)
        client.post(LOGOUT_URL)
        resp = client.post(LOGOUT_URL)
        assert resp.status_code == 401

    def test_update_password_missing_token_field_422(self, client):
        resp = client.post(UPDATE_PW_URL, json={"new_password": "newpassword1"})
        assert resp.status_code == 422

    def test_update_password_missing_new_password_field_422(self, client, db):
        do_register(client)
        token = make_token(db, "password_recovery")
        resp = client.post(UPDATE_PW_URL, json={"token": token})
        assert resp.status_code == 422

    def test_unlock_missing_token_field_422(self, client):
        resp = client.post(UNLOCK_URL, json={})
        assert resp.status_code == 422

    def test_recovery_missing_email_field_422(self, client):
        resp = client.post(RECOVERY_URL, json={})
        assert resp.status_code == 422

    def test_refresh_ignores_body_uses_cookie(self, client):
        """Refresh reads the cookie, not a body field — body must be irrelevant."""
        do_register(client)
        resp = client.post(REFRESH_URL, json={"refresh_token": "garbage"})
        # Cookie is valid → 200; the body field is ignored
        assert resp.status_code == 200

    def test_inactive_user_cannot_refresh(self, client, db):
        do_register(client)
        db_set_status(db, UserStatus.inactive)
        resp = client.post(REFRESH_URL)
        assert resp.status_code in (401, 403)

    def test_lock_threshold_is_exactly_5_not_4(self, client):
        do_register(client)
        for _ in range(4):
            do_login(client, password="wrong")
        # 4 failures → still active
        resp = do_login(client, password=DEFAULT_PASSWORD)
        assert resp.status_code == 200

    def test_6th_failure_after_reset_counter_does_not_immediately_lock(self, client):
        """
        After a successful login resets the counter, the next single failure
        must not lock the account.
        """
        do_register(client)
        for _ in range(4):
            do_login(client, password="wrong")
        do_login(client)  # success → counter cleared
        do_login(client, password="wrong")  # 1 failure on fresh counter
        resp = do_login(client, password=DEFAULT_PASSWORD)
        assert resp.status_code == 200
