from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.services.email_service as email_svc
import hashlib

from app.core.security import create_recovery_token, hash_code
from app.db.base_class import Base
from app.db.session import get_db
from app.main import app as fastapi_app
from app.models.user import UserStatus

# Import all models so Base.metadata is populated
import app.db.base  # noqa: F401

SQLITE_URL = "sqlite://"

engine = create_engine(
    SQLITE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# ---------------------------------------------------------------------------
# DB / email fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(autouse=True)
def stub_email(monkeypatch):
    """Prevent real SendGrid calls."""
    monkeypatch.setattr(email_svc, "_send", lambda *_args, **_kwargs: None)


@pytest.fixture
def db():
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(db):
    def override_get_db():
        yield db

    fastapi_app.dependency_overrides[get_db] = override_get_db
    with TestClient(fastapi_app, raise_server_exceptions=True) as c:
        yield c
    fastapi_app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Shared helpers (callable in any test)
# ---------------------------------------------------------------------------

REGISTER_URL = "/api/v1/auth/register"
LOGIN_URL = "/api/v1/auth/login"

DEFAULT_EMAIL = "user@example.com"
DEFAULT_PASSWORD = "password123"


def do_register(
    client: TestClient,
    email: str = DEFAULT_EMAIL,
    password: str = DEFAULT_PASSWORD,
    names: str = "Test",
    last_names: str = "User",
):
    return client.post(
        REGISTER_URL,
        json={"names": names, "last_names": last_names, "email": email, "password": password},
    )


def do_login(client: TestClient, email: str = DEFAULT_EMAIL, password: str = DEFAULT_PASSWORD):
    return client.post(LOGIN_URL, json={"email": email, "password": password})


def db_get_user(db, email: str = DEFAULT_EMAIL):
    from app.services.user_service import get_by_email

    return get_by_email(db, email)


def db_set_verification_code(db, email: str = DEFAULT_EMAIL, code: str = "123456"):
    user = db_get_user(db, email)
    user.verification_code = hash_code(code)
    user.verification_expiry = datetime.now(UTC) + timedelta(minutes=5)
    db.commit()
    db.refresh(user)


def db_expire_verification_code(db, email: str = DEFAULT_EMAIL):
    user = db_get_user(db, email)
    user.verification_code = hash_code("999999")
    user.verification_expiry = datetime.now(UTC) - timedelta(minutes=1)
    db.commit()


def db_set_status(db, status: UserStatus, email: str = DEFAULT_EMAIL):
    user = db_get_user(db, email)
    user.status = status
    db.commit()


def make_token(db, token_type: str, email: str = DEFAULT_EMAIL) -> str:
    user = db_get_user(db, email)
    token = create_recovery_token(user.id, token_type)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    if token_type == "password_recovery":
        user.password_reset_token_hash = token_hash
    elif token_type == "unlock_user":
        user.unlock_token_hash = token_hash
    db.commit()
    return token


# ---------------------------------------------------------------------------
# Higher-level fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def registered_client(client):
    """Client that has just registered (cookies set)."""
    do_register(client)
    return client


@pytest.fixture
def registered_user(client):
    """Register a user and return response JSON."""
    resp = do_register(client)
    assert resp.status_code == 201
    return resp.json()
