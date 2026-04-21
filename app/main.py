import logging
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import FastAPI

from app.api.v1.router import router as v1_router
from app.core.config import settings
from app.core.exceptions import register_handlers
from app.core.middleware import register_middleware
from app.db.session import SessionLocal
from app.services.user_service import create_user, get_by_email, assign_role

logger = logging.getLogger(__name__)


def _create_superuser() -> None:
    db = SessionLocal()
    try:
        if get_by_email(db, settings.SUPERUSER_EMAIL):
            return
        user = create_user(
            db,
            names=settings.SUPERUSER_NAMES,
            last_names=settings.SUPERUSER_LAST_NAMES,
            email=settings.SUPERUSER_EMAIL,
            plain_password=settings.SUPERUSER_PASSWORD,
            email_verified=True,
        )
        assign_role(db, user, "backoffice-admin")
        db.commit()
        logger.info("Superuser created: %s", settings.SUPERUSER_EMAIL)
    except Exception:
        db.rollback()
        logger.exception("Failed to create superuser")
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    _create_superuser()
    yield


app = FastAPI(
    title="Abaco2 API",
    version="1.0.0",
    lifespan=lifespan,
)

register_middleware(app)
register_handlers(app)
app.include_router(v1_router)


@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.now(UTC).isoformat()}
