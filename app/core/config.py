from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    DATABASE_URL: str = "mysql+pymysql://abaco:secret@db:3306/abaco2"
    SECRET_KEY: str = "changeme"
    ALGORITHM: str = "HS256"

    @field_validator("DATABASE_URL")
    @classmethod
    def fix_postgres_url(cls, v: str) -> str:
        # Render provides postgres:// — SQLAlchemy requires postgresql://
        if v.startswith("postgres://"):
            return v.replace("postgres://", "postgresql://", 1)
        return v

    SENDGRID_API_KEY: str = ""
    SENDGRID_FROM_EMAIL: str = "no-reply@example.com"

    SUPERUSER_EMAIL: str = "admin@example.com"
    SUPERUSER_PASSWORD: str = "changeme"
    SUPERUSER_NAMES: str = "Admin"
    SUPERUSER_LAST_NAMES: str = "System"

    ENVIRONMENT: str = "development"
    FAILED_LOGIN_THRESHOLD: int = 5
    VERIFICATION_CODE_TTL_MINUTES: int = 5

    CORS_ORIGINS: str = "http://localhost:3000"

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]


settings = Settings()
