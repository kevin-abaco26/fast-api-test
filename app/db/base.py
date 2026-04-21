# This module is imported by Alembic env.py to discover all models.
# Do NOT import this in application code — use base_class.py for Base.
from app.db.base_class import Base  # noqa: F401

from app.models.role import Permission, Role, role_permissions, user_roles  # noqa: F401
from app.models.user import User  # noqa: F401
from app.models.failed_login import FailedLogin  # noqa: F401
