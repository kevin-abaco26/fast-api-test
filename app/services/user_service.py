from sqlalchemy.orm import Session

from app.models.role import Role
from app.models.user import User, UserStatus
from app.core.security import hash_password


def get_by_email(db: Session, email: str) -> User | None:
    return db.query(User).filter(User.email == email, User.deleted_at.is_(None)).first()


def get_by_id(db: Session, user_id: int) -> User | None:
    return db.query(User).filter(User.id == user_id, User.deleted_at.is_(None)).first()


def get_or_create_role(db: Session, name: str) -> Role:
    role = db.query(Role).filter_by(name=name).first()
    if not role:
        role = Role(name=name)
        db.add(role)
        db.flush()
    return role


def assign_role(db: Session, user: User, role_name: str) -> None:
    role = get_or_create_role(db, role_name)
    if role not in user.roles:
        user.roles.append(role)


def create_user(
    db: Session,
    *,
    names: str,
    last_names: str,
    email: str,
    plain_password: str,
    phone_number: str | None = None,
    country_iso_code: str | None = None,
    email_verified: bool = False,
) -> User:
    from datetime import UTC, datetime

    user = User(
        names=names,
        last_names=last_names,
        email=email,
        password=hash_password(plain_password),
        phone_number=phone_number,
        country_iso_code=country_iso_code,
        status=UserStatus.active,
        email_verified_at=datetime.now(UTC) if email_verified else None,
    )
    db.add(user)
    db.flush()
    return user
