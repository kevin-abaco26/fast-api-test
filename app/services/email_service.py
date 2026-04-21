import logging
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

from app.core.config import settings

logger = logging.getLogger(__name__)

_templates_dir = Path(__file__).parent.parent / "templates" / "emails"
_env = Environment(
    loader=FileSystemLoader(str(_templates_dir)),
    autoescape=select_autoescape(["html"]),
)


def _render(template_name: str, **ctx) -> str:
    ctx.setdefault("current_year", datetime.now().year)
    return _env.get_template(template_name).render(**ctx)


def _send(to_email: str, subject: str, html_content: str) -> None:
    if not settings.SENDGRID_API_KEY:
        logger.info("[EMAIL STUB] To: %s | Subject: %s | Body: %s", to_email, subject, html_content)
        return
    message = Mail(
        from_email=settings.SENDGRID_FROM_EMAIL,
        to_emails=to_email,
        subject=subject,
        html_content=html_content,
    )
    try:
        sg = SendGridAPIClient(settings.SENDGRID_API_KEY)
        sg.send(message)
    except Exception:
        logger.exception("SendGrid send failed to %s", to_email)


def send_verification_code(to_email: str, code: str, names: str = "") -> None:
    html = _render(
        "verification_code.html",
        names=names,
        code=code,
        ttl_minutes=settings.VERIFICATION_CODE_TTL_MINUTES,
    )
    _send(to_email, subject="Tu código de verificación — Abaco Fintech", html_content=html)


def send_password_recovery(to_email: str, token: str, names: str = "", reset_url: str = "") -> None:
    html = _render(
        "password_recovery.html",
        names=names,
        token=token,
        reset_url=reset_url or f"#token={token}",
        ttl_minutes=15,
    )
    _send(to_email, subject="Recupera tu contraseña — Abaco Fintech", html_content=html)


def send_unlock_email(to_email: str, token: str, names: str = "", unlock_url: str = "") -> None:
    html = _render(
        "unlock_account.html",
        names=names,
        token=token,
        unlock_url=unlock_url or f"#token={token}",
        ttl_minutes=15,
    )
    _send(to_email, subject="Desbloquea tu cuenta — Abaco Fintech", html_content=html)
