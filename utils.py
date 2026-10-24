import os
import ssl
import smtplib
from datetime import timedelta
from email.message import EmailMessage
from math import asin, cos, radians, sin, sqrt
from urllib.parse import urlparse

from config import AppConfig


def haversine(lat1, lon1, lat2, lon2):
    R = 6371000
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    c = 2 * asin(sqrt(a))
    return R * c


def get_password_reset_base_url():
    configured = os.environ.get("SAAS_HR_BASE_URL", AppConfig.BASE_URL).strip()

    if not configured:
        if AppConfig.IS_PRODUCTION:
            raise RuntimeError("SAAS_HR_BASE_URL must be configured in production")
        configured = "http://127.0.0.1:5000"

    parsed = urlparse(configured)

    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError("SAAS_HR_BASE_URL is invalid")

    if AppConfig.IS_PRODUCTION and parsed.scheme != "https":
        raise RuntimeError("SAAS_HR_BASE_URL must use HTTPS in production")

    return configured.rstrip("/")


def send_password_reset_email(recipient, link):
    host = os.environ.get("SMTP_HOST", "smtp.gmail.com").strip()
    username = os.environ.get("SMTP_USERNAME", "").strip()
    password = os.environ.get("SMTP_PASSWORD", "")
    sender = os.environ.get("SMTP_FROM", username).strip()

    if not host or not username or not password or not sender:
        raise RuntimeError(
            "SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD and SMTP_FROM must be configured"
        )

    try:
        port = int(os.environ.get("SMTP_PORT", "587"))
    except ValueError:
        raise RuntimeError("SMTP_PORT must be a valid port number") from None

    if not 1 <= port <= 65535:
        raise RuntimeError("SMTP_PORT is outside the valid range")

    message = EmailMessage()
    message["Subject"] = "Reset your SaaS-HR password"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        "We received a request to reset your SaaS-HR password.\n\n"
        "Open the link below within 15 minutes to choose a new password:\n\n"
        f"{link}\n\n"
        "If you did not request this, you can ignore this email.\n"
        "Do not share this link with anyone."
    )

    with smtplib.SMTP(host, port, timeout=15) as server:
        server.ehlo()
        server.starttls(context=ssl.create_default_context())
        server.ehlo()
        server.login(username, password)
        server.send_message(message)


__all__ = ["haversine", "get_password_reset_base_url", "send_password_reset_email"]
