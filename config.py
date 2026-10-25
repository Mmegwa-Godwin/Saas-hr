import os
from datetime import timedelta
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


def _is_production() -> bool:
    return os.environ.get("FLASK_ENV", "").lower() == "production"


def get_secret_key() -> str:
    secret = os.environ.get("SAAS_HR_SECRET_KEY")
    if secret:
        return secret
    if _is_production():
        raise RuntimeError("SAAS_HR_SECRET_KEY must be configured in production")
    return "local-development-only-change-before-deployment"


class AppConfig:
    IS_PRODUCTION = _is_production()
    SECRET_KEY = get_secret_key()
    TESTING = os.environ.get("FLASK_ENV", "").lower() == "test"
    _test_database_path = os.environ.get("SAAS_HR_TEST_DB", "").strip()

    if TESTING and not _test_database_path:
        raise RuntimeError(
            "SAAS_HR_TEST_DB must point to an isolated temporary database in test mode"
        )

    DATABASE_PATH = (
        _test_database_path
        if TESTING
        else os.environ.get("SAAS_HR_DATABASE_PATH", "").strip()
        or str(BASE_DIR / "saas_hr.db")
    )
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = IS_PRODUCTION
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    BASE_URL = os.environ.get("SAAS_HR_BASE_URL", "http://127.0.0.1:5000").strip() or "http://127.0.0.1:5000"
