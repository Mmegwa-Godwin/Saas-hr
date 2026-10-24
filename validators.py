import re

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_email(value):
    if not isinstance(value, str):
        return ""
    return value.strip().lower()


def is_valid_email(value):
    return bool(EMAIL_RE.match(normalize_email(value)))


def validate_password(password, minimum=8):
    if not isinstance(password, str):
        return False
    return len(password) >= minimum


def validate_company_id(value):
    if value is None:
        return False
    return str(value).strip() != ""
