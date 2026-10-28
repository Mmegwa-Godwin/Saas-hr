import pytest

from app import password_policy_error


def test_accepts_strong_password():
    assert password_policy_error("StrongPass!2026") is None


@pytest.mark.parametrize(
    ("password", "expected_message"),
    [
        ("Short!1Aa", "12 characters"),
        ("lowercasepass!123", "uppercase"),
        ("UPPERCASEPASS!123", "lowercase"),
        ("NoNumberPassword!", "number"),
        ("NoSpecialChar123A", "special character"),
    ],
)
def test_rejects_passwords_missing_requirements(password, expected_message):
    error = password_policy_error(password)

    assert error is not None
    assert expected_message.lower() in error.lower()


@pytest.mark.parametrize("password", [None, 123, [], {}])
def test_rejects_non_string_passwords(password):
    assert password_policy_error(password) == "Password must be text."
