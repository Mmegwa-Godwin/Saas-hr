import os
import unittest
from unittest.mock import MagicMock, patch

import app as app_module


class PasswordResetEmailTests(unittest.TestCase):
    def test_sender_uses_tls_authentication_and_sends_email(self):
        settings = {
            "SMTP_HOST": "smtp.gmail.com",
            "SMTP_PORT": "587",
            "SMTP_USERNAME": "sender@example.com",
            "SMTP_PASSWORD": "test-only-password",
            "SMTP_FROM": "sender@example.com",
        }

        fake_server = MagicMock()
        fake_server.__enter__.return_value = fake_server

        with patch.dict(os.environ, settings, clear=False):
            with patch.object(
                app_module.smtplib,
                "SMTP",
                return_value=fake_server,
            ) as smtp:
                app_module.send_password_reset_email(
                    "recipient@example.com",
                    "https://example.com/reset-password?token=test-token",
                )

        smtp.assert_called_once_with(
            "smtp.gmail.com", 587, timeout=15
        )
        fake_server.starttls.assert_called_once()
        fake_server.login.assert_called_once_with(
            "sender@example.com", "test-only-password"
        )
        fake_server.send_message.assert_called_once()

        message = fake_server.send_message.call_args.args[0]
        self.assertEqual(message["To"], "recipient@example.com")
        self.assertIn("reset-password?token=test-token",
                      message.get_content())

    def test_missing_smtp_credentials_are_rejected(self):
        settings = {
            "SMTP_HOST": "smtp.gmail.com",
            "SMTP_USERNAME": "",
            "SMTP_PASSWORD": "",
            "SMTP_FROM": "",
        }

        with patch.dict(os.environ, settings, clear=False):
            with self.assertRaisesRegex(RuntimeError, "must be configured"):
                app_module.send_password_reset_email(
                    "recipient@example.com",
                    "https://example.com/reset-password?token=test",
                )

    def test_production_requires_https_reset_url(self):
        with patch.object(app_module, "IS_PRODUCTION", True):
            with patch.dict(
                os.environ,
                {"SAAS_HR_BASE_URL": "http://example.com"},
                clear=False,
            ):
                with self.assertRaisesRegex(RuntimeError, "HTTPS"):
                    app_module.get_password_reset_base_url()

    def test_local_base_url_has_safe_default(self):
        with patch.object(app_module, "IS_PRODUCTION", False):
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("SAAS_HR_BASE_URL", None)
                self.assertEqual(
                    app_module.get_password_reset_base_url(),
                    "http://127.0.0.1:5000",
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
