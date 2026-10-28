import os
import sqlite3
import tempfile
import unittest

import app as app_module


class PasswordEndpointTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_saas_hr.db")

        self.old_database_path = app_module.app.config.get("DATABASE_PATH")
        self.old_testing = app_module.app.config.get("TESTING")

        app_module.app.config["DATABASE_PATH"] = self.db_path
        app_module.app.config["TESTING"] = True
        app_module.app.config["SECRET_KEY"] = "isolated-test-secret"
        app_module.app.testing = True

        self.client = app_module.app.test_client()

        response = self.client.get("/api/csrf-token")
        self.assertEqual(response.status_code, 200)
        self.csrf_token = response.get_json()["csrf_token"]

    def tearDown(self):
        app_module.app.config["DATABASE_PATH"] = self.old_database_path
        app_module.app.config["TESTING"] = self.old_testing
        app_module.app.testing = False
        self.temp_dir.cleanup()

    def post_json(self, path, data):
        return self.client.post(
            path,
            json=data,
            headers={"X-CSRF-Token": self.csrf_token},
        )

    def test_weak_company_password_is_rejected(self):
        response = self.post_json(
            "/api/company/register",
            {
                "name": "Test Company",
                "email": "company@example.test",
                "password": "weak",
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())

        with sqlite3.connect(self.db_path) as db:
            count = db.execute(
                "SELECT COUNT(*) FROM companies"
            ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_strong_company_password_is_accepted(self):
        response = self.post_json(
            "/api/company/register",
            {
                "name": "Test Company",
                "email": "company@example.test",
                "password": "StrongPass!2026",
            },
        )

        self.assertEqual(response.status_code, 201, response.get_json())
        self.assertIn("company_id", response.get_json())

    def test_weak_employee_password_is_rejected(self):
        # Simulate a valid company session under the auth-version guard.
        with sqlite3.connect(self.db_path) as db:
            db.execute(
                """INSERT INTO auth_versions
                   (account_type, account_id, version)
                   VALUES ('company', 'test-company', 1)"""
            )

        with self.client.session_transaction() as session:
            session["company_id"] = "test-company"
            session["auth_version"] = 1

        response = self.post_json(
            "/api/staff",
            {
                "company_id": "test-company",
                "name": "Test Employee",
                "email": "employee@example.test",
                "password": "weak",
                "role": "staff",
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())

    def test_weak_password_reset_is_rejected_before_token_lookup(self):
        response = self.post_json(
            "/api/password/reset",
            {
                "token": "test-token",
                "password": "weak",
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())
        self.assertNotIn(
            "Invalid or expired reset link",
            response.get_json()["error"],
        )

    def test_strong_password_reaches_reset_token_validation(self):
        response = self.post_json(
            "/api/password/reset",
            {
                "token": "nonexistent-test-token",
                "password": "StrongPass!2026",
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json()["error"],
            "Invalid or expired reset link",
        )

    def test_post_without_csrf_token_is_rejected(self):
        response = self.client.post(
            "/api/company/register",
            json={
                "name": "Test Company",
                "email": "csrf@example.test",
                "password": "StrongPass!2026",
            },
        )

        self.assertEqual(response.status_code, 403)
        self.assertIn("CSRF", response.get_json()["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
