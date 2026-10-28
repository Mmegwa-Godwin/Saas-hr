import hashlib
import os
import sqlite3
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import app as app_module


class SessionRevocationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_saas_hr.db")

        self.old_database_path = app_module.app.config.get("DATABASE_PATH")
        self.old_testing = app_module.app.config.get("TESTING")
        self.old_secret_key = app_module.app.config.get("SECRET_KEY")

        app_module.app.config["DATABASE_PATH"] = self.db_path
        app_module.app.config["TESTING"] = True
        app_module.app.config["SECRET_KEY"] = "session-revocation-test-secret"
        app_module.app.testing = True

        self.client = app_module.app.test_client()
        response = self.client.get("/api/csrf-token")
        self.assertEqual(response.status_code, 200)
        self.csrf_token = response.get_json()["csrf_token"]

    def tearDown(self):
        app_module.app.config["DATABASE_PATH"] = self.old_database_path
        app_module.app.config["TESTING"] = self.old_testing
        app_module.app.config["SECRET_KEY"] = self.old_secret_key
        app_module.app.testing = bool(self.old_testing)
        self.temp_dir.cleanup()

    def refresh_csrf(self):
        response = self.client.get("/api/csrf-token")
        self.assertEqual(response.status_code, 200)
        self.csrf_token = response.get_json()["csrf_token"]

    def post_json(self, path, payload):
        return self.client.post(
            path,
            json=payload,
            headers={"X-CSRF-Token": self.csrf_token},
        )

    def seed_account(self, account_type, account_id, email, name=None):
        password_hash = app_module.generate_password_hash("OldPassword!2026")
        now = datetime.now(timezone.utc)
        raw_token = "reset-" + uuid.uuid4().hex
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

        with sqlite3.connect(self.db_path) as db:
            if account_type == "company":
                db.execute(
                    """INSERT INTO companies
                       (id, name, email, password, plan, created)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        account_id,
                        name or "Test Company",
                        email,
                        password_hash,
                        "free",
                        now.isoformat(),
                    ),
                )
            else:
                db.execute(
                    """INSERT INTO platform_admins
                       (id, email, password, created)
                       VALUES (?, ?, ?, ?)""",
                    (account_id, email, password_hash, now.isoformat()),
                )

            db.execute(
                """INSERT INTO auth_versions
                   (account_type, account_id, version)
                   VALUES (?, ?, 1)""",
                (account_type, account_id),
            )
            db.execute(
                """INSERT INTO password_resets
                   (id, account_type, account_id, token_hash,
                    expires_at, used, created_at)
                   VALUES (?, ?, ?, ?, ?, 0, ?)""",
                (
                    uuid.uuid4().hex,
                    account_type,
                    account_id,
                    token_hash,
                    (now + timedelta(minutes=15)).isoformat(),
                    now.isoformat(),
                ),
            )

        return raw_token

    def test_company_reset_revokes_old_session_and_allows_new_login(self):
        token = self.seed_account(
            "company", "company-1", "company@example.test"
        )

        login = self.post_json(
            "/api/company/login",
            {
                "email": "company@example.test",
                "password": "OldPassword!2026",
            },
        )
        self.assertEqual(login.status_code, 200, login.get_json())

        # Login clears the session, so obtain a fresh CSRF token.
        self.refresh_csrf()

        reset = self.post_json(
            "/api/password/reset",
            {"token": token, "password": "NewPassword!2026"},
        )
        self.assertEqual(reset.status_code, 200, reset.get_json())

        with sqlite3.connect(self.db_path) as db:
            version = db.execute(
                """SELECT version FROM auth_versions
                   WHERE account_type='company' AND account_id='company-1'"""
            ).fetchone()[0]
            used = db.execute(
                "SELECT used FROM password_resets WHERE token_hash=?",
                (hashlib.sha256(token.encode()).hexdigest(),),
            ).fetchone()[0]

        self.assertEqual(version, 2)
        self.assertEqual(used, 1)

        old_session = self.client.get("/api/session")
        self.assertEqual(old_session.status_code, 401)

        # Revocation clears the old session, so obtain a fresh CSRF token.
        self.refresh_csrf()

        reuse = self.post_json(
            "/api/password/reset",
            {"token": token, "password": "AnotherPassword!2026"},
        )
        self.assertEqual(reuse.status_code, 400)

        new_login = self.post_json(
            "/api/company/login",
            {
                "email": "company@example.test",
                "password": "NewPassword!2026",
            },
        )
        self.assertEqual(new_login.status_code, 200, new_login.get_json())

        current_session = self.client.get("/api/session")
        self.assertEqual(current_session.status_code, 200)
        self.assertTrue(current_session.get_json()["authenticated"])

    def test_owner_reset_revokes_old_session_and_allows_new_login(self):
        token = self.seed_account(
            "owner", "owner-1", "owner@example.test"
        )

        login = self.post_json(
            "/api/owner/login",
            {
                "email": "owner@example.test",
                "password": "OldPassword!2026",
            },
        )
        self.assertEqual(login.status_code, 200, login.get_json())

        self.refresh_csrf()

        reset = self.post_json(
            "/api/password/reset",
            {"token": token, "password": "NewPassword!2026"},
        )
        self.assertEqual(reset.status_code, 200, reset.get_json())

        with sqlite3.connect(self.db_path) as db:
            version = db.execute(
                """SELECT version FROM auth_versions
                   WHERE account_type='owner' AND account_id='owner-1'"""
            ).fetchone()[0]

        self.assertEqual(version, 2)

        old_session = self.client.get("/api/owner/session")
        self.assertEqual(old_session.status_code, 401)

        # Revocation clears the old session, so obtain a fresh CSRF token.
        self.refresh_csrf()

        new_login = self.post_json(
            "/api/owner/login",
            {
                "email": "owner@example.test",
                "password": "NewPassword!2026",
            },
        )
        self.assertEqual(new_login.status_code, 200, new_login.get_json())

        current_session = self.client.get("/api/owner/session")
        self.assertEqual(current_session.status_code, 200)
        self.assertTrue(current_session.get_json()["authenticated"])



    def seed_employee_account(self, account_id, email):
        password_hash = app_module.generate_password_hash("OldPassword!2026")
        now = datetime.now(timezone.utc)
        raw_token = "reset-" + uuid.uuid4().hex
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        company_id = "company-for-" + account_id

        with sqlite3.connect(self.db_path) as db:
            db.execute(
                """INSERT INTO companies
                   (id, name, email, password, plan, created)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    company_id,
                    "Employee Test Company",
                    "company-" + account_id + "@example.test",
                    password_hash,
                    "free",
                    now.isoformat(),
                ),
            )
            db.execute(
                """INSERT INTO users
                   (id, company_id, name, email, role, department,
                    photo, photo_hash, password, created, active)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                (
                    account_id,
                    company_id,
                    "Test Employee",
                    email,
                    "HR",
                    "",
                    "",
                    "",
                    password_hash,
                    now.isoformat(),
                ),
            )
            db.execute(
                """INSERT INTO auth_versions
                   (account_type, account_id, version)
                   VALUES ('employee', ?, 1)""",
                (account_id,),
            )
            db.execute(
                """INSERT INTO password_resets
                   (id, account_type, account_id, token_hash,
                    expires_at, used, created_at)
                   VALUES (?, 'employee', ?, ?, ?, 0, ?)""",
                (
                    uuid.uuid4().hex,
                    account_id,
                    token_hash,
                    (now + timedelta(minutes=15)).isoformat(),
                    now.isoformat(),
                ),
            )

        return raw_token, company_id

    def test_employee_reset_revokes_old_session_and_allows_new_login(self):
        token, company_id = self.seed_employee_account(
            "employee-1", "employee@example.test"
        )

        login = self.post_json(
            "/api/employee/login",
            {
                "company_id": company_id,
                "email": "employee@example.test",
                "password": "OldPassword!2026",
            },
        )
        self.assertEqual(login.status_code, 200, login.get_json())

        self.refresh_csrf()

        reset = self.post_json(
            "/api/password/reset",
            {"token": token, "password": "NewPassword!2026"},
        )
        self.assertEqual(reset.status_code, 200, reset.get_json())

        with sqlite3.connect(self.db_path) as db:
            version = db.execute(
                """SELECT version FROM auth_versions
                   WHERE account_type='employee' AND account_id='employee-1'"""
            ).fetchone()[0]
            used = db.execute(
                "SELECT used FROM password_resets WHERE token_hash=?",
                (hashlib.sha256(token.encode()).hexdigest(),),
            ).fetchone()[0]

        self.assertEqual(version, 2)
        self.assertEqual(used, 1)

        old_session = self.client.get("/api/employee/session")
        self.assertEqual(old_session.status_code, 401)

        self.refresh_csrf()

        reuse = self.post_json(
            "/api/password/reset",
            {"token": token, "password": "AnotherPassword!2026"},
        )
        self.assertEqual(reuse.status_code, 400)

        new_login = self.post_json(
            "/api/employee/login",
            {
                "company_id": company_id,
                "email": "employee@example.test",
                "password": "NewPassword!2026",
            },
        )
        self.assertEqual(new_login.status_code, 200, new_login.get_json())

        current_session = self.client.get("/api/employee/session")
        self.assertEqual(current_session.status_code, 200)
        self.assertTrue(current_session.get_json()["authenticated"])

    def test_employee_forgot_password_creates_reset_token(self):
        self.seed_employee_account(
            "employee-request-1", "employee-request@example.test"
        )

        with patch.object(app_module, "send_password_reset_email") as send_email:
            response = self.post_json(
                "/api/password/forgot",
                {"email": "employee-request@example.test"},
            )

        self.assertEqual(response.status_code, 200, response.get_json())
        send_email.assert_called_once()

        with sqlite3.connect(self.db_path) as db:
            rows = db.execute(
                """SELECT account_type, account_id, used
                   FROM password_resets
                   WHERE account_type='employee'
                     AND account_id='employee-request-1'
                   ORDER BY created_at DESC"""
            ).fetchall()

        self.assertTrue(rows)
        self.assertEqual(rows[0][0], "employee")
        self.assertEqual(rows[0][1], "employee-request-1")
        self.assertEqual(rows[0][2], 0)

if __name__ == "__main__":
    unittest.main(verbosity=2)
