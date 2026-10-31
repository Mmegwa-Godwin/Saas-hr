import os
import tempfile
import unittest

import app as app_module


class EmployeeRouteGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.original_db_path = app_module.app.config.get("DATABASE_PATH")
        cls.original_testing = app_module.app.config.get("TESTING")

        app_module.app.config["DATABASE_PATH"] = os.path.join(
            cls.tmp.name, "route_guard_test.db"
        )
        app_module.app.config["TESTING"] = True

        with app_module.app.app_context():
            app_module.init_db()
            db = app_module.get_db()

            for cid, name, email in [
                ("guard_c1", "Guard Company One", "guard1@test.invalid"),
                ("guard_c2", "Guard Company Two", "guard2@test.invalid"),
            ]:
                db.execute(
                    """INSERT INTO companies
                    (id, name, email, password, plan, created)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                    (cid, name, email, "x", "free", "2026-01-01"),
                )

            db.commit()
            app_module.init_db()
            db = app_module.get_db()

            for uid, cid, role in [
                ("guard_staff", "guard_c1", "staff"),
                ("guard_hr", "guard_c1", "HR"),
                ("guard_admin", "guard_c1", "admin"),
            ]:
                db.execute(
                    """INSERT INTO users
                    (id, company_id, name, email, role, department,
                     photo, photo_hash, password, created, active,
                     employment_status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        uid, cid, uid, uid + "@test.invalid", role,
                        "HR", "", "", "x", "2026-01-01", 1, "active",
                    ),
                )

            hr_department = db.execute(
                """SELECT id FROM departments
                   WHERE company_id=? AND lower(name)='hr'""",
                ("guard_c1",),
            ).fetchone()

            db.execute(
                """INSERT INTO user_departments
                   (company_id, user_id, department_id, created)
                   VALUES (?, ?, ?, ?)""",
                ("guard_c1", "guard_hr", hr_department["id"], "2026-01-01"),
            )

            permission = db.execute(
                "SELECT id FROM permissions WHERE code='hr.view'"
            ).fetchone()

            db.execute(
                """INSERT INTO user_permissions
                   (company_id, user_id, department_id, permission_id,
                    effect, granted_by, created)
                   VALUES (?, ?, ?, ?, 'grant', ?, ?)""",
                (
                    "guard_c1", "guard_hr", hr_department["id"],
                    permission["id"], "guard_admin", "2026-01-01",
                ),
            )

            for account_type, account_id in [
                ("employee", "guard_staff"),
                ("employee", "guard_hr"),
                ("employee", "guard_admin"),
                ("company", "guard_c1"),
            ]:
                db.execute(
                    """INSERT OR REPLACE INTO auth_versions
                       (account_type, account_id, version)
                       VALUES (?, ?, 1)""",
                    (account_type, account_id),
                )

            db.commit()

    @classmethod
    def tearDownClass(cls):
        app_module.app.config["DATABASE_PATH"] = cls.original_db_path
        app_module.app.config["TESTING"] = cls.original_testing
        cls.tmp.cleanup()

    def make_client(self, account_type, account_id):
        client = app_module.app.test_client()

        with client.session_transaction() as sess:
            sess["_csrf_token"] = "test-csrf-token"
            sess["auth_version"] = 1

            if account_type == "employee":
                sess["company_id"] = "guard_c1"
                sess["employee_id"] = account_id
            elif account_type == "company":
                sess["company_id"] = account_id

        return client

    def test_employee_without_permission_is_denied(self):
        client = self.make_client("employee", "guard_staff")
        response = client.get("/api/departments")
        self.assertEqual(response.status_code, 403)

    def test_employee_with_hr_view_can_list_departments(self):
        client = self.make_client("employee", "guard_hr")
        response = client.get("/api/departments")
        self.assertEqual(response.status_code, 200)

    def test_admin_employee_has_company_wide_access(self):
        client = self.make_client("employee", "guard_admin")
        response = client.get("/api/departments")
        self.assertEqual(response.status_code, 200)

    def test_employee_cannot_access_another_company_records(self):
        client = self.make_client("employee", "guard_admin")
        response = client.get("/api/staff/guard_c2")
        self.assertEqual(response.status_code, 403)

    def test_employee_cannot_access_company_settings(self):
        client = self.make_client("employee", "guard_admin")
        response = client.get("/api/settings")
        self.assertEqual(response.status_code, 403)

    def test_company_account_can_still_list_departments(self):
        client = self.make_client("company", "guard_c1")
        response = client.get("/api/departments")
        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
