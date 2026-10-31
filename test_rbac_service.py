import os
import tempfile
import unittest
from pathlib import Path

import app as app_module
from services.rbac_service import has_permission, normalize_role


class RBACServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.original_db_path = app_module.app.config.get("DATABASE_PATH")

        app_module.app.config["DATABASE_PATH"] = os.path.join(
            cls.tmp.name, "rbac_test.db"
        )
        app_module.app.config["TESTING"] = True

        with app_module.app.app_context():
            app_module.init_db()
            db = app_module.get_db()

            for cid, name, email in [
                ("c1", "Company One", "one@test.invalid"),
                ("c2", "Company Two", "two@test.invalid"),
            ]:
                db.execute(
                    """INSERT INTO companies
                    (id, name, email, password, plan, created)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                    (cid, name, email, "x", "free", "2026-01-01"),
                )

            # Seed lifecycle records, departments and RBAC roles
            # for the companies inserted above.
            db.commit()
            app_module.init_db()
            db = app_module.get_db()

            for uid, cid, role, active, status in [
                ("staff1", "c1", "staff", 1, "active"),
                ("hr1", "c1", "HR", 1, "active"),
                ("admin1", "c1", "admin", 1, "active"),
                ("inactive1", "c1", "staff", 0, "inactive"),
                ("staff2", "c2", "staff", 1, "active"),
            ]:
                db.execute(
                    """INSERT INTO users
                    (id, company_id, name, email, role, department,
                     photo, photo_hash, password, created, active,
                     employment_status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        uid, cid, uid, uid + "@test.invalid", role,
                        "Accounting", "", "", "x", "2026-01-01",
                        active, status,
                    ),
                )

            db.commit()

    @classmethod
    def tearDownClass(cls):
        app_module.app.config["DATABASE_PATH"] = cls.original_db_path
        cls.tmp.cleanup()

    def setUp(self):
        self.context = app_module.app.app_context()
        self.context.push()
        self.db = app_module.get_db()

    def tearDown(self):
        self.db.rollback()
        self.context.pop()

    def assign(self, user_id, company_id="c1", department="Accounting"):
        row = self.db.execute(
            """SELECT id FROM departments
               WHERE company_id=? AND lower(name)=lower(?)""",
            (company_id, department),
        ).fetchone()
        self.assertIsNotNone(row)
        self.db.execute(
            """INSERT OR IGNORE INTO user_departments
               (company_id, user_id, department_id, created)
               VALUES (?, ?, ?, ?)""",
            (company_id, user_id, row["id"], "2026-01-01"),
        )
        self.db.commit()
        return row["id"]

    def permission_id(self, code):
        row = self.db.execute(
            "SELECT id FROM permissions WHERE code=?", (code,)
        ).fetchone()
        self.assertIsNotNone(row)
        return row["id"]

    def grant_role(self, role_key, permission_code, company_id="c1"):
        role = self.db.execute(
            "SELECT id FROM roles WHERE company_id=? AND role_key=?",
            (company_id, role_key),
        ).fetchone()
        self.assertIsNotNone(role)
        self.db.execute(
            """INSERT OR IGNORE INTO role_permissions
               (role_id, permission_id) VALUES (?, ?)""",
            (role["id"], self.permission_id(permission_code)),
        )
        self.db.commit()

    def override(self, user_id, department_id, code, effect):
        self.db.execute(
            """INSERT OR REPLACE INTO user_permissions
               (company_id, user_id, department_id, permission_id,
                effect, granted_by, created)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                "c1", user_id, department_id,
                self.permission_id(code), effect, "admin1", "2026-01-01",
            ),
        )
        self.db.commit()

    def test_default_staff_has_no_permission(self):
        self.assign("staff1")
        self.assertFalse(
            has_permission("c1", "staff1", "accounting", "view")
        )

    def test_role_permission_grants_access(self):
        self.assign("staff1")
        self.grant_role("staff", "accounting.view")
        self.assertTrue(
            has_permission("c1", "staff1", "accounting", "view")
        )

    def test_user_grant_adds_access(self):
        department_id = self.assign("staff1")
        self.override(
            "staff1", department_id, "accounting.create", "grant"
        )
        self.assertTrue(
            has_permission("c1", "staff1", "accounting", "create")
        )

    def test_user_deny_overrides_role_grant(self):
        department_id = self.assign("staff1")
        self.grant_role("staff", "accounting.view")
        self.override(
            "staff1", department_id, "accounting.view", "deny"
        )
        self.assertFalse(
            has_permission("c1", "staff1", "accounting", "view")
        )

    def test_unassigned_department_is_denied(self):
        self.assertFalse(
            has_permission("c1", "staff1", "sales", "view")
        )

    def test_admin_has_company_wide_department_access(self):
        self.assertTrue(
            has_permission("c1", "admin1", "sales", "manage")
        )

    def test_cross_company_employee_access_is_denied(self):
        self.assign("staff2", "c2")
        self.assertFalse(
            has_permission("c1", "staff2", "accounting", "view")
        )

    def test_inactive_employee_is_denied(self):
        self.assign("inactive1")
        self.assertFalse(
            has_permission("c1", "inactive1", "accounting", "view")
        )

    def test_unknown_department_and_action_are_denied(self):
        self.assertFalse(
            has_permission("c1", "admin1", "unknown", "view")
        )
        self.assertFalse(
            has_permission("c1", "admin1", "accounting", "delete")
        )

    def test_role_normalization(self):
        self.assertEqual(normalize_role("HR"), "hr")
        self.assertEqual(normalize_role("human resources"), "hr")
        self.assertEqual(normalize_role("STAFF"), "staff")
        self.assertEqual(normalize_role("unknown"), "")


    def test_hr_department_is_seeded_for_every_company(self):
        for company_id in ("c1", "c2"):
            row = self.db.execute(
                """SELECT id FROM departments
                   WHERE company_id=? AND lower(name)=lower('HR')""",
                (company_id,),
            ).fetchone()
            self.assertIsNotNone(row)

    def test_hr_department_has_all_five_permissions(self):
        rows = self.db.execute(
            """SELECT action FROM permissions
               WHERE department_key='hr'
               ORDER BY action"""
        ).fetchall()

        self.assertEqual(
            {row["action"] for row in rows},
            {"view", "create", "update", "approve", "manage"},
        )

    def test_hr_seeding_is_idempotent(self):
        app_module.init_db()

        for company_id in ("c1", "c2"):
            count = self.db.execute(
                """SELECT COUNT(*) AS total FROM departments
                   WHERE company_id=? AND lower(name)=lower('HR')""",
                (company_id,),
            ).fetchone()["total"]
            self.assertEqual(count, 1)

        permission_count = self.db.execute(
            """SELECT COUNT(*) AS total FROM permissions
               WHERE department_key='hr'"""
        ).fetchone()["total"]
        self.assertEqual(permission_count, 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
