import os
import tempfile
import unittest

import app as app_module

from services.accounting_service import create_account


class AccountingAPITests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.original_db_path = app_module.app.config.get("DATABASE_PATH")
        cls.original_testing = app_module.app.config.get("TESTING")

        app_module.app.config["DATABASE_PATH"] = os.path.join(
            cls.tmp.name, "accounting_api_test.db"
        )
        app_module.app.config["TESTING"] = True

        with app_module.app.app_context():
            app_module.init_db()
            db = app_module.get_db()

            for cid, name, email in [
                ("api_c1", "API Company One", "api1@test.invalid"),
                ("api_c2", "API Company Two", "api2@test.invalid"),
            ]:
                db.execute(
                    """
                    INSERT INTO companies
                    (id, name, email, password, plan, created)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (cid, name, email, "x", "free", "2026-01-01"),
                )

                db.execute(
                    """
                    INSERT OR REPLACE INTO auth_versions
                    (account_type, account_id, version)
                    VALUES ('company', ?, 1)
                    """,
                    (cid,),
                )

            db.execute(
                """INSERT INTO users
                (id, company_id, name, email, role, department,
                 photo, photo_hash, password, created, active,
                 employment_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    "api_accounting_staff", "api_c1",
                    "Accounting Test Staff", "accounting-staff@test.invalid",
                    "staff", "HR", "", "", "x", "2026-01-01", 1, "active",
                ),
            )

            db.execute(
                """INSERT OR REPLACE INTO auth_versions
                   (account_type, account_id, version)
                   VALUES ('employee', ?, 1)""",
                ("api_accounting_staff",),
            )

            db.commit()

    @classmethod
    def tearDownClass(cls):
        app_module.app.config["DATABASE_PATH"] = cls.original_db_path
        app_module.app.config["TESTING"] = cls.original_testing
        cls.tmp.cleanup()

    def setUp(self):
        self.context = app_module.app.app_context()
        self.context.push()
        self.db = app_module.get_db()

        self.db.execute("DELETE FROM accounting_audit_log")
        self.db.execute("DELETE FROM journal_lines")
        self.db.execute("DELETE FROM journal_entries")
        self.db.execute("DELETE FROM accounting_periods")
        self.db.execute("DELETE FROM chart_of_accounts")
        self.db.commit()

        self.client = app_module.app.test_client()

        with self.client.session_transaction() as sess:
            sess["company_id"] = "api_c1"
            sess["company_name"] = "API Company One"
            sess["auth_version"] = 1
            sess["_csrf_token"] = "accounting-api-test-token"

        self.headers = {
            "X-CSRF-Token": "accounting-api-test-token"
        }

    def tearDown(self):
        self.db.rollback()
        self.context.pop()

    def create_account(self, code="1000", name="Cash"):
        return self.client.post(
            "/api/accounting/accounts",
            json={
                "account_code": code,
                "account_name": name,
                "account_type": "asset",
            },
            headers=self.headers,
        )

    def test_company_can_create_and_list_account(self):
        created = self.create_account()

        self.assertEqual(created.status_code, 201)
        account = created.get_json()["account"]
        self.assertEqual(account["account_code"], "1000")

        listed = self.client.get("/api/accounting/accounts")

        self.assertEqual(listed.status_code, 200)
        self.assertEqual(len(listed.get_json()["accounts"]), 1)

    def test_duplicate_account_code_returns_conflict(self):
        first = self.create_account()
        duplicate = self.create_account(name="Duplicate Cash")

        self.assertEqual(first.status_code, 201)
        self.assertEqual(duplicate.status_code, 409)

    def test_account_can_be_updated(self):
        created = self.create_account()
        account_id = created.get_json()["account"]["id"]

        updated = self.client.patch(
            f"/api/accounting/accounts/{account_id}",
            json={"account_name": "Main Cash Account"},
            headers=self.headers,
        )

        self.assertEqual(updated.status_code, 200)
        self.assertEqual(
            updated.get_json()["account"]["account_name"],
            "Main Cash Account",
        )

    def test_unknown_account_update_field_is_rejected(self):
        created = self.create_account()
        account_id = created.get_json()["account"]["id"]

        response = self.client.patch(
            f"/api/accounting/accounts/{account_id}",
            json={"account_type": "income"},
            headers=self.headers,
        )

        self.assertEqual(response.status_code, 400)

    def test_client_cannot_supply_company_or_actor_identity(self):
        for field in ("company_id", "actor_id"):
            payload = {
                "account_code": "2000",
                "account_name": "Bank",
                "account_type": "asset",
                field: "api_c2",
            }

            response = self.client.post(
                "/api/accounting/accounts",
                json=payload,
                headers=self.headers,
            )

            expected_status = 403 if field == "company_id" else 400
            self.assertEqual(response.status_code, expected_status, field)

    def test_foreign_company_account_cannot_be_updated(self):
        foreign = create_account(
            company_id="api_c2",
            account_code="9000",
            account_name="Foreign Cash",
            account_type="asset",
            actor_id="api_c2",
            actor_type="company",
        )

        response = self.client.patch(
            f"/api/accounting/accounts/{foreign['id']}",
            json={"account_name": "Attempted Takeover"},
            headers=self.headers,
        )

        self.assertEqual(response.status_code, 404)

    def test_employee_without_accounting_permission_is_denied(self):
        client = app_module.app.test_client()

        with client.session_transaction() as sess:
            sess["company_id"] = "api_c1"
            sess["employee_id"] = "api_accounting_staff"
            sess["auth_version"] = 1
            sess["_csrf_token"] = "employee-accounting-test-token"

        response = client.get("/api/accounting/accounts")

        self.assertEqual(response.status_code, 403)

    def test_foreign_company_account_cannot_be_deactivated(self):
        foreign = create_account(
            company_id="api_c2",
            account_code="9100",
            account_name="Foreign Bank",
            account_type="asset",
            actor_id="api_c2",
            actor_type="company",
        )

        response = self.client.post(
            f"/api/accounting/accounts/{foreign['id']}/deactivate",
            headers=self.headers,
        )

        self.assertEqual(response.status_code, 404)

    def test_period_cannot_close_while_draft_journal_exists(self):
        created = self.client.post(
            "/api/accounting/periods",
            json={
                "name": "February 2026",
                "start_date": "2026-02-01",
                "end_date": "2026-02-28",
            },
            headers=self.headers,
        )

        self.assertEqual(created.status_code, 201)
        period_id = created.get_json()["period"]["id"]

        self.db.execute(
            """
            INSERT INTO journal_entries (
                id, company_id, branch_id, period_id,
                entry_number, entry_date, description, reference,
                status, total_debit, total_credit,
                created_by, created_at, updated_at
            )
            VALUES (
                'api_draft_journal', 'api_c1', NULL, ?,
                'API-DRAFT-001', '2026-02-15', 'Test draft journal', '',
                'draft', 100, 100,
                'api_c1', datetime('now'), datetime('now')
            )
            """,
            (period_id,),
        )
        self.db.commit()

        response = self.client.post(
            f"/api/accounting/periods/{period_id}/close",
            headers=self.headers,
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("draft", response.get_json()["error"].lower())

    def test_company_can_create_and_list_accounting_period(self):
        created = self.client.post(
            "/api/accounting/periods",
            json={
                "name": "January 2026",
                "start_date": "2026-01-01",
                "end_date": "2026-01-31",
            },
            headers=self.headers,
        )

        self.assertEqual(created.status_code, 201)

        listed = self.client.get("/api/accounting/periods")

        self.assertEqual(listed.status_code, 200)
        self.assertEqual(len(listed.get_json()["periods"]), 1)

    def test_invalid_include_inactive_parameter_is_rejected(self):
        response = self.client.get(
            "/api/accounting/accounts?include_inactive=maybe"
        )

        self.assertEqual(response.status_code, 400)

    def test_unauthenticated_request_is_rejected(self):
        client = app_module.app.test_client()

        response = client.get("/api/accounting/accounts")

        self.assertEqual(response.status_code, 401)

    def test_write_without_csrf_token_is_rejected(self):
        client = app_module.app.test_client()

        with client.session_transaction() as sess:
            sess["company_id"] = "api_c1"
            sess["company_name"] = "API Company One"
            sess["auth_version"] = 1
            sess["_csrf_token"] = "expected-token"

        response = client.post(
            "/api/accounting/accounts",
            json={
                "account_code": "3000",
                "account_name": "Receivables",
                "account_type": "asset",
            },
        )

        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main(verbosity=2)
