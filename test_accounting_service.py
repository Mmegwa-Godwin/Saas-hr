import os
import tempfile
import unittest

import app as app_module

from services.accounting_service import (
    create_account,
    list_accounts,
    update_account,
    deactivate_account,
    create_accounting_period,
    list_accounting_periods,
)


class AccountingServiceTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.original_db_path = app_module.app.config.get("DATABASE_PATH")
        cls.original_testing = app_module.app.config.get("TESTING")

        app_module.app.config["DATABASE_PATH"] = os.path.join(
            cls.tmp.name, "accounting_test.db"
        )
        app_module.app.config["TESTING"] = True

        with app_module.app.app_context():
            app_module.init_db()
            db = app_module.get_db()

            for cid, name, email in [
                ("acct_c1", "Accounting Company One", "acct1@test.invalid"),
                ("acct_c2", "Accounting Company Two", "acct2@test.invalid"),
            ]:
                db.execute(
                    """
                    INSERT INTO companies
                    (id, name, email, password, plan, created)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (cid, name, email, "x", "free", "2026-01-01"),
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

        # Service functions commit their own transactions.
        # Reset Accounting data so tests cannot affect one another.
        self.db.execute("DELETE FROM accounting_audit_log")
        self.db.execute("DELETE FROM journal_lines")
        self.db.execute("DELETE FROM journal_entries")
        self.db.execute("DELETE FROM accounting_periods")
        self.db.execute("DELETE FROM chart_of_accounts")
        self.db.commit()

    def tearDown(self):
        self.db.rollback()
        self.context.pop()

    def make_account(
        self,
        company_id="acct_c1",
        code="1000",
        name="Cash",
        account_type="asset",
        parent_account_id=None,
        description="",
    ):
        return create_account(
            company_id=company_id,
            account_code=code,
            account_name=name,
            account_type=account_type,
            actor_id="test_admin",
            parent_account_id=parent_account_id,
            description=description,
        )

    def test_create_asset_account_uses_debit_balance(self):
        account = self.make_account()

        self.assertEqual(account["account_code"], "1000")
        self.assertEqual(account["account_type"], "asset")
        self.assertEqual(account["normal_balance"], "debit")
        self.assertEqual(account["active"], 1)

    def test_income_account_uses_credit_balance(self):
        account = self.make_account(
            code="4000",
            name="Sales Revenue",
            account_type="income",
        )

        self.assertEqual(account["normal_balance"], "credit")

    def test_duplicate_account_code_is_rejected(self):
        self.make_account()

        with self.assertRaises(Exception):
            self.make_account(name="Duplicate Cash")

    def test_accounts_are_isolated_by_company(self):
        self.make_account(company_id="acct_c1")

        company_two_accounts = list_accounts("acct_c2")

        self.assertEqual(len(company_two_accounts), 0)

        with self.assertRaises(ValueError):
            update_account(
                company_id="acct_c2",
                account_id=self.db.execute(
                    """
                    SELECT id FROM chart_of_accounts
                    WHERE company_id = 'acct_c1'
                    """
                ).fetchone()["id"],
                actor_id="test_admin",
                account_name="Attempted takeover",
            )

    def test_foreign_company_parent_is_rejected(self):
        foreign_parent = self.make_account(
            company_id="acct_c2",
            code="2000",
            name="Foreign Parent",
        )

        with self.assertRaises(ValueError):
            self.make_account(
                code="1001",
                name="Child Account",
                parent_account_id=foreign_parent["id"],
            )

    def test_circular_parent_hierarchy_is_rejected(self):
        parent = self.make_account(code="1000", name="Parent")
        child = self.make_account(
            code="1100",
            name="Child",
            parent_account_id=parent["id"],
        )

        with self.assertRaisesRegex(ValueError, "Circular"):
            update_account(
                company_id="acct_c1",
                account_id=parent["id"],
                actor_id="test_admin",
                parent_account_id=child["id"],
                change_parent=True,
            )

    def test_description_over_1000_characters_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "1000"):
            self.make_account(description="x" * 1001)

    def test_accounting_period_rejects_overlapping_dates(self):
        create_accounting_period(
            company_id="acct_c1",
            name="January 2026",
            start_date="2026-01-01",
            end_date="2026-01-31",
            actor_id="test_admin",
        )

        with self.assertRaisesRegex(ValueError, "overlaps"):
            create_accounting_period(
                company_id="acct_c1",
                name="Second January Period",
                start_date="2026-01-20",
                end_date="2026-02-10",
                actor_id="test_admin",
            )

    def test_accounting_period_rejects_invalid_date_range(self):
        with self.assertRaisesRegex(ValueError, "after"):
            create_accounting_period(
                company_id="acct_c1",
                name="Invalid Period",
                start_date="2026-02-01",
                end_date="2026-01-01",
                actor_id="test_admin",
            )

    def test_accounting_periods_are_company_scoped(self):
        create_accounting_period(
            company_id="acct_c1",
            name="2026 Financial Year",
            start_date="2026-01-01",
            end_date="2026-12-31",
            actor_id="test_admin",
        )

        self.assertEqual(len(list_accounting_periods("acct_c1")), 1)
        self.assertEqual(len(list_accounting_periods("acct_c2")), 0)

    def test_account_used_by_draft_journal_cannot_be_deactivated(self):
        account = self.make_account()

        period = create_accounting_period(
            company_id="acct_c1",
            name="2026 Test Period",
            start_date="2026-01-01",
            end_date="2026-12-31",
            actor_id="test_admin",
        )

        self.db.execute(
            """
            INSERT INTO journal_entries (
                id, company_id, branch_id, period_id,
                entry_number, entry_date, description, reference,
                status, total_debit, total_credit,
                created_by, created_at, updated_at
            )
            VALUES (
                'draft_journal_1', 'acct_c1', NULL, ?,
                'DRAFT-001', '2026-01-15', 'Test journal', '',
                'draft', 100, 100,
                'test_admin', datetime('now'), datetime('now')
            )
            """,
            (period["id"],),
        )

        self.db.execute(
            """
            INSERT INTO journal_lines (
                id, company_id, journal_entry_id, account_id,
                description, debit, credit, line_order, created_at
            )
            VALUES (
                'draft_line_1', 'acct_c1', 'draft_journal_1', ?,
                'Cash line', 100, 0, 1, datetime('now')
            )
            """,
            (account["id"],),
        )
        self.db.commit()

        with self.assertRaisesRegex(ValueError, "referenced by a journal"):
            deactivate_account("acct_c1", account["id"], "test_admin")


if __name__ == "__main__":
    unittest.main()
