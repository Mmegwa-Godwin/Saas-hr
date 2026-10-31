"""Additive database schema for the Accounting department."""

SCHEMA_VERSION = 1


def init_accounting_schema(db):
    """Create Accounting tables without modifying existing HR tables."""

    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS accounting_schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS accounting_periods (
            id TEXT PRIMARY KEY,
            company_id TEXT NOT NULL,
            name TEXT NOT NULL,
            start_date TEXT NOT NULL,
            end_date TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open'
                CHECK(status IN ('open', 'closed')),
            created_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(company_id, name),
            CHECK(start_date <= end_date)
        );

        CREATE TABLE IF NOT EXISTS chart_of_accounts (
            id TEXT PRIMARY KEY,
            company_id TEXT NOT NULL,
            account_code TEXT NOT NULL,
            account_name TEXT NOT NULL,
            account_type TEXT NOT NULL
                CHECK(account_type IN (
                    'asset', 'liability', 'equity', 'income', 'expense'
                )),
            normal_balance TEXT NOT NULL
                CHECK(normal_balance IN ('debit', 'credit')),
            parent_account_id TEXT,
            description TEXT NOT NULL DEFAULT '',
            is_control_account INTEGER NOT NULL DEFAULT 0
                CHECK(is_control_account IN (0, 1)),
            active INTEGER NOT NULL DEFAULT 1
                CHECK(active IN (0, 1)),
            created_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(company_id, account_code),
            UNIQUE(company_id, id)
        );

        CREATE TABLE IF NOT EXISTS journal_entries (
            id TEXT PRIMARY KEY,
            company_id TEXT NOT NULL,
            branch_id TEXT,
            period_id TEXT NOT NULL,
            entry_number TEXT NOT NULL,
            entry_date TEXT NOT NULL,
            description TEXT NOT NULL,
            reference TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'draft'
                CHECK(status IN (
                    'draft', 'approved', 'posted', 'reversed'
                )),
            total_debit NUMERIC NOT NULL DEFAULT 0
                CHECK(total_debit >= 0),
            total_credit NUMERIC NOT NULL DEFAULT 0
                CHECK(total_credit >= 0),
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            approved_by TEXT,
            approved_at TEXT,
            posted_by TEXT,
            posted_at TEXT,
            reversed_by TEXT,
            reversed_at TEXT,
            reversal_of TEXT,
            UNIQUE(company_id, entry_number),
            UNIQUE(company_id, id)
        );

        CREATE TABLE IF NOT EXISTS journal_lines (
            id TEXT PRIMARY KEY,
            company_id TEXT NOT NULL,
            journal_entry_id TEXT NOT NULL,
            account_id TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            debit NUMERIC NOT NULL DEFAULT 0 CHECK(debit >= 0),
            credit NUMERIC NOT NULL DEFAULT 0 CHECK(credit >= 0),
            line_order INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            CHECK (
                (debit > 0 AND credit = 0)
                OR
                (credit > 0 AND debit = 0)
            )
        );

        CREATE TABLE IF NOT EXISTS accounting_audit_log (
            id TEXT PRIMARY KEY,
            company_id TEXT NOT NULL,
            actor_type TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            action TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            details_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS ix_accounting_periods_company_dates
        ON accounting_periods(company_id, start_date, end_date);

        CREATE INDEX IF NOT EXISTS ix_chart_accounts_company_type
        ON chart_of_accounts(company_id, account_type, active);

        CREATE INDEX IF NOT EXISTS ix_journal_entries_company_date
        ON journal_entries(company_id, entry_date);

        CREATE INDEX IF NOT EXISTS ix_journal_entries_branch_date
        ON journal_entries(company_id, branch_id, entry_date);

        CREATE INDEX IF NOT EXISTS ix_journal_entries_period_status
        ON journal_entries(company_id, period_id, status);

        CREATE INDEX IF NOT EXISTS ix_journal_lines_entry
        ON journal_lines(company_id, journal_entry_id, line_order);

        CREATE INDEX IF NOT EXISTS ix_journal_lines_account
        ON journal_lines(company_id, account_id);

        CREATE INDEX IF NOT EXISTS ix_accounting_audit_company_date
        ON accounting_audit_log(company_id, created_at);
        """
    )

    db.execute(
        """
        INSERT OR IGNORE INTO accounting_schema_migrations
            (version, applied_at)
        VALUES (?, datetime('now'))
        """,
        (SCHEMA_VERSION,),
    )
    db.commit()
