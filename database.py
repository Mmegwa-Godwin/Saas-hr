import sqlite3
import uuid

from flask import current_app, g

from config import AppConfig


def get_db():
    if "db" not in g:
        database_path = current_app.config["DATABASE_PATH"]
        g.db = sqlite3.connect(database_path)
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    db = get_db()

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS password_resets (
            id TEXT PRIMARY KEY,
            account_type TEXT NOT NULL,
            account_id TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
        """
    )
    db.commit()

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS auth_versions (
            account_type TEXT NOT NULL,
            account_id TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY (account_type, account_id)
        )
        """
    )
    db.commit()

    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS companies(
            id TEXT PRIMARY KEY,
            name TEXT,
            email TEXT UNIQUE,
            password TEXT,
            plan TEXT,
            created TEXT
        );

        CREATE TABLE IF NOT EXISTS platform_admins(
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS users(
            id TEXT PRIMARY KEY,
            company_id TEXT,
            name TEXT,
            email TEXT,
            role TEXT,
            department TEXT,
            photo TEXT,
            photo_hash TEXT,
            password TEXT,
            created TEXT
        );

        CREATE TABLE IF NOT EXISTS attendance(
            id TEXT PRIMARY KEY,
            company_id TEXT,
            user_id TEXT,
            date TEXT,
            clock_in TEXT,
            clock_out TEXT,
            status TEXT,
            lat REAL,
            lng REAL,
            distance REAL,
            photo_hash TEXT
        );

        CREATE TABLE IF NOT EXISTS subscriptions(
            id TEXT PRIMARY KEY,
            company_id TEXT,
            plan TEXT,
            amount REAL,
            status TEXT,
            proof TEXT,
            created TEXT,
            expires TEXT
        );

        CREATE TABLE IF NOT EXISTS settings(
            id TEXT PRIMARY KEY,
            moniepoint_account TEXT,
            moniepoint_name TEXT,
            office_lat REAL,
            office_lng REAL,
            office_radius REAL
        );

        CREATE TABLE IF NOT EXISTS company_settings(
            company_id TEXT PRIMARY KEY,
            moniepoint_account TEXT NOT NULL DEFAULT '',
            moniepoint_name TEXT NOT NULL DEFAULT '',
            office_lat REAL NOT NULL DEFAULT 6.5244,
            office_lng REAL NOT NULL DEFAULT 3.3792,
            office_radius REAL NOT NULL DEFAULT 50
        );
        """
    )

    # Company lifecycle and employee employment status.
    # Separate company table preserves the legacy companies column layout.
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS company_lifecycle (
            company_id TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'active',
            reason TEXT NOT NULL DEFAULT '',
            updated_by TEXT NOT NULL DEFAULT 'system',
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS lifecycle_status_history (
            id TEXT PRIMARY KEY,
            company_id TEXT NOT NULL,
            subject_type TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            old_status TEXT NOT NULL,
            new_status TEXT NOT NULL,
            reason TEXT NOT NULL,
            changed_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS ix_lifecycle_history_subject
        ON lifecycle_status_history(company_id, subject_type, subject_id, created_at);
        """
    )

    user_columns = {row["name"] for row in db.execute("PRAGMA table_info(users)").fetchall()}
    if "active" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1")

    user_columns = {row["name"] for row in db.execute("PRAGMA table_info(users)").fetchall()}
    if "employment_status" not in user_columns:
        db.execute(
            "ALTER TABLE users ADD COLUMN employment_status TEXT NOT NULL DEFAULT 'active'"
        )

    # Preserve the meaning of existing deactivated accounts.
    db.execute(
        """UPDATE users SET employment_status='inactive'
           WHERE active=0 AND employment_status='active'"""
    )

    # Existing companies remain operational unless explicitly changed.
    db.execute(
        """INSERT OR IGNORE INTO company_lifecycle
           (company_id, status, reason, updated_by, updated_at)
           SELECT id, 'active', 'Existing company migration', 'system', datetime('now')
           FROM companies"""
    )
    db.commit()

    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS departments (
            id TEXT PRIMARY KEY,
            company_id TEXT NOT NULL,
            name TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created TEXT NOT NULL,
            UNIQUE(company_id, name)
        );

        CREATE TABLE IF NOT EXISTS branches (
            id TEXT PRIMARY KEY,
            company_id TEXT NOT NULL,
            name TEXT NOT NULL,
            address TEXT NOT NULL DEFAULT '',
            active INTEGER NOT NULL DEFAULT 1,
            created TEXT NOT NULL,
            UNIQUE(company_id, name)
        );
        """
    )

    # Additive migrations preserve existing employee records.
    user_columns = {
        row["name"]
        for row in db.execute("PRAGMA table_info(users)").fetchall()
    }
    for column, definition in (
        ("department_id", "TEXT"),
        ("branch_id", "TEXT"),
        ("job_title", "TEXT NOT NULL DEFAULT ''"),
    ):
        if column not in user_columns:
            db.execute(
                f"ALTER TABLE users ADD COLUMN {column} {definition}"
            )

    # Convert existing department text values into company-owned records.
    existing_departments = db.execute(
        """
        SELECT DISTINCT company_id, TRIM(department) AS name
        FROM users
        WHERE company_id IS NOT NULL
          AND TRIM(COALESCE(department, '')) <> ''
        """
    ).fetchall()

    for row in existing_departments:
        company_id = row["company_id"]
        name = row["name"]
        department = db.execute(
            """
            SELECT id FROM departments
            WHERE company_id = ? AND name = ?
            """,
            (company_id, name),
        ).fetchone()

        if department is None:
            department_id = uuid.uuid4().hex[:12]
            db.execute(
                """
                INSERT OR IGNORE INTO departments
                    (id, company_id, name, active, created)
                VALUES (?, ?, ?, 1, datetime('now'))
                """,
                (department_id, company_id, name),
            )
            department = db.execute(
                """
                SELECT id FROM departments
                WHERE company_id = ? AND name = ?
                """,
                (company_id, name),
            ).fetchone()

        if department:
            db.execute(
                """
                UPDATE users SET department_id = ?
                WHERE company_id = ?
                  AND TRIM(COALESCE(department, '')) = ?
                  AND (department_id IS NULL OR department_id = '')
                """,
                (department["id"], company_id, name),
            )

    db.commit()

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS attendance_audit (
            id TEXT PRIMARY KEY,
            company_id TEXT NOT NULL,
            attendance_id TEXT NOT NULL,
            employee_id TEXT NOT NULL,
            action TEXT NOT NULL,
            old_values TEXT,
            new_values TEXT,
            reason TEXT NOT NULL,
            admin_id TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )

    existing_indexes = {row["name"] for row in db.execute("PRAGMA index_list(attendance)").fetchall()}
    if "ux_attendance_company_user_date" not in existing_indexes:
        duplicate = db.execute(
            """
            SELECT company_id, user_id, date, COUNT(*) AS total
            FROM attendance
            WHERE company_id IS NOT NULL
              AND user_id IS NOT NULL
              AND date IS NOT NULL
            GROUP BY company_id, user_id, date
            HAVING COUNT(*) > 1
            LIMIT 1
            """
        ).fetchone()

        if not duplicate:
            db.execute(
                """
                CREATE UNIQUE INDEX ux_attendance_company_user_date
                ON attendance(company_id, user_id, date)
                """
            )

    db.commit()

    row = db.execute("SELECT * FROM settings LIMIT 1").fetchone()
    if not row:
        db.execute("INSERT INTO settings VALUES (?,?,?,?,?,?)", ("1", "", "", 6.5244, 3.3792, 50))
        db.commit()
