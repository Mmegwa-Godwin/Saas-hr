import sqlite3

from flask import g

from config import AppConfig


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(AppConfig.DATABASE_PATH)
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

    user_columns = {row["name"] for row in db.execute("PRAGMA table_info(users)").fetchall()}
    if "active" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1")

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
