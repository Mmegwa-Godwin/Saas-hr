#!/usr/bin/env python3

import getpass
import os
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from werkzeug.security import generate_password_hash

REPAIR_DIR = Path(__file__).resolve().parent
DB_CANDIDATE = REPAIR_DIR / "saas_hr.db"
PRODUCTION_DB = Path("/public/saas-hr/backend/saas_hr.db").resolve()


def main():
    print("SaaS-HR: Isolated First Platform Owner Setup")
    print("This script does not start the web application.")

    # Reject links before resolving the target path.
    if DB_CANDIDATE.is_symlink():
        print("REFUSED: repair database path is a symbolic link.")
        return

    if DB_CANDIDATE.resolve().parent != REPAIR_DIR:
        print("REFUSED: database path is outside the repair directory.")
        return

    if DB_CANDIDATE.resolve() == PRODUCTION_DB:
        print("REFUSED: production database is protected.")
        return

    # Never reuse an existing database or SQLite sidecar.
    sidecars = [
        Path(str(DB_CANDIDATE) + suffix)
        for suffix in ("-wal", "-shm", "-journal")
    ]

    if DB_CANDIDATE.exists() or any(p.exists() or p.is_symlink() for p in sidecars):
        print("REFUSED: database or SQLite sidecar already exists.")
        print("Nothing was changed. Inspect the files before proceeding.")
        return

    email = input("Platform owner email: ").strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        print("Invalid email address.")
        return

    password = getpass.getpass("New password (minimum 14 characters): ")
    if len(password) < 14:
        print("Password is too short; use at least 14 characters.")
        return

    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        print("Passwords do not match.")
        return

    password_hash = generate_password_hash(password)
    owner_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()

    # Exclusively create a brand-new database file with restrictive permissions.
    try:
        fd = os.open(
            str(DB_CANDIDATE),
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
        os.close(fd)
    except FileExistsError:
        print("REFUSED: database appeared during setup. Nothing was overwritten.")
        return
    except OSError as error:
        print(f"Could not create isolated database: {error}")
        return

    try:
        with sqlite3.connect(str(DB_CANDIDATE), timeout=5) as db:
            db.execute("PRAGMA busy_timeout = 5000")
            db.execute("""
                CREATE TABLE platform_admins (
                    id TEXT PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    created TEXT NOT NULL
                )
            """)
            db.execute(
                """
                INSERT INTO platform_admins (id, email, password, created)
                VALUES (?, ?, ?, ?)
                """,
                (owner_id, email, password_hash, created_at),
            )

        print("SUCCESS: first platform owner created in the isolated repair database.")
        print(f"Owner email: {email}")
        print(f"Database: {DB_CANDIDATE}")
        print("Password was hashed and was not printed or saved as plaintext.")
        print("Production database was not used.")

    except (sqlite3.Error, OSError) as error:
        print(f"Setup failed: {error}")
        print("The new database file was preserved for inspection.")
        print("Do not rerun setup until the file has been checked.")


if __name__ == "__main__":
    main()
