import os
import json
import sqlite3
import tempfile
import importlib.util
from pathlib import Path
from werkzeug.security import generate_password_hash

spec = importlib.util.spec_from_file_location(
    "saas_hr_full_security_test", Path("app.py").resolve()
)
app_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app_module)

tmp = tempfile.TemporaryDirectory()
app_module.DB = os.path.join(tmp.name, "test.db")
app_module.app.config["TESTING"] = True

passed = 0
failed = 0


def check(name, condition):
    global passed, failed
    if condition:
        print("PASS:", name)
        passed += 1
    else:
        print("FAIL:", name)
        failed += 1


def employee_csrf():
    return employee_client.get(
        "/api/csrf-token"
    ).get_json()["csrf_token"]


def employee_login():
    # Always fetch a fresh token because successful login clears the session.
    token = employee_csrf()
    return employee_client.post(
        "/api/employee/login",
        json={
            "company_id": "c1",
            "email": "u1@test.invalid",
            "password": "TestPassword!123"
        },
        headers={"X-CSRF-Token": token}
    )


def company_csrf():
    return {"X-CSRF-Token": company_token}


def correct(attendance_id, changes, reason="Regression correction",
            company="c1"):
    return company_client.post(
        f"/api/attendance/{company}/{attendance_id}/correct",
        json={"reason": reason, "changes": changes},
        headers=company_csrf()
    )


try:
    # ------------------------------------------------------
    # ISOLATED DATABASE SETUP
    # ------------------------------------------------------
    with app_module.app.app_context():
        app_module.init_db()
        db = app_module.get_db()

        db.execute(
            "INSERT INTO companies VALUES (?, ?, ?, ?, ?, ?)",
            ("c1", "Company One", "one@test.invalid",
             "x", "free", "2026-01-01")
        )
        db.execute(
            "INSERT INTO companies VALUES (?, ?, ?, ?, ?, ?)",
            ("c2", "Company Two", "two@test.invalid",
             "x", "free", "2026-01-01")
        )

        password_hash = generate_password_hash("TestPassword!123")

        for uid, cid in [
            ("u1", "c1"),
            ("u2", "c1"),
            ("u3", "c2")
        ]:
            db.execute(
                """INSERT INTO users
                (id, company_id, name, email, role, department,
                 photo, photo_hash, password, created, active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    uid, cid, uid, uid + "@test.invalid",
                    "staff", "HR", "", "", password_hash,
                    "2026-01-01", 1
                )
            )

        db.execute(
            """INSERT INTO attendance
            (id, company_id, user_id, date, clock_in, clock_out, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            ("a1", "c1", "u1", "2026-10-20",
             "2026-10-20T09:00:00",
             "2026-10-20T17:00:00", "present")
        )

        db.execute(
            """INSERT INTO attendance
            (id, company_id, user_id, date, clock_in, clock_out, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            ("a2", "c1", "u1", "2026-10-21",
             "2026-10-21T09:00:00", None, "present")
        )

        db.execute(
            """INSERT INTO attendance
            (id, company_id, user_id, date, clock_in, clock_out, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            ("a3", "c2", "u3", "2026-10-20",
             "2026-10-20T09:00:00",
             "2026-10-20T17:00:00", "present")
        )
        db.commit()

        indexes = {
            row["name"]
            for row in db.execute("PRAGMA index_list(attendance)")
        }
        check(
            "Database unique attendance index exists",
            "ux_attendance_company_user_date" in indexes
        )

    # Separate clients keep company and employee sessions independent.
    employee_client = app_module.app.test_client()
    company_client = app_module.app.test_client()

    employee_client.get("/api/csrf-token")
    company_token = company_client.get(
        "/api/csrf-token"
    ).get_json()["csrf_token"]

    with company_client.session_transaction() as session:
        session["company_id"] = "c1"
        session["company_name"] = "Company One"

    # ------------------------------------------------------
    # SUITE A: EMPLOYEE SECURITY
    # ------------------------------------------------------
    print("\n===== SUITE A: EMPLOYEE SECURITY =====")

    login = employee_login()
    check("Valid employee login succeeds", login.status_code == 200)

    own_status = employee_client.get("/api/attendance/status/u1")
    check(
        "Employee can access own attendance status",
        own_status.status_code == 200
    )

    other_status = employee_client.get("/api/attendance/status/u2")
    check(
        "Employee cannot access another employee's status",
        other_status.status_code == 403
    )

    staff_list = employee_client.get("/api/staff/c1")
    check(
        "Employee cannot access company staff management",
        staff_list.status_code == 403
    )

    company_session_attempt = employee_client.get("/api/session")
    check(
        "Employee session cannot become company session",
        company_session_attempt.status_code == 403
    )

    deactivate = company_client.patch(
        "/api/staff/c1/u1/active",
        json={"active": False},
        headers=company_csrf()
    )
    check("Company can deactivate employee", deactivate.status_code == 200)

    inactive_session = employee_client.get("/api/employee/session")
    check(
        "Inactive employee session is rejected",
        inactive_session.status_code == 401
    )

    inactive_login = employee_login()
    check(
        "Inactive employee cannot log in",
        inactive_login.status_code == 401
    )

    reactivate = company_client.patch(
        "/api/staff/c1/u1/active",
        json={"active": True},
        headers=company_csrf()
    )
    check("Company can reactivate employee", reactivate.status_code == 200)

    login_again = employee_login()
    check(
        "Reactivated employee can log in",
        login_again.status_code == 200
    )

    deactivate_again = company_client.patch(
        "/api/staff/c1/u1/active",
        json={"active": False},
        headers=company_csrf()
    )
    check(
        "Employee can be deactivated while logged in",
        deactivate_again.status_code == 200
    )

    blocked_status = employee_client.get("/api/attendance/status/u1")
    check(
        "Deactivation blocks an existing employee session",
        blocked_status.status_code == 401
    )

    reactivate_again = company_client.patch(
        "/api/staff/c1/u1/active",
        json={"active": True},
        headers=company_csrf()
    )
    check(
        "Employee can be reactivated again",
        reactivate_again.status_code == 200
    )

    # ------------------------------------------------------
    # SUITE B: ATTENDANCE INTEGRITY AND AUDIT
    # ------------------------------------------------------
    print("\n===== SUITE B: ATTENDANCE INTEGRITY AND AUDIT =====")

    valid = correct("a1", {"clock_out": "2026-10-20T18:00:00"})
    check("Valid attendance correction succeeds", valid.status_code == 200)

    backwards = correct("a1", {"clock_out": "2026-10-20T08:00:00"})
    check(
        "Clock-out before clock-in is rejected",
        backwards.status_code == 400
    )

    duplicate_date = correct("a1", {"date": "2026-10-21"})
    check(
        "Duplicate employee/date correction is rejected",
        duplicate_date.status_code == 409
    )

    missing_reason = correct("a1", {"status": "late"}, reason="short")
    check(
        "Short correction reason is rejected",
        missing_reason.status_code == 400
    )

    invalid_status = correct("a1", {"status": "unknown"})
    check(
        "Unsupported attendance status is rejected",
        invalid_status.status_code == 400
    )

    cross_company = correct("a3", {"status": "late"}, company="c2")
    check(
        "Cross-company correction is blocked",
        cross_company.status_code == 403
    )

    own_audit = company_client.get("/api/attendance/c1/audit")
    check("Company can read its own audit log", own_audit.status_code == 200)

    foreign_audit = company_client.get("/api/attendance/c2/audit")
    check(
        "Cross-company audit access is blocked",
        foreign_audit.status_code == 403
    )

    with app_module.app.app_context():
        db = app_module.get_db()

        record = db.execute(
            "SELECT clock_out, date, status FROM attendance WHERE id='a1'"
        ).fetchone()

        audit_rows = db.execute(
            """SELECT * FROM attendance_audit
            WHERE attendance_id='a1' ORDER BY created_at"""
        ).fetchall()

        check(
            "Successful correction stored the new clock-out",
            record["clock_out"] == "2026-10-20T18:00:00"
        )
        check(
            "Failed corrections left date and status unchanged",
            record["date"] == "2026-10-20"
            and record["status"] == "present"
        )
        check(
            "Only successful correction created an audit entry",
            len(audit_rows) == 1
        )

        if audit_rows:
            audit = audit_rows[0]
            old_values = json.loads(audit["old_values"])
            new_values = json.loads(audit["new_values"])

            check(
                "Audit preserves old clock-out",
                old_values.get("clock_out") == "2026-10-20T17:00:00"
            )
            check(
                "Audit preserves new clock-out",
                new_values.get("clock_out") == "2026-10-20T18:00:00"
            )
            check(
                "Audit stores correction reason",
                audit["reason"] == "Regression correction"
            )
        else:
            check("Audit preserves old clock-out", False)
            check("Audit preserves new clock-out", False)
            check("Audit stores correction reason", False)

        # Independently verify that the database rejects duplicates.
        try:
            db.execute(
                """INSERT INTO attendance
                (id, company_id, user_id, date, status)
                VALUES (?, ?, ?, ?, ?)""",
                ("duplicate-test", "c1", "u1", "2026-10-20", "present")
            )
            db.commit()
            duplicate_rejected = False
        except sqlite3.IntegrityError:
            db.rollback()
            duplicate_rejected = True

        check(
            "Database rejects duplicate attendance directly",
            duplicate_rejected
        )

finally:
    tmp.cleanup()

print(f"\n===== FINAL RESULTS: {passed} PASSED, {failed} FAILED =====")

if failed:
    print("INVESTIGATION REQUIRED: do not deploy this development copy.")
else:
    print("ALL COMBINED TESTS PASSED")
