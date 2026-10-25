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
app_module.app.config["DATABASE_PATH"] = os.path.join(tmp.name, "test.db")
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
    # SUITE PRE: TENANT ISOLATION AND CSRF REGRESSIONS
    # ------------------------------------------------------
    print("\\n===== SUITE PRE: TENANT ISOLATION AND CSRF =====")

    cross_company_staff = company_client.get("/api/staff/c2")
    check(
        "Company cannot access another company's staff list",
        cross_company_staff.status_code == 403
    )

    cross_company_status = company_client.get("/api/attendance/status/u3")
    check(
        "Company cannot access another company's employee attendance status",
        cross_company_status.status_code == 404
    )

    mismatched_company_body = company_client.patch(
        "/api/staff/c1/u1/active",
        json={"active": True, "company_id": "c2"},
        headers=company_csrf()
    )
    check(
        "Company cannot submit another company's ID in request data",
        mismatched_company_body.status_code == 403
    )

    csrf_probe_client = app_module.app.test_client()
    saved_csrf_token = csrf_probe_client.get(
        "/api/csrf-token"
    ).get_json()["csrf_token"]

    missing_csrf = csrf_probe_client.post(
        "/api/staff/c1/u1/active",
        json={"active": False}
    )
    check(
        "State-changing request without CSRF token is rejected",
        missing_csrf.status_code == 403
    )

    invalid_csrf = csrf_probe_client.post(
        "/api/staff/c1/u1/active",
        json={"active": False},
        headers={"X-CSRF-Token": "invalid-token"}
    )
    check(
        "State-changing request with incorrect CSRF token is rejected",
        invalid_csrf.status_code == 403
    )

    with csrf_probe_client.session_transaction() as session:
        session.clear()

    stale_csrf = csrf_probe_client.post(
        "/api/staff/c1/u1/active",
        json={"active": False},
        headers={"X-CSRF-Token": saved_csrf_token}
    )
    check(
        "Old CSRF token is rejected after its session is cleared",
        stale_csrf.status_code == 403
    )

    mixed_session_client = app_module.app.test_client()
    with mixed_session_client.session_transaction() as session:
        session["company_id"] = "c1"
        session["company_name"] = "Company One"
        session["employee_id"] = "u1"
        session["employee_name"] = "u1"

    mixed_session_response = mixed_session_client.get("/api/staff/c1")
    check(
        "Mixed company and employee session cannot manage staff",
        mixed_session_response.status_code == 403
    )

    # ------------------------------------------------------
    # SUITE A: EMPLOYEE SECURITY
    # ------------------------------------------------------
    print("\n===== SUITE A: EMPLOYEE SECURITY =====")

    login = employee_login()
    check("Valid employee login succeeds", login.status_code == 200)

    # ------------------------------------------------------
    # SUITE A2: CLOCK-IN/CLOCK-OUT AUTHORIZATION
    # ------------------------------------------------------
    print("\\n===== SUITE A2: ATTENDANCE AUTHORIZATION =====")

    own_clock_in = employee_client.post(
        "/api/attendance/clock-in",
        json={
            "company_id": "c1",
            "user_id": "u1",
            "lat": 6.5244,
            "lng": 3.3792
        },
        headers={"X-CSRF-Token": employee_csrf()}
    )
    check(
        "Employee can clock in for themselves",
        own_clock_in.status_code == 200
    )

    own_clock_out = employee_client.post(
        "/api/attendance/clock-out",
        json={"company_id": "c1", "user_id": "u1"},
        headers={"X-CSRF-Token": employee_csrf()}
    )
    check(
        "Employee can clock out for themselves",
        own_clock_out.status_code == 200
    )

    other_clock_in = employee_client.post(
        "/api/attendance/clock-in",
        json={
            "company_id": "c1",
            "user_id": "u2",
            "lat": 6.5244,
            "lng": 3.3792
        },
        headers={"X-CSRF-Token": employee_csrf()}
    )
    check(
        "Employee cannot clock in another employee",
        other_clock_in.status_code == 403
    )

    other_clock_out = employee_client.post(
        "/api/attendance/clock-out",
        json={"company_id": "c1", "user_id": "u2"},
        headers={"X-CSRF-Token": employee_csrf()}
    )
    check(
        "Employee cannot clock out another employee",
        other_clock_out.status_code == 403
    )

    company_clock_in = company_client.post(
        "/api/attendance/clock-in",
        json={
            "company_id": "c1",
            "user_id": "u2",
            "lat": 6.5244,
            "lng": 3.3792
        },
        headers=company_csrf()
    )
    check(
        "Company session cannot use employee clock-in endpoint",
        company_clock_in.status_code == 403
    )

    # Remove any unexpected record if the current insecure handler
    # accepted the request, so the regression test leaves no residue.
    today_for_test = app_module.datetime.now().date().isoformat()
    with app_module.app.app_context():
        db = app_module.get_db()
        db.execute(
            "DELETE FROM attendance WHERE company_id=? AND user_id=? AND date=?",
            ("c1", "u2", today_for_test)
        )
        db.execute(
            """INSERT INTO attendance
               (id, company_id, user_id, date, clock_in, clock_out, status)
               VALUES (?, ?, ?, ?, ?, NULL, ?)""",
            ("permission-test-u2", "c1", "u2", today_for_test,
             app_module.datetime.now().isoformat(), "present")
        )
        db.commit()

    company_clock_out = company_client.post(
        "/api/attendance/clock-out",
        json={"company_id": "c1", "user_id": "u2"},
        headers=company_csrf()
    )
    check(
        "Company session cannot use employee clock-out endpoint",
        company_clock_out.status_code == 403
    )

    with app_module.app.app_context():
        db = app_module.get_db()
        db.execute(
            "DELETE FROM attendance WHERE id=?",
            ("permission-test-u2",)
        )
        db.commit()

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
    # SUITE C: PLATFORM OWNER AUTHORIZATION
    # ------------------------------------------------------
    print("\\n===== SUITE C: PLATFORM OWNER AUTHORIZATION =====")

    unauth_client = app_module.app.test_client()

    unauth_owner_access = unauth_client.get("/api/owner/companies")
    check(
        "Unauthenticated user cannot access owner companies",
        unauth_owner_access.status_code == 401
    )

    company_owner_access = company_client.get("/api/owner/companies")
    check(
        "Company session cannot access owner companies",
        company_owner_access.status_code == 401
    )

    unauth_token = unauth_client.get(
        "/api/csrf-token"
    ).get_json()["csrf_token"]

    unauth_legacy_approval = unauth_client.post(
        "/api/subscriptions/approve/nonexistent",
        headers={"X-CSRF-Token": unauth_token}
    )
    check(
        "Unauthenticated user cannot use legacy subscription approval",
        unauth_legacy_approval.status_code == 401
    )

    company_legacy_approval = company_client.post(
        "/api/subscriptions/approve/nonexistent",
        headers=company_csrf()
    )
    check(
        "Company session cannot use legacy subscription approval",
        company_legacy_approval.status_code == 403
    )

    # Create owner and pending subscription only in the isolated test DB.
    with app_module.app.app_context():
        db = app_module.get_db()
        db.execute(
            """INSERT INTO platform_admins (id, email, password, created)
               VALUES (?, ?, ?, ?)""",
            (
                "owner-test",
                "Owner@Test.invalid",
                generate_password_hash("OwnerTestPassword!123"),
                "2026-10-25"
            )
        )
        db.execute(
            """INSERT INTO subscriptions
               (id, company_id, plan, amount, status, proof, created, expires)
               VALUES (?, ?, ?, ?, ?, ?, ?, NULL)""",
            (
                "owner-sub-test", "c1", "pro", 5000,
                "pending", "isolated-test-proof", "2026-10-25"
            )
        )
        db.commit()

    # A platform owner session must not be combined with an employee identity.
    mixed_owner_employee_client = app_module.app.test_client()
    with mixed_owner_employee_client.session_transaction() as session:
        session["platform_admin_id"] = "owner-test"
        session["employee_id"] = "u1"

    mixed_owner_employee_response = mixed_owner_employee_client.get(
        "/api/owner/companies"
    )
    check(
        "Mixed owner and employee session cannot access owner APIs",
        mixed_owner_employee_response.status_code == 401
    )

    mixed_owner_session_response = mixed_owner_employee_client.get(
        "/api/owner/session"
    )
    check(
        "Owner session endpoint rejects a mixed owner and employee session",
        mixed_owner_session_response.status_code == 401
    )

    owner_client = app_module.app.test_client()
    owner_login_token = owner_client.get(
        "/api/csrf-token"
    ).get_json()["csrf_token"]

    owner_login_response = owner_client.post(
        "/api/owner/login",
        json={
            "email": "owner@test.invalid",
            "password": "OwnerTestPassword!123"
        },
        headers={"X-CSRF-Token": owner_login_token}
    )
    check(
        "Valid platform owner login succeeds",
        owner_login_response.status_code == 200
    )

    owner_token = owner_client.get(
        "/api/csrf-token"
    ).get_json()["csrf_token"]

    owner_companies_response = owner_client.get("/api/owner/companies")
    check(
        "Authenticated owner can access owner companies",
        owner_companies_response.status_code == 200
    )

    owner_approval = owner_client.post(
        "/api/owner/subscriptions/approve/owner-sub-test",
        headers={"X-CSRF-Token": owner_token}
    )
    check(
        "Authenticated owner can approve a valid pending subscription",
        owner_approval.status_code == 200
    )

    repeated_approval = owner_client.post(
        "/api/owner/subscriptions/approve/owner-sub-test",
        headers={"X-CSRF-Token": owner_token}
    )
    check(
        "Already approved subscription cannot be approved again",
        repeated_approval.status_code == 409
    )

    with app_module.app.app_context():
        db = app_module.get_db()
        subscription = db.execute(
            "SELECT status, expires FROM subscriptions WHERE id=?",
            ("owner-sub-test",)
        ).fetchone()
        company = db.execute(
            "SELECT plan FROM companies WHERE id=?",
            ("c1",)
        ).fetchone()

        check(
            "Owner approval activates subscription and sets expiry",
            subscription is not None
            and subscription["status"] == "active"
            and bool(subscription["expires"])
        )
        check(
            "Owner approval updates the company's plan",
            company is not None and company["plan"] == "pro"
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
