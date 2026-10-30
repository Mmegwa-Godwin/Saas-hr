import sqlite3
import uuid

from werkzeug.security import generate_password_hash
from app import app
from database import get_db, init_db


def test_company_pause_resume_security_and_history(tmp_path):
    old_path = app.config.get("DATABASE_PATH")
    old_testing = app.config.get("TESTING")

    app.config["DATABASE_PATH"] = str(tmp_path / "lifecycle_test.db")
    app.config["TESTING"] = True

    try:
        with app.app_context():
            init_db()
            db = get_db()

            db.execute(
                "INSERT INTO companies VALUES (?, ?, ?, ?, ?, ?)",
                (
                    "life-c1",
                    "Lifecycle Test Company",
                    "life@test.invalid",
                    "unused",
                    "free",
                    "2026-01-01",
                ),
            )

            db.execute(
                """INSERT INTO users
                   (id, company_id, name, email, role, department,
                    photo, photo_hash, password, created, active)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    "life-u1",
                    "life-c1",
                    "Lifecycle Employee",
                    "employee@test.invalid",
                    "staff",
                    "HR",
                    "",
                    "",
                    generate_password_hash("TestPassword!123"),
                    "2026-01-01",
                    1,
                ),
            )

            db.execute(
                """INSERT INTO platform_admins (id, email, password, created)
                   VALUES (?, ?, ?, ?)""",
                (
                    "life-owner",
                    "owner@test.invalid",
                    generate_password_hash("TestPassword!123"),
                    "2026-01-01",
                ),
            )

            db.execute(
                """INSERT INTO auth_versions
                   (account_type, account_id, version)
                   VALUES ('company', 'life-c1', 1)"""
            )
            db.execute(
                """INSERT INTO auth_versions
                   (account_type, account_id, version)
                   VALUES ('owner', 'life-owner', 1)"""
            )
            db.execute(
                """INSERT INTO auth_versions
                   (account_type, account_id, version)
                   VALUES ('employee', 'life-u1', 1)"""
            )

            db.execute(
                """INSERT INTO attendance
                   (id, company_id, user_id, date, clock_in, clock_out, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    "life-a1",
                    "life-c1",
                    "life-u1",
                    "2026-10-20",
                    "2026-10-20T09:00:00",
                    "2026-10-20T17:00:00",
                    "present",
                ),
            )
            db.commit()

        owner = app.test_client()
        company = app.test_client()

        owner_token = owner.get("/api/csrf-token").get_json()["csrf_token"]
        company.get("/api/csrf-token")

        with owner.session_transaction() as sess:
            sess["platform_admin_id"] = "life-owner"
            sess["auth_version"] = 1

        with company.session_transaction() as sess:
            sess["company_id"] = "life-c1"
            sess["company_name"] = "Lifecycle Test Company"
            sess["auth_version"] = 1

        # An unauthenticated caller cannot change company status.
        anonymous = app.test_client()
        token = anonymous.get("/api/csrf-token").get_json()["csrf_token"]
        response = anonymous.patch(
            "/api/owner/companies/life-c1/status",
            json={"status": "paused", "reason": "Test pause"},
            headers={"X-CSRF-Token": token},
        )
        assert response.status_code == 401, response.get_json()

        # CSRF validation must reject a state change without its token.
        response = owner.patch(
            "/api/owner/companies/life-c1/status",
            json={"status": "paused", "reason": "Test pause"},
        )
        assert response.status_code == 403, response.get_json()

        headers = {"X-CSRF-Token": owner_token}

        # Pause the company.
        response = owner.patch(
            "/api/owner/companies/life-c1/status",
            json={"status": "paused", "reason": "Temporary operational break"},
            headers=headers,
        )
        assert response.status_code == 200, response.get_json()
        assert response.get_json()["operational_status"] == "paused"

        # The company can inspect its status but cannot use normal APIs.
        response = company.get("/api/company/lifecycle")
        assert response.status_code == 200, response.get_json()
        assert response.get_json()["status"] == "paused"

        response = company.get("/api/staff/life-c1")
        assert response.status_code == 423, response.get_json()

        # Resume the company.
        response = owner.patch(
            "/api/owner/companies/life-c1/status",
            json={"status": "active", "reason": "Operations resumed"},
            headers=headers,
        )
        assert response.status_code == 200, response.get_json()
        assert response.get_json()["operational_status"] == "active"

        response = company.get("/api/company/lifecycle")
        assert response.status_code == 200, response.get_json()
        assert response.get_json()["status"] == "active"

        response = company.get("/api/staff/life-c1")
        assert response.status_code == 200, response.get_json()

        # Both status changes must be audited.
        response = owner.get(
            "/api/owner/companies/life-c1/status-history"
        )
        assert response.status_code == 200, response.get_json()
        history = response.get_json()
        assert len(history) == 2, history
        assert {item["new_status"] for item in history} == {
            "paused",
            "active",
        }

        # Pausing/resuming must preserve employee and attendance records.
        with app.app_context():
            db = get_db()
            assert db.execute(
                "SELECT COUNT(*) FROM users WHERE id='life-u1'"
            ).fetchone()[0] == 1
            assert db.execute(
                "SELECT COUNT(*) FROM attendance WHERE id='life-a1'"
            ).fetchone()[0] == 1

    finally:
        app.config["DATABASE_PATH"] = old_path
        app.config["TESTING"] = old_testing


def test_employee_leave_blocks_attendance_and_reactivation_restores_it(tmp_path):
    old_path = app.config.get("DATABASE_PATH")
    old_testing = app.config.get("TESTING")

    app.config["DATABASE_PATH"] = str(tmp_path / "employee_lifecycle.db")
    app.config["TESTING"] = True

    try:
        with app.app_context():
            init_db()
            db = get_db()

            db.execute(
                "INSERT INTO companies VALUES (?, ?, ?, ?, ?, ?)",
                (
                    "leave-c1",
                    "Leave Test Company",
                    "leave@test.invalid",
                    "unused",
                    "free",
                    "2026-01-01",
                ),
            )

            db.execute(
                """INSERT INTO users
                   (id, company_id, name, email, role, department,
                    photo, photo_hash, password, created, active)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    "leave-u1",
                    "leave-c1",
                    "Leave Test Employee",
                    "leave-employee@test.invalid",
                    "staff",
                    "HR",
                    "",
                    "",
                    generate_password_hash("TestPassword!123"),
                    "2026-01-01",
                    1,
                ),
            )

            db.execute(
                """INSERT INTO auth_versions
                   (account_type, account_id, version)
                   VALUES ('company', 'leave-c1', 1)"""
            )
            db.execute(
                """INSERT INTO auth_versions
                   (account_type, account_id, version)
                   VALUES ('employee', 'leave-u1', 1)"""
            )
            db.commit()

        company = app.test_client()
        employee = app.test_client()

        company.get("/api/csrf-token")
        employee.get("/api/csrf-token")

        with company.session_transaction() as sess:
            sess["company_id"] = "leave-c1"
            sess["company_name"] = "Leave Test Company"
            sess["auth_version"] = 1

        with employee.session_transaction() as sess:
            sess["company_id"] = "leave-c1"
            sess["employee_id"] = "leave-u1"
            sess["employee_name"] = "Leave Test Employee"
            sess["auth_version"] = 1

        with company.session_transaction() as sess:
            company_csrf = sess["_csrf_token"]

        with employee.session_transaction() as sess:
            employee_csrf = sess["_csrf_token"]

        # Put the employee on leave.
        response = company.patch(
            "/api/staff/leave-c1/leave-u1/status",
            json={
                "status": "on_leave",
                "reason": "Approved annual leave",
            },
            headers={"X-CSRF-Token": company_csrf},
        )
        assert response.status_code == 200, response.get_json()
        assert response.get_json()["employment_status"] == "on_leave"

        # Both attendance actions must be blocked during leave.
        response = employee.post(
            "/api/attendance/clock-in",
            json={
                "company_id": "leave-c1",
                "user_id": "leave-u1",
                "lat": 6.5244,
                "lng": 3.3792,
            },
            headers={"X-CSRF-Token": employee_csrf},
        )
        assert response.status_code == 403, response.get_json()

        response = employee.post(
            "/api/attendance/clock-out",
            json={
                "company_id": "leave-c1",
                "user_id": "leave-u1",
            },
            headers={"X-CSRF-Token": employee_csrf},
        )
        assert response.status_code == 403, response.get_json()

        # Reactivate the employee.
        response = company.patch(
            "/api/staff/leave-c1/leave-u1/status",
            json={
                "status": "active",
                "reason": "Returned from approved leave",
            },
            headers={"X-CSRF-Token": company_csrf},
        )
        assert response.status_code == 200, response.get_json()
        assert response.get_json()["employment_status"] == "active"

        # Attendance should work again.
        response = employee.post(
            "/api/attendance/clock-in",
            json={
                "company_id": "leave-c1",
                "user_id": "leave-u1",
                "lat": 6.5244,
                "lng": 3.3792,
            },
            headers={"X-CSRF-Token": employee_csrf},
        )
        assert response.status_code == 200, response.get_json()

        response = employee.post(
            "/api/attendance/clock-out",
            json={
                "company_id": "leave-c1",
                "user_id": "leave-u1",
            },
            headers={"X-CSRF-Token": employee_csrf},
        )
        assert response.status_code == 200, response.get_json()

        # Confirm both status changes were audited.
        response = company.get(
            "/api/staff/leave-c1/leave-u1/status-history"
        )
        assert response.status_code == 200, response.get_json()

        history = response.get_json()
        assert len(history) == 2, history
        assert [item["new_status"] for item in history] == [
            "active",
            "on_leave",
        ] or [item["new_status"] for item in history] == [
            "on_leave",
            "active",
        ]

        assert {item["reason"] for item in history} == {
            "Approved annual leave",
            "Returned from approved leave",
        }

    finally:
        app.config["DATABASE_PATH"] = old_path
        app.config["TESTING"] = old_testing
