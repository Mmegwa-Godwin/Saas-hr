import os
import tempfile
import importlib.util
from pathlib import Path
from werkzeug.security import generate_password_hash

spec = importlib.util.spec_from_file_location(
    "saas_hr_structure_test_app",
    Path("app.py").resolve()
)
app_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app_module)

tmp = tempfile.TemporaryDirectory()
app_module.app.config["DATABASE_PATH"] = os.path.join(tmp.name, "structure_test.db")
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


try:
    with app_module.app.app_context():
        app_module.init_db()
        db = app_module.get_db()

        db.execute(
            "INSERT INTO companies VALUES (?, ?, ?, ?, ?, ?)",
            ("c1", "Company One", "one@test.invalid", "x", "free", "2026-01-01")
        )
        db.execute(
            "INSERT INTO companies VALUES (?, ?, ?, ?, ?, ?)",
            ("c2", "Company Two", "two@test.invalid", "x", "free", "2026-01-01")
        )
        db.execute(
            "INSERT INTO auth_versions (account_type, account_id, version) VALUES (?, ?, ?)",
            ("company", "c1", 1)
        )
        db.execute(
            "INSERT INTO auth_versions (account_type, account_id, version) VALUES (?, ?, ?)",
            ("company", "c2", 1)
        )

        db.execute(
            """INSERT INTO users
               (id, company_id, name, email, role, department,
                photo, photo_hash, password, created, active)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "u2", "c2", "Other Employee", "other@test.invalid",
                "staff", "HR", "", "",
                generate_password_hash("TestPassword!123"),
                "2026-01-01", 1
            )
        )
        db.commit()

    client = app_module.app.test_client()
    csrf_response = client.get("/api/csrf-token")
    token = csrf_response.get_json()["csrf_token"]

    with client.session_transaction() as sess:
        sess["company_id"] = "c1"
        sess["company_name"] = "Company One"
        sess["auth_version"] = 1

    headers = {"X-CSRF-Token": token}

    # Department creation and duplicate prevention.
    response = client.post(
        "/api/departments",
        json={"name": "Production"},
        headers=headers
    )
    check("Create department", response.status_code == 201)
    department_id = response.get_json().get("id") if response.status_code == 201 else None

    duplicate = client.post(
        "/api/departments",
        json={"name": "production"},
        headers=headers
    )
    check("Reject duplicate department regardless of case", duplicate.status_code == 409)

    departments = client.get("/api/departments")
    check(
        "List company departments",
        departments.status_code == 200
        and any(d["name"] == "Production" for d in departments.get_json())
    )

    # Branch creation and duplicate prevention.
    response = client.post(
        "/api/branches",
        json={"name": "Main Factory", "address": "Lagos"},
        headers=headers
    )
    check("Create branch", response.status_code == 201)
    branch_id = response.get_json().get("id") if response.status_code == 201 else None

    duplicate_branch = client.post(
        "/api/branches",
        json={"name": "main factory", "address": "Another address"},
        headers=headers
    )
    check("Reject duplicate branch regardless of case", duplicate_branch.status_code == 409)

    branches = client.get("/api/branches")
    check(
        "List company branches",
        branches.status_code == 200
        and any(b["name"] == "Main Factory" for b in branches.get_json())
    )

    # Update existing department and branch.
    if department_id:
        renamed = client.patch(
            f"/api/departments/{department_id}",
            json={"name": "Manufacturing"},
            headers=headers
        )
        check(
            "Rename department",
            renamed.status_code == 200
            and renamed.get_json().get("name") == "Manufacturing"
        )
    else:
        check("Rename department", False)

    if branch_id:
        updated_branch = client.patch(
            f"/api/branches/{branch_id}",
            json={"address": "Ikeja, Lagos"},
            headers=headers
        )
        check(
            "Update branch address",
            updated_branch.status_code == 200
            and updated_branch.get_json().get("address") == "Ikeja, Lagos"
        )
    else:
        check("Update branch address", False)

    # Create an employee with department and branch assignments.
    if department_id and branch_id:
        employee = client.post(
            "/api/staff",
            json={
                "company_id": "c1",
                "name": "Test Employee",
                "email": "employee@test.invalid",
                "password": "SecureTestPassword!123",
                "role": "staff",
                "department_id": department_id,
                "branch_id": branch_id,
                "job_title": "Production Officer"
            },
            headers=headers
        )
        check("Create employee with department and branch", employee.status_code == 201)

        if employee.status_code == 201:
            with app_module.app.app_context():
                row = app_module.get_db().execute(
                    """SELECT department_id, branch_id, job_title
                       FROM users WHERE id = ? AND company_id = ?""",
                    (employee.get_json()["id"], "c1")
                ).fetchone()
                check(
                    "Persist employee assignment fields",
                    row is not None
                    and row["department_id"] == department_id
                    and row["branch_id"] == branch_id
                    and row["job_title"] == "Production Officer"
                )
    else:
        check("Create employee with department and branch", False)
        check("Persist employee assignment fields", False)

    # Reject a department belonging to another company.
    with client.session_transaction() as sess:
        sess["company_id"] = "c2"
        sess["company_name"] = "Company Two"
        sess["auth_version"] = 1

    other_company_departments = client.get("/api/departments")
    check(
        "Company cannot see another company's department",
        other_company_departments.status_code == 200
        and all(d["id"] != department_id for d in other_company_departments.get_json())
    )

    other_company_branches = client.get("/api/branches")
    check(
        "Company cannot see another company's branch",
        other_company_branches.status_code == 200
        and all(b["id"] != branch_id for b in other_company_branches.get_json())
    )

    if department_id:
        foreign_department = client.patch(
            f"/api/departments/{department_id}",
            json={"name": "Hijacked Department"},
            headers=headers
        )
        check("Block cross-company department update", foreign_department.status_code == 404)
    else:
        check("Block cross-company department update", False)

    if branch_id:
        foreign_branch = client.patch(
            f"/api/branches/{branch_id}",
            json={"name": "Hijacked Branch"},
            headers=headers
        )
        check("Block cross-company branch update", foreign_branch.status_code == 404)
    else:
        check("Block cross-company branch update", False)

    # Restore Company One session and verify invalid assignment rejection.
    with client.session_transaction() as sess:
        sess["company_id"] = "c1"
        sess["company_name"] = "Company One"
        sess["auth_version"] = 1

    if department_id and branch_id:
        invalid_assignment = client.post(
            "/api/staff",
            json={
                "company_id": "c1",
                "name": "Invalid Assignment",
                "email": "invalid@test.invalid",
                "password": "SecureTestPassword!123",
                "role": "staff",
                "department_id": "not-a-company-department",
                "branch_id": branch_id,
                "job_title": "Assistant"
            },
            headers=headers
        )
        check(
            "Reject nonexistent department assignment",
            invalid_assignment.status_code == 400
        )
    else:
        check("Reject nonexistent department assignment", False)

finally:
    tmp.cleanup()

print(f"\nRESULTS: {passed} passed, {failed} failed")
print("ALL STRUCTURE TESTS PASSED" if failed == 0 else "INVESTIGATION REQUIRED")
