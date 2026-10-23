import os
import tempfile
import importlib.util
from pathlib import Path
from werkzeug.security import generate_password_hash

spec = importlib.util.spec_from_file_location(
    "saas_hr_csrf_test", Path("app.py").resolve()
)
app_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app_module)

tmp = tempfile.TemporaryDirectory()
app_module.DB = os.path.join(tmp.name, "test.db")
app_module.app.config["TESTING"] = True

try:
    with app_module.app.app_context():
        app_module.init_db()
        db = app_module.get_db()

        db.execute(
            "INSERT INTO companies VALUES (?, ?, ?, ?, ?, ?)",
            ("c1", "Company One", "one@test.invalid", "x", "free", "2026-01-01")
        )
        db.execute(
            """INSERT INTO users
            (id, company_id, name, email, role, department,
             photo, photo_hash, password, created, active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "u1", "c1", "Employee", "u1@test.invalid", "staff",
                "HR", "", "", generate_password_hash("TestPassword!123"),
                "2026-01-01", 1
            )
        )
        db.commit()

    client = app_module.app.test_client()
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

    def get_csrf_token():
        response = client.get("/api/csrf-token")
        return response.get_json()["csrf_token"]

    def login(token):
        return client.post(
            "/api/employee/login",
            json={
                "company_id": "c1",
                "email": "u1@test.invalid",
                "password": "TestPassword!123"
            },
            headers={"X-CSRF-Token": token}
        )

    token = get_csrf_token()
    first_login = login(token)
    check("Valid employee login succeeds", first_login.status_code == 200)

    # Login clears the session, so obtain a fresh token.
    token = get_csrf_token()

    with app_module.app.app_context():
        db = app_module.get_db()
        db.execute("UPDATE users SET active=0 WHERE id='u1'")
        db.commit()

    inactive_login = login(token)
    check("Inactive employee login is rejected", inactive_login.status_code == 401)

    # Refresh the token before testing login after reactivation.
    token = get_csrf_token()

    with app_module.app.app_context():
        db = app_module.get_db()
        db.execute("UPDATE users SET active=1 WHERE id='u1'")
        db.commit()

    reactivated_login = login(token)
    check("Reactivated employee can log in", reactivated_login.status_code == 200)

    print(f"\nRESULTS: {passed} passed, {failed} failed")
    if failed:
        print("INVESTIGATION REQUIRED")
    else:
        print("ALL CSRF AND EMPLOYEE LOGIN TESTS PASSED")

finally:
    tmp.cleanup()
