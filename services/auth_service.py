"""Service-layer helpers for auth-related operations."""

from werkzeug.security import check_password_hash

from database import get_db


def authenticate_company(email, password):
    if not email or not password:
        return None
    db = get_db()
    company = db.execute(
        "SELECT * FROM companies WHERE lower(email)=?",
        (email,),
    ).fetchone()
    if not company:
        return None
    if not check_password_hash(company["password"], password):
        return None
    return company


def authenticate_employee(company_id, email, password):
    if not company_id or not email or not password:
        return None
    db = get_db()
    employee = db.execute(
        """SELECT u.id, u.company_id, u.name, u.email, u.role, u.password,
                  u.active, u.employment_status, c.name AS company_name,
                  COALESCE(cl.status, 'active') AS company_status
           FROM users u
           JOIN companies c ON c.id = u.company_id
           LEFT JOIN company_lifecycle cl ON cl.company_id = c.id
           WHERE u.company_id = ? AND lower(u.email) = ?""",
        (company_id, email),
    ).fetchone()
    if not employee:
        return None
    if not employee["active"]:
        return None
    if employee["employment_status"] not in ("active", "on_leave"):
        return None
    if employee["company_status"] != "active":
        return None
    if not check_password_hash(employee["password"], password):
        return None
    return employee


def authenticate_owner(email, password):
    if not email or not password:
        return None
    db = get_db()
    admin = db.execute(
        "SELECT id, email, password FROM platform_admins WHERE lower(email)=?",
        (email,),
    ).fetchone()
    if not admin:
        return None
    if not check_password_hash(admin["password"], password):
        return None
    return admin
