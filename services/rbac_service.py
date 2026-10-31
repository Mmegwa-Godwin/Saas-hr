"""Company-scoped role and department permission checks."""

from database import get_db


DEPARTMENT_NAMES = {
    "accounting": "Accounting",
    "stores": "Stores",
    "procurement": "Procurement",
    "welfare_canteen": "Welfare/Canteen",
    "maintenance_repair": "Maintenance/Repair",
    "marketing": "Marketing",
    "sales": "Sales",
    "media": "Media",
    "hr": "HR",
}

VALID_ACTIONS = {"view", "create", "update", "approve", "manage"}


def normalize_role(role):
    """Normalize legacy role names without changing stored employee data."""
    value = str(role or "").strip().lower()

    if value in {"hr", "human resources"}:
        return "hr"

    if value in {"admin", "manager", "staff"}:
        return value

    return ""


def has_permission(company_id, user_id, department_key, action):
    """
    Check one employee's permission in one company department.

    Explicit user denials override role grants.
    Explicit user grants can add permissions.
    Admin employees have company-wide administrative authority.
    """
    if not company_id or not user_id:
        return False

    if department_key not in DEPARTMENT_NAMES:
        return False

    if action not in VALID_ACTIONS:
        return False

    db = get_db()

    employee = db.execute(
        """
        SELECT id, company_id, role, active, employment_status
        FROM users
        WHERE id = ? AND company_id = ?
        """,
        (user_id, company_id),
    ).fetchone()

    if not employee or not employee["active"]:
        return False

    if employee["employment_status"] not in ("active", "on_leave"):
        return False

    company = db.execute(
        """
        SELECT status
        FROM company_lifecycle
        WHERE company_id = ?
        """,
        (company_id,),
    ).fetchone()

    if not company or company["status"] != "active":
        return False

    department = db.execute(
        """
        SELECT id
        FROM departments
        WHERE company_id = ?
          AND lower(name) = lower(?)
          AND active = 1
        """,
        (company_id, DEPARTMENT_NAMES[department_key]),
    ).fetchone()

    if not department:
        return False

    department_id = department["id"]

    role_key = normalize_role(employee["role"])

    if not role_key:
        return False

    # Admin employees have company-wide authority.
    if role_key == "admin":
        return True

    assignment = db.execute(
        """
        SELECT 1
        FROM user_departments
        WHERE company_id = ?
          AND user_id = ?
          AND department_id = ?
        """,
        (company_id, user_id, department_id),
    ).fetchone()

    if not assignment:
        return False

    permission = db.execute(
        """
        SELECT id
        FROM permissions
        WHERE code = ?
          AND department_key = ?
          AND action = ?
        """,
        (f"{department_key}.{action}", department_key, action),
    ).fetchone()

    if not permission:
        return False

    override = db.execute(
        """
        SELECT effect
        FROM user_permissions
        WHERE company_id = ?
          AND user_id = ?
          AND department_id = ?
          AND permission_id = ?
        """,
        (company_id, user_id, department_id, permission["id"]),
    ).fetchone()

    if override:
        return override["effect"] == "grant"

    role = db.execute(
        """
        SELECT id
        FROM roles
        WHERE company_id = ?
          AND role_key = ?
        """,
        (company_id, role_key),
    ).fetchone()

    if not role:
        return False

    grant = db.execute(
        """
        SELECT 1
        FROM role_permissions
        WHERE role_id = ?
          AND permission_id = ?
        """,
        (role["id"], permission["id"]),
    ).fetchone()

    return grant is not None
