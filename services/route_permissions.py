"""Exact employee API route-to-permission mapping.

Unmapped routes are denied to employee sessions by default.
Company accounts and platform-owner sessions use separate authorization.
"""

EMPLOYEE_ROUTE_PERMISSIONS = {
    # Departments
    ("company_departments", "GET"): ("hr", "view"),
    ("company_departments", "POST"): ("hr", "create"),
    ("update_company_department", "PATCH"): ("hr", "manage"),

    # Branches
    ("company_branches", "GET"): ("hr", "view"),
    ("company_branches", "POST"): ("hr", "create"),
    ("update_company_branch", "PATCH"): ("hr", "manage"),

    # Employees
    ("add_staff", "POST"): ("hr", "create"),
    ("set_staff_active", "PATCH"): ("hr", "manage"),
    ("list_staff", "GET"): ("hr", "view"),
    ("set_employee_lifecycle_status", "PATCH"): ("hr", "manage"),
    ("employee_lifecycle_history", "GET"): ("hr", "view"),

    # Attendance
    ("att", "GET"): ("hr", "view"),
    ("correct_attendance", "POST"): ("hr", "update"),
    ("attendance_audit", "GET"): ("hr", "view"),
    ("stats", "GET"): ("hr", "view"),

    # Accounting
    ("accounting_accounts", "GET"): ("accounting", "view"),
    ("accounting_account_create", "POST"): ("accounting", "create"),
    ("accounting_account_update", "PATCH"): ("accounting", "update"),
    ("accounting_account_deactivate", "POST"): ("accounting", "manage"),
    ("accounting_periods", "GET"): ("accounting", "view"),
    ("accounting_period_create", "POST"): ("accounting", "create"),
    ("accounting_period_close", "POST"): ("accounting", "manage"),
}


def get_employee_route_permission(endpoint, method):
    """Return (department, action), or None when the route is unmapped."""
    if not endpoint or not method:
        return None

    return EMPLOYEE_ROUTE_PERMISSIONS.get(
        (str(endpoint), str(method).upper())
    )
