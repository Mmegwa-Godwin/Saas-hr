from __future__ import annotations

import secrets

from flask import jsonify, request, session

from database import get_db


def compare_csrf_token() -> bool:
    expected_token = session.get("_csrf_token")
    supplied_token = request.headers.get("X-CSRF-Token", "")

    if not isinstance(expected_token, str):
        return False
    if not isinstance(supplied_token, str):
        return False
    if not expected_token or not supplied_token:
        return False
    return secrets.compare_digest(expected_token, supplied_token)


def require_company_session():
    company_id = session.get("company_id")
    if not company_id:
        return jsonify({"error": "Authentication required"}), 401
    return None


def require_employee_session():
    employee_id = session.get("employee_id")
    company_id = session.get("company_id")
    if not employee_id or not company_id:
        return jsonify({"error": "Authentication required"}), 401

    employee = get_db().execute(
        "SELECT active FROM users WHERE id=? AND company_id=?",
        (employee_id, company_id),
    ).fetchone()

    if not employee or not employee["active"]:
        session.clear()
        return jsonify({"error": "Employee account is inactive"}), 401

    return None


def require_owner_session():
    owner_id = session.get("platform_admin_id")
    if not owner_id or session.get("company_id"):
        return jsonify({"error": "Platform owner authentication required"}), 401

    admin = get_db().execute(
        "SELECT id FROM platform_admins WHERE id=?",
        (owner_id,),
    ).fetchone()

    if not admin:
        session.clear()
        return jsonify({"error": "Platform owner session expired"}), 401

    return None


def enforce_csrf_for_mutation():
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return None

    if not compare_csrf_token():
        return jsonify({"error": "CSRF validation failed. Refresh the page and try again."}), 403

    return None
