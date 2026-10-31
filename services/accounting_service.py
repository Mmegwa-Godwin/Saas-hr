"""Company-scoped Accounting operations.

This module manages chart-of-account records and accounting periods.
Journal creation, approval and posting are implemented separately.
"""

import json
import uuid
from datetime import date

from database import get_db


ACCOUNT_TYPES = {
    "asset": "debit",
    "expense": "debit",
    "liability": "credit",
    "equity": "credit",
    "income": "credit",
}


def _required(value, field):
    value = str(value or "").strip()
    if not value:
        raise ValueError(f"{field} is required.")
    return value


def _company_exists(db, company_id):
    company = db.execute(
        "SELECT id FROM companies WHERE id = ?",
        (company_id,),
    ).fetchone()
    if not company:
        raise ValueError("Company not found.")
    return company


def _audit(
    db, company_id, actor_id, action, entity_type,
    entity_id, details=None, actor_type="employee"
):
    if actor_type not in {"employee", "company", "owner", "system"}:
        raise ValueError("Invalid audit actor type.")

    db.execute(
        """
        INSERT INTO accounting_audit_log (
            id, company_id, actor_type, actor_id, action,
            entity_type, entity_id, details_json, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """,
        (
            uuid.uuid4().hex,
            company_id,
            actor_type,
            str(actor_id),
            action,
            entity_type,
            entity_id,
            json.dumps(details or {}, sort_keys=True),
        ),
    )


def _account(db, company_id, account_id):
    row = db.execute(
        """
        SELECT *
        FROM chart_of_accounts
        WHERE company_id = ? AND id = ?
        """,
        (company_id, account_id),
    ).fetchone()
    if not row:
        raise ValueError("Account not found in this company.")
    return row


def _validate_parent(db, company_id, parent_account_id, account_id=None):
    if not parent_account_id:
        return None

    parent_account_id = str(parent_account_id).strip()

    if account_id and parent_account_id == account_id:
        raise ValueError("An account cannot be its own parent.")

    parent = _account(db, company_id, parent_account_id)

    if not parent["active"]:
        raise ValueError("Parent account is inactive.")

    if account_id:
        ancestor_id = parent_account_id
        while ancestor_id:
            if ancestor_id == account_id:
                raise ValueError("Circular account hierarchy is not allowed.")

            ancestor = _account(db, company_id, ancestor_id)
            ancestor_id = ancestor["parent_account_id"]

    return parent


def create_account(
    company_id,
    account_code,
    account_name,
    account_type,
    actor_id,
    parent_account_id=None,
    description="",
    is_control_account=False,
    actor_type="employee",
):
    """Create a company-owned chart-of-account record."""
    company_id = _required(company_id, "Company")
    actor_id = _required(actor_id, "Actor")
    account_code = _required(account_code, "Account code").upper()
    account_name = _required(account_name, "Account name")
    account_type = _required(account_type, "Account type").lower()

    if account_type not in ACCOUNT_TYPES:
        raise ValueError("Invalid account type.")

    if len(account_code) > 30:
        raise ValueError("Account code cannot exceed 30 characters.")

    if len(account_name) > 150:
        raise ValueError("Account name cannot exceed 150 characters.")

    if not isinstance(is_control_account, bool):
        raise ValueError("is_control_account must be true or false.")

    db = get_db()
    _company_exists(db, company_id)
    parent = _validate_parent(db, company_id, parent_account_id)
    parent_account_id = parent["id"] if parent else None

    description = str(description or "").strip()
    if len(description) > 1000:
        raise ValueError("Description cannot exceed 1000 characters.")

    account_id = uuid.uuid4().hex

    try:
        db.execute(
            """
            INSERT INTO chart_of_accounts (
                id, company_id, account_code, account_name,
                account_type, normal_balance, parent_account_id,
                description, is_control_account, active,
                created_by, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, datetime('now'), datetime('now'))
            """,
            (
                account_id,
                company_id,
                account_code,
                account_name,
                account_type,
                ACCOUNT_TYPES[account_type],
                parent_account_id,
                description,
                int(is_control_account),
                actor_id,
            ),
        )
        _audit(
            db, company_id, actor_id, "account.created",
            "chart_of_accounts", account_id,
            {"account_code": account_code, "account_type": account_type},
            actor_type=actor_type,
        )
        db.commit()
    except Exception:
        db.rollback()
        raise

    return _account(db, company_id, account_id)


def list_accounts(company_id, account_type=None, include_inactive=False):
    """List accounts belonging only to the requested company."""
    company_id = _required(company_id, "Company")
    db = get_db()
    _company_exists(db, company_id)

    query = """
        SELECT *
        FROM chart_of_accounts
        WHERE company_id = ?
    """
    params = [company_id]

    if account_type:
        account_type = str(account_type).strip().lower()
        if account_type not in ACCOUNT_TYPES:
            raise ValueError("Invalid account type.")
        query += " AND account_type = ?"
        params.append(account_type)

    if not include_inactive:
        query += " AND active = 1"

    query += " ORDER BY account_code"
    return db.execute(query, params).fetchall()


def update_account(
    company_id,
    account_id,
    actor_id,
    account_name=None,
    description=None,
    parent_account_id=None,
    change_parent=False,
    actor_type="employee",
):
    """Update editable account details without changing its identity."""
    company_id = _required(company_id, "Company")
    account_id = _required(account_id, "Account")
    actor_id = _required(actor_id, "Actor")

    db = get_db()
    _company_exists(db, company_id)
    current = _account(db, company_id, account_id)

    if not current["active"]:
        raise ValueError("Inactive accounts cannot be updated.")

    new_name = (
        _required(account_name, "Account name")
        if account_name is not None
        else current["account_name"]
    )
    new_description = (
        str(description or "").strip()
        if description is not None
        else current["description"]
    )

    if len(new_description) > 1000:
        raise ValueError("Description cannot exceed 1000 characters.")

    new_parent = current["parent_account_id"]
    if change_parent:
        parent = _validate_parent(
            db, company_id, parent_account_id, account_id
        )
        new_parent = parent["id"] if parent else None

    try:
        db.execute(
            """
            UPDATE chart_of_accounts
            SET account_name = ?, description = ?,
                parent_account_id = ?, updated_at = datetime('now')
            WHERE company_id = ? AND id = ?
            """,
            (
                new_name,
                new_description,
                new_parent,
                company_id,
                account_id,
            ),
        )
        _audit(
            db, company_id, actor_id, "account.updated",
            "chart_of_accounts", account_id,
            {"account_name": new_name},
            actor_type=actor_type,
        )
        db.commit()
    except Exception:
        db.rollback()
        raise

    return _account(db, company_id, account_id)


def deactivate_account(
    company_id, account_id, actor_id, actor_type="employee"
):
    """Deactivate an unused account; never delete accounting history."""
    company_id = _required(company_id, "Company")
    account_id = _required(account_id, "Account")
    actor_id = _required(actor_id, "Actor")

    db = get_db()
    _company_exists(db, company_id)
    account = _account(db, company_id, account_id)

    if not account["active"]:
        return account

    existing_use = db.execute(
        """
        SELECT 1
        FROM journal_lines jl
        JOIN journal_entries je
          ON je.id = jl.journal_entry_id
         AND je.company_id = jl.company_id
        WHERE jl.company_id = ?
          AND jl.account_id = ?
        LIMIT 1
        """,
        (company_id, account_id),
    ).fetchone()

    if existing_use:
        raise ValueError(
            "An account referenced by a journal cannot be deactivated."
        )

    try:
        db.execute(
            """
            UPDATE chart_of_accounts
            SET active = 0, updated_at = datetime('now')
            WHERE company_id = ? AND id = ?
            """,
            (company_id, account_id),
        )
        _audit(
            db, company_id, actor_id, "account.deactivated",
            "chart_of_accounts", account_id,
            actor_type=actor_type,
        )
        db.commit()
    except Exception:
        db.rollback()
        raise

    return _account(db, company_id, account_id)


def _parse_date(value, field):
    value = _required(value, field)
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{field} must use YYYY-MM-DD format.") from exc

    if parsed.isoformat() != value:
        raise ValueError(f"{field} must use YYYY-MM-DD format.")

    return parsed


def create_accounting_period(
    company_id,
    name,
    start_date,
    end_date,
    actor_id,
    actor_type="employee",
):
    """Create a non-overlapping accounting period for a company."""
    company_id = _required(company_id, "Company")
    name = _required(name, "Period name")
    actor_id = _required(actor_id, "Actor")

    start = _parse_date(start_date, "Start date")
    end = _parse_date(end_date, "End date")

    if start > end:
        raise ValueError("Start date cannot be after end date.")

    db = get_db()
    _company_exists(db, company_id)

    overlap = db.execute(
        """
        SELECT id, name
        FROM accounting_periods
        WHERE company_id = ?
          AND start_date <= ?
          AND end_date >= ?
        LIMIT 1
        """,
        (company_id, end.isoformat(), start.isoformat()),
    ).fetchone()

    if overlap:
        raise ValueError(
            f"Period overlaps with existing period: {overlap['name']}."
        )

    period_id = uuid.uuid4().hex

    try:
        db.execute(
            """
            INSERT INTO accounting_periods (
                id, company_id, name, start_date, end_date,
                status, created_by, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, 'open', ?, datetime('now'), datetime('now'))
            """,
            (
                period_id,
                company_id,
                name,
                start.isoformat(),
                end.isoformat(),
                actor_id,
            ),
        )
        _audit(
            db, company_id, actor_id, "period.created",
            "accounting_periods", period_id,
            {"start_date": start.isoformat(), "end_date": end.isoformat()},
            actor_type=actor_type,
        )
        db.commit()
    except Exception:
        db.rollback()
        raise

    return get_accounting_period(company_id, period_id)


def get_accounting_period(company_id, period_id):
    company_id = _required(company_id, "Company")
    period_id = _required(period_id, "Period")

    row = get_db().execute(
        """
        SELECT *
        FROM accounting_periods
        WHERE company_id = ? AND id = ?
        """,
        (company_id, period_id),
    ).fetchone()

    if not row:
        raise ValueError("Accounting period not found in this company.")

    return row


def list_accounting_periods(company_id, status=None):
    company_id = _required(company_id, "Company")
    db = get_db()
    _company_exists(db, company_id)

    query = """
        SELECT *
        FROM accounting_periods
        WHERE company_id = ?
    """
    params = [company_id]

    if status:
        status = str(status).strip().lower()
        if status not in {"open", "closed"}:
            raise ValueError("Invalid accounting period status.")
        query += " AND status = ?"
        params.append(status)

    query += " ORDER BY start_date DESC"
    return db.execute(query, params).fetchall()


def close_accounting_period(
    company_id, period_id, actor_id, actor_type="employee"
):
    """Close a period only when it has no draft or approved journals."""
    company_id = _required(company_id, "Company")
    period_id = _required(period_id, "Period")
    actor_id = _required(actor_id, "Actor")

    db = get_db()
    _company_exists(db, company_id)
    period = get_accounting_period(company_id, period_id)

    if period["status"] == "closed":
        return period

    unfinished = db.execute(
        """
        SELECT COUNT(*) AS total
        FROM journal_entries
        WHERE company_id = ?
          AND period_id = ?
          AND status IN ('draft', 'approved')
        """,
        (company_id, period_id),
    ).fetchone()["total"]

    if unfinished:
        raise ValueError(
            "Cannot close a period while draft or approved journals remain."
        )

    try:
        db.execute(
            """
            UPDATE accounting_periods
            SET status = 'closed', updated_at = datetime('now')
            WHERE company_id = ? AND id = ?
            """,
            (company_id, period_id),
        )
        _audit(
            db, company_id, actor_id, "period.closed",
            "accounting_periods", period_id,
            actor_type=actor_type,
        )
        db.commit()
    except Exception:
        db.rollback()
        raise

    return get_accounting_period(company_id, period_id)
