"""Authenticated company-scoped Accounting API routes."""

import sqlite3

from flask import jsonify, request, session

from services.accounting_service import (
    create_account,
    list_accounts,
    update_account,
    deactivate_account,
    create_accounting_period,
    list_accounting_periods,
    close_accounting_period,
)


def register_accounting_routes(app):
    """Register Accounting endpoints on the existing Flask application."""

    def actor_context():
        employee_id = session.get("employee_id")
        company_id = session.get("company_id")

        if not company_id:
            return None

        return {
            "company_id": str(company_id),
            "actor_id": str(employee_id or company_id),
            "actor_type": "employee" if employee_id else "company",
        }

    def json_body():
        payload = request.get_json(silent=True)

        if not isinstance(payload, dict):
            return None, (jsonify({"error": "A JSON object is required."}), 400)

        # Tenant and audit identity are always taken from the session.
        if "company_id" in payload or "actor_id" in payload:
            return None, (
                jsonify({"error": "Company and actor identity cannot be supplied in the request body."}),
                400,
            )

        return payload, None

    def error_response(error):
        if isinstance(error, sqlite3.IntegrityError):
            return jsonify({"error": "The record conflicts with existing data."}), 409

        message = str(error)
        lowered = message.lower()

        if "not found" in lowered:
            return jsonify({"error": message}), 404

        if "overlap" in lowered:
            return jsonify({"error": message}), 409

        if isinstance(error, ValueError):
            return jsonify({"error": message}), 400

        app.logger.exception("Accounting API operation failed")
        return jsonify({"error": "Unable to complete the Accounting operation."}), 500

    def row_json(row):
        return dict(row) if row is not None else None

    def accounts():
        context = actor_context()
        if not context:
            return jsonify({"error": "Authentication required."}), 401

        account_type = request.args.get("account_type")
        include_value = request.args.get("include_inactive", "false").lower()

        if include_value not in ("true", "false"):
            return jsonify({"error": "include_inactive must be true or false."}), 400

        try:
            rows = list_accounts(
                context["company_id"],
                account_type=account_type,
                include_inactive=(include_value == "true"),
            )
            return jsonify({"accounts": [row_json(row) for row in rows]}), 200
        except Exception as exc:
            return error_response(exc)

    def account_create():
        context = actor_context()
        if not context:
            return jsonify({"error": "Authentication required."}), 401

        data, error = json_body()
        if error:
            return error

        try:
            account = create_account(
                company_id=context["company_id"],
                account_code=data.get("account_code"),
                account_name=data.get("account_name"),
                account_type=data.get("account_type"),
                actor_id=context["actor_id"],
                parent_account_id=data.get("parent_account_id"),
                description=data.get("description", ""),
                is_control_account=data.get("is_control_account", False),
                actor_type=context["actor_type"],
            )
            return jsonify({"account": row_json(account)}), 201
        except Exception as exc:
            return error_response(exc)

    def account_update(account_id):
        context = actor_context()
        if not context:
            return jsonify({"error": "Authentication required."}), 401

        data, error = json_body()
        if error:
            return error

        allowed = {"account_name", "description", "parent_account_id"}
        unknown = set(data) - allowed
        if unknown:
            return jsonify({"error": "Unsupported account update field."}), 400

        try:
            account = update_account(
                company_id=context["company_id"],
                account_id=account_id,
                actor_id=context["actor_id"],
                account_name=data.get("account_name"),
                description=data.get("description"),
                parent_account_id=data.get("parent_account_id"),
                change_parent=("parent_account_id" in data),
                actor_type=context["actor_type"],
            )
            return jsonify({"account": row_json(account)}), 200
        except Exception as exc:
            return error_response(exc)

    def account_deactivate(account_id):
        context = actor_context()
        if not context:
            return jsonify({"error": "Authentication required."}), 401

        try:
            account = deactivate_account(
                company_id=context["company_id"],
                account_id=account_id,
                actor_id=context["actor_id"],
                actor_type=context["actor_type"],
            )
            return jsonify({"account": row_json(account)}), 200
        except Exception as exc:
            return error_response(exc)

    def periods():
        context = actor_context()
        if not context:
            return jsonify({"error": "Authentication required."}), 401

        try:
            rows = list_accounting_periods(
                context["company_id"],
                status=request.args.get("status"),
            )
            return jsonify({"periods": [row_json(row) for row in rows]}), 200
        except Exception as exc:
            return error_response(exc)

    def period_create():
        context = actor_context()
        if not context:
            return jsonify({"error": "Authentication required."}), 401

        data, error = json_body()
        if error:
            return error

        try:
            period = create_accounting_period(
                company_id=context["company_id"],
                name=data.get("name"),
                start_date=data.get("start_date"),
                end_date=data.get("end_date"),
                actor_id=context["actor_id"],
                actor_type=context["actor_type"],
            )
            return jsonify({"period": row_json(period)}), 201
        except Exception as exc:
            return error_response(exc)

    def period_close(period_id):
        context = actor_context()
        if not context:
            return jsonify({"error": "Authentication required."}), 401

        try:
            period = close_accounting_period(
                company_id=context["company_id"],
                period_id=period_id,
                actor_id=context["actor_id"],
                actor_type=context["actor_type"],
            )
            return jsonify({"period": row_json(period)}), 200
        except Exception as exc:
            return error_response(exc)

    app.add_url_rule(
        "/api/accounting/accounts",
        endpoint="accounting_accounts",
        view_func=accounts,
        methods=["GET"],
    )
    app.add_url_rule(
        "/api/accounting/accounts",
        endpoint="accounting_account_create",
        view_func=account_create,
        methods=["POST"],
    )
    app.add_url_rule(
        "/api/accounting/accounts/<account_id>",
        endpoint="accounting_account_update",
        view_func=account_update,
        methods=["PATCH"],
    )
    app.add_url_rule(
        "/api/accounting/accounts/<account_id>/deactivate",
        endpoint="accounting_account_deactivate",
        view_func=account_deactivate,
        methods=["POST"],
    )
    app.add_url_rule(
        "/api/accounting/periods",
        endpoint="accounting_periods",
        view_func=periods,
        methods=["GET"],
    )
    app.add_url_rule(
        "/api/accounting/periods",
        endpoint="accounting_period_create",
        view_func=period_create,
        methods=["POST"],
    )
    app.add_url_rule(
        "/api/accounting/periods/<period_id>/close",
        endpoint="accounting_period_close",
        view_func=period_close,
        methods=["POST"],
    )
