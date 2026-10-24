import json
import os
import secrets
import ssl
import smtplib
import uuid
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from math import asin, cos, radians, sin, sqrt
from urllib.parse import urlparse

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.smtp.env'))
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))
except ImportError:
    pass

from flask import Flask, abort, g, jsonify, render_template_string, request, session
from werkzeug.security import check_password_hash, generate_password_hash

from auth_helpers import enforce_csrf_for_mutation, require_company_session, require_employee_session, require_owner_session
from config import AppConfig
from database import close_db, get_db, init_db

app = Flask(__name__)
app.config.from_object(AppConfig)
app.teardown_appcontext(close_db)

with app.app_context():
    init_db()

IS_PRODUCTION = AppConfig.IS_PRODUCTION


@app.before_request
def security_guard():
    path = request.path

    csrf_error = enforce_csrf_for_mutation()
    if csrf_error is not None:
        return csrf_error

    public_api = (
        '/api/csrf-token',
        '/api/company/register',
        '/api/company/login',
        '/api/employee/login',
        '/api/employee/session',
        '/api/logout',
        '/api/session',
        '/api/owner/login',
        '/api/owner/session',
        '/api/owner/logout',
        '/api/password/forgot',
        '/api/password/reset',
    )

    if path == '/' or path in public_api:
        return None

    if not path.startswith('/api/'):
        return None

    owner_error = require_owner_session() if path.startswith('/api/owner/') else None
    if owner_error is not None:
        return owner_error

    employee_error = require_employee_session() if session.get('employee_id') else None
    if employee_error is not None:
        return employee_error

    company_error = require_company_session()
    if company_error is not None:
        return company_error

    if path == '/api/subscriptions/all' or path.startswith('/api/subscriptions/approve/'):
        return jsonify({"error": "Use the authenticated platform owner dashboard"}), 403

    parts = path.strip('/').split('/')
    company_routes = {
        ('staff', 2),
        ('attendance', 2),
        ('stats', 2),
        ('subscriptions', 2),
    }

    if len(parts) >= 3 and (parts[1], 2) in company_routes:
        route_name = parts[2]
        special_attendance_routes = (
            parts[1] == 'attendance'
            and route_name in ('clock-in', 'clock-out', 'status')
        )
        if not special_attendance_routes and route_name != session.get('company_id'):
            return jsonify({"error": "Access denied"}), 403

    data = request.get_json(silent=True) or {}
    supplied_cid = data.get('company_id')
    if supplied_cid is not None and str(supplied_cid) != str(session.get('company_id')):
        return jsonify({"error": "Access denied"}), 403

    user_id = data.get('user_id')
    if not user_id and len(parts) >= 4 and parts[1] == 'attendance' and parts[2] == 'status':
        user_id = parts[3]

    if user_id:
        user = get_db().execute(
            "SELECT id FROM users WHERE id=? AND company_id=?",
            (user_id, session.get('company_id')),
        ).fetchone()
        if not user:
            return jsonify({"error": "Staff member not found"}), 404

    return None


def haversine(lat1, lon1, lat2, lon2):
    R = 6371000
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    c = 2 * asin(sqrt(a))
    return R * c
