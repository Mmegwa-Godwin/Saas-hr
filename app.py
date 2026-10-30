import json
import ssl
import os, uuid, sqlite3, secrets, hashlib, smtplib
from datetime import datetime, timedelta, timezone
from math import radians, cos, sin, asin, sqrt
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.smtp.env'))
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))
except ImportError:
    pass

from flask import Flask, request, jsonify, g, render_template, render_template_string, session, abort
from email.message import EmailMessage
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash, check_password_hash
from config import AppConfig
from database import close_db, get_db, init_db
from services.auth_service import authenticate_company, authenticate_employee, authenticate_owner

app = Flask(__name__)
app.config.from_object(AppConfig)
app.teardown_appcontext(close_db)

IS_PRODUCTION = AppConfig.IS_PRODUCTION
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
def haversine(lat1,lon1,lat2,lon2):
    R=6371000
    dlat=radians(lat2-lat1); dlon=radians(lon2-lon1)
    a=sin(dlat/2)**2+cos(radians(lat1))*cos(radians(lat2))*sin(dlon/2)**2
    c=2*asin(sqrt(a))
    return R*c
@app.before_request
def before(): init_db()


def get_or_create_auth_version(account_type, account_id):
    """Return the persistent session version for an authenticated account."""
    db = get_db()
    db.execute(
        """
        INSERT OR IGNORE INTO auth_versions
            (account_type, account_id, version)
        VALUES (?, ?, 1)
        """,
        (account_type, str(account_id)),
    )
    db.commit()
    row = db.execute(
        """
        SELECT version FROM auth_versions
        WHERE account_type=? AND account_id=?
        """,
        (account_type, str(account_id)),
    ).fetchone()
    return int(row["version"])


@app.before_request
def security_guard():
    path = request.path

    # CSRF protection for all state-changing requests.
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        expected_token = session.get("_csrf_token")
        supplied_token = request.headers.get("X-CSRF-Token", "")
        if (
            not isinstance(expected_token, str)
            or not isinstance(supplied_token, str)
            or not expected_token
            or not supplied_token
            or not secrets.compare_digest(expected_token, supplied_token)
        ):
            return jsonify({"error": "CSRF validation failed. Refresh the page and try again."}), 403

    # A missing or outdated version invalidates legacy and revoked sessions.
    identity = None
    if session.get("platform_admin_id"):
        identity = ("owner", session.get("platform_admin_id"))
    elif session.get("employee_id"):
        identity = ("employee", session.get("employee_id"))
    elif session.get("company_id"):
        identity = ("company", session.get("company_id"))

    if identity:
        account_type, account_id = identity
        current = get_db().execute(
            """
            SELECT version FROM auth_versions
            WHERE account_type=? AND account_id=?
            """,
            (account_type, str(account_id)),
        ).fetchone()
        session_version = session.get("auth_version")

        if (
            current is None
            or type(session_version) is not int
            or session_version != int(current["version"])
        ):
            session.clear()

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

    # Owner APIs require a valid platform-owner session.
    if path.startswith('/api/owner/'):
        owner_id = session.get('platform_admin_id')
        if (
            not owner_id
            or session.get('company_id')
            or session.get('employee_id')
        ):
            return jsonify({"error": "Platform owner authentication required"}), 401

        admin = get_db().execute(
            "SELECT id FROM platform_admins WHERE id=?",
            (owner_id,)
        ).fetchone()

        if not admin:
            session.clear()
            return jsonify({"error": "Platform owner session expired"}), 401

        return None

    # Employee sessions are restricted to their own active account.
    employee_id = session.get('employee_id')
    if employee_id:
        cid = session.get('company_id')
        employee_record = get_db().execute(
            """SELECT active, employment_status
               FROM users WHERE id=? AND company_id=?""",
            (employee_id, cid)
        ).fetchone()
        if not employee_record or not employee_record["active"]:
            session.clear()
            return jsonify({"error": "Employee account is inactive"}), 401

        if employee_record["employment_status"] not in ("active", "on_leave"):
            session.clear()
            return jsonify({"error": "Employee status does not permit access"}), 401

        company_lifecycle = get_db().execute(
            "SELECT status FROM company_lifecycle WHERE company_id=?",
            (cid,)
        ).fetchone()
        if not company_lifecycle or company_lifecycle["status"] != "active":
            return jsonify({"error": "Company operations are currently unavailable"}), 423

        if (
            request.method == 'GET'
            and path == '/api/attendance/status/' + str(employee_id)
        ):
            return None

        if (
            request.method == 'POST'
            and path in (
                '/api/attendance/clock-in',
                '/api/attendance/clock-out',
            )
        ):
            if employee_record["employment_status"] == "on_leave":
                return jsonify({"error": "Attendance is disabled while you are on leave"}), 403

            data = request.get_json(silent=True) or {}

            if str(data.get('user_id', '')) != str(employee_id):
                return jsonify({"error": "Employees may only access their own attendance"}), 403

            if str(data.get('company_id', '')) != str(cid):
                return jsonify({"error": "Access denied"}), 403

            return None

        return jsonify({"error": "Employee permission denied"}), 403

    # Company sessions may manage attendance records, but self-service
    # clock-in/out endpoints are reserved for authenticated employees.
    if (
        request.method == "POST"
        and path in (
            "/api/attendance/clock-in",
            "/api/attendance/clock-out",
        )
    ):
        return jsonify({
            "error": "Only employees may use self-service clock-in/out"
        }), 403

    cid = session.get('company_id')
    if not cid or session.get('platform_admin_id'):
        return jsonify({"error": "Authentication required"}), 401

    # A non-active company can only inspect its lifecycle status.
    lifecycle_row = get_db().execute(
        "SELECT status FROM company_lifecycle WHERE company_id=?",
        (cid,)
    ).fetchone()
    operational_status = lifecycle_row["status"] if lifecycle_row else "active"
    if operational_status != "active" and path != "/api/company/lifecycle":
        return jsonify({
            "error": "Company operations are unavailable",
            "company_status": operational_status
        }), 423

    # Keep legacy platform-wide subscription routes blocked.
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
        if not special_attendance_routes and route_name != cid:
            return jsonify({"error": "Access denied"}), 403

    data = request.get_json(silent=True) or {}
    supplied_cid = data.get('company_id')
    if supplied_cid is not None and str(supplied_cid) != str(cid):
        return jsonify({"error": "Access denied"}), 403

    user_id = data.get('user_id')
    if not user_id and len(parts) >= 4 and parts[1] == 'attendance' and parts[2] == 'status':
        user_id = parts[3]

    if user_id:
        user = get_db().execute(
            "SELECT id FROM users WHERE id=? AND company_id=?",
            (user_id, cid)
        ).fetchone()
        if not user:
            return jsonify({"error": "Staff member not found"}), 404

    return None


@app.route('/api/csrf-token', methods=['GET'])
def csrf_token():
    token = session.get("_csrf_token")
    if not isinstance(token, str) or len(token) < 32:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token

    response = jsonify({"csrf_token": token})
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


@app.after_request
def install_browser_csrf_helper(response):
    # Install the helper only in HTML pages, not JSON responses or JavaScript files.
    if "text/html" not in response.headers.get("Content-Type", "").lower():
        return response

    html = response.get_data(as_text=True)
    if "</head>" not in html.lower() or "window.__saasHrCsrfInstalled" in html:
        return response

    helper = r"""
<script>
(function () {
  if (window.__saasHrCsrfInstalled) return;
  window.__saasHrCsrfInstalled = true;

  const originalFetch = window.fetch.bind(window);
  let csrfToken = null;
  let tokenPromise = null;

  async function getCsrfToken() {
    if (csrfToken) return csrfToken;

    if (!tokenPromise) {
      tokenPromise = originalFetch('/api/csrf-token', {
        method: 'GET',
        credentials: 'same-origin',
        cache: 'no-store'
      }).then(async function (response) {
        if (!response.ok) throw new Error('Unable to obtain security token.');
        const data = await response.json();
        if (!data.csrf_token) throw new Error('Security token missing.');
        csrfToken = data.csrf_token;
        return csrfToken;
      }).finally(function () {
        tokenPromise = null;
      });
    }

    return tokenPromise;
  }

  window.fetch = async function (input, init) {
    init = init || {};

    let url;
    let method;
    try {
      url = new URL(
        typeof input === 'string' || input instanceof URL ? input : input.url,
        window.location.href
      );
      method = String(
        init.method || (input instanceof Request ? input.method : 'GET')
      ).toUpperCase();
    } catch (_) {
      return originalFetch(input, init);
    }

    const sameOrigin = url.origin === window.location.origin;
    const unsafe = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);

    if (sameOrigin && unsafe) {
      const token = await getCsrfToken();
      const headers = new Headers(input instanceof Request ? input.headers : undefined);
      new Headers(init.headers || {}).forEach(function (value, key) {
        headers.set(key, value);
      });
      headers.set('X-CSRF-Token', token);

      init = Object.assign({}, init, {
        headers: headers,
        credentials: init.credentials || 'same-origin'
      });
    }

    const response = await originalFetch(input, init);

    if (response.ok && sameOrigin && (
      url.pathname === '/api/company/login' ||
      url.pathname === '/api/employee/login' ||
      url.pathname === '/api/owner/login' ||
      url.pathname === '/api/logout' ||
      url.pathname === '/api/owner/logout'
    )) {
      // Authentication changes the session; obtain a fresh token next time.
      csrfToken = null;
      tokenPromise = null;
    }

    return response;
  };
})();
</script>
"""

    position = html.lower().find("</head>")
    if position >= 0:
        html = html[:position] + helper + html[position:]

    password_ui = r"""
<style>
.password-ui-wrap {
    display:flex;
    align-items:center;
    width:100%;
    gap:6px;
}
.password-ui-wrap input[type="password"],
.password-ui-wrap input[type="text"] {
    flex:1;
    min-width:0;
    width:0;
    margin-right:0;
}
.password-eye {
    flex:0 0 46px;
    width:46px;
    min-height:44px;
    margin:0;
    padding:8px;
    border:1px solid #d1d5db;
    border-radius:10px;
    background:#f8fafc;
    color:#111827;
    cursor:pointer;
    font-size:20px;
}
.password-strength {
    margin:4px 0 12px;
    font-size:13px;
    line-height:1.6;
}
.password-strength-track {
    height:7px;
    margin:6px 0;
    overflow:hidden;
    background:#e5e7eb;
    border-radius:10px;
}
.password-strength-fill {
    height:100%;
    width:0;
    background:#dc2626;
    transition:width .2s ease,background .2s ease;
}
.password-strength ul {
    padding-left:20px;
    margin-top:5px;
}
.password-strength .passed { color:#15803d; }
.password-strength .missing { color:#6b7280; }
</style>
<script>
(function () {
    'use strict';

    const rules = [
        {label:'At least 12 characters', test:p=>p.length>=12},
        {label:'One uppercase letter (A-Z)', test:p=>/[A-Z]/.test(p)},
        {label:'One lowercase letter (a-z)', test:p=>/[a-z]/.test(p)},
        {label:'One number (0-9)', test:p=>/[0-9]/.test(p)},
        {label:'One special character (!@#$...)', test:p=>/[^A-Za-z0-9\s]/.test(p)}
    ];

    window.saasPasswordError = function (password) {
        password = typeof password === 'string' ? password : '';
        const missing = rules.filter(rule => !rule.test(password));
        return missing.length
            ? 'Strong password required. ' + missing.map(rule => rule.label).join('; ') + '.'
            : '';
    };

    function initialisePasswordUI() {
        document.querySelectorAll('input[type="password"]').forEach(function (input) {
            if (input.dataset.passwordUiReady === '1') return;
            input.dataset.passwordUiReady = '1';

            const wrap = document.createElement('div');
            wrap.className = 'password-ui-wrap';
            input.parentNode.insertBefore(wrap, input);
            wrap.appendChild(input);

            const eye = document.createElement('button');
            eye.type = 'button';
            eye.className = 'password-eye';
            eye.textContent = '👁';
            eye.setAttribute('aria-label', 'Show password');
            eye.setAttribute('aria-pressed', 'false');
            eye.title = 'Show or hide password';
            eye.addEventListener('click', function () {
                const show = input.type === 'password';
                input.type = show ? 'text' : 'password';
                eye.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
                eye.setAttribute('aria-pressed', String(show));
            });
            wrap.appendChild(eye);

            const needsStrength =
                input.autocomplete === 'new-password' &&
                input.id !== 'confirm';

            if (!needsStrength) return;

            input.minLength = 12;

            const meter = document.createElement('div');
            meter.className = 'password-strength';
            meter.setAttribute('aria-live', 'polite');

            const title = document.createElement('div');
            title.textContent = 'Password strength: Not checked';

            const track = document.createElement('div');
            track.className = 'password-strength-track';
            track.setAttribute('aria-hidden', 'true');

            const fill = document.createElement('div');
            fill.className = 'password-strength-fill';
            track.appendChild(fill);

            const list = document.createElement('ul');
            const items = rules.map(function (rule) {
                const item = document.createElement('li');
                item.className = 'missing';
                item.textContent = rule.label;
                list.appendChild(item);
                return item;
            });

            meter.append(title, track, list);
            wrap.insertAdjacentElement('afterend', meter);

            function updateStrength() {
                const password = input.value;
                const results = rules.map(rule => rule.test(password));
                const score = results.filter(Boolean).length;

                items.forEach(function (item, index) {
                    item.className = results[index] ? 'passed' : 'missing';
                    item.textContent = (results[index] ? '✓ ' : '○ ') + rules[index].label;
                });

                const label = !password ? 'Not checked'
                    : score === 5 ? 'Strong'
                    : score >= 4 ? 'Good — not yet strong'
                    : score >= 3 ? 'Fair — needs improvement'
                    : 'Weak';

                title.textContent = 'Password strength: ' + label;
                fill.style.width = (score * 20) + '%';
                fill.style.background = score === 5 ? '#16a34a'
                    : score >= 4 ? '#ca8a04' : '#dc2626';

                input.dataset.passwordStrong = String(score === 5);
            }

            input.addEventListener('input', updateStrength);
            updateStrength();
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialisePasswordUI);
    } else {
        initialisePasswordUI();
    }
})();
</script>
"""

    body_position = html.lower().rfind("</body>")
    if body_position >= 0 and "password-ui-wrap" not in html:
        html = html[:body_position] + password_ui + html[body_position:]

    response.set_data(html)
    return response

def password_policy_error(password):
    """Require strong passwords for newly created or reset accounts."""
    if not isinstance(password, str):
        return "Password must be text."
    if len(password) < 12:
        return "Use at least 12 characters."
    if not any(c.isupper() for c in password):
        return "Add at least one uppercase letter."
    if not any(c.islower() for c in password):
        return "Add at least one lowercase letter."
    if not any(c.isdigit() for c in password):
        return "Add at least one number."
    if not any(not c.isalnum() and not c.isspace() for c in password):
        return "Add at least one special character, such as ! or @."
    return None


@app.route('/api/company/register', methods=['POST'])
def reg():
    d = request.get_json(silent=True) or {}
    name = str(d.get("name", "")).strip()
    email = str(d.get("email", "")).strip().lower()
    password = d.get("password", "")

    if not name or not email:
        return jsonify({"error": "Company name and email are required."}), 400

    policy_error = password_policy_error(password)
    if policy_error:
        return jsonify({"error": policy_error}), 400

    cid = uuid.uuid4().hex[:8]
    db = get_db()
    try:
        db.execute(
            "INSERT INTO companies VALUES (?,?,?,?,?,?)",
            (cid, name, email, generate_password_hash(password),
             "free", datetime.now().isoformat())
        )
        db.commit()
        return jsonify({"company_id": cid}), 201
    except Exception:
        db.rollback()
        return jsonify({"error": "Registration failed. This email may already be registered."}), 400
@app.route('/api/company/login', methods=['POST'])
def login():
    d = request.get_json(silent=True) or {}
    email = str(d.get('email', '')).strip().lower()
    password = d.get('password', '')
    if not isinstance(password, str):
        password = ''
    c = authenticate_company(email, password)
    if c:
        session.clear()
        session['company_id'] = c['id']
        session['company_name'] = c['name']
        session['auth_version'] = get_or_create_auth_version("company", c['id'])
        return jsonify({"company_id":c['id'],"name":c['name']})
    return jsonify({"error":"invalid"}),401
@app.route('/api/employee/login', methods=['POST'])
def employee_login():
    data = request.get_json(silent=True) or {}

    company_id = str(data.get('company_id', '')).strip()
    email = str(data.get('email', '')).strip().lower()
    password = data.get('password', '')

    if not company_id or not email or not isinstance(password, str) or not password:
        return jsonify({"error": "Company ID, email and password are required"}), 400

    employee = authenticate_employee(company_id, email, password)

    if not employee:
        return jsonify({"error": "Invalid employee credentials"}), 401

    session.clear()
    session.permanent = True
    session['company_id'] = employee['company_id']
    session['company_name'] = employee['company_name']
    session['employee_id'] = employee['id']
    session['employee_name'] = employee['name']
    session['employee_role'] = employee['role']
    session['auth_version'] = get_or_create_auth_version("employee", employee['id'])

    return jsonify({
        "authenticated": True,
        "account_type": "employee",
        "employee_id": employee['id'],
        "company_id": employee['company_id'],
        "name": employee['name'],
        "role": employee['role']
    })


@app.route('/api/employee/session')
def employee_session():
    employee_id = session.get('employee_id')
    company_id = session.get('company_id')

    if not employee_id or not company_id:
        return jsonify({"authenticated": False}), 401

    employee = get_db().execute(
        """SELECT id, company_id, name, email, role, active, employment_status
           FROM users WHERE id = ? AND company_id = ?""",
        (employee_id, company_id)
    ).fetchone()

    if (
        not employee
        or not employee["active"]
        or employee["employment_status"] not in ("active", "on_leave")
    ):
        session.clear()
        return jsonify({"authenticated": False}), 401

    company_state = get_db().execute(
        "SELECT status FROM company_lifecycle WHERE company_id=?",
        (company_id,)
    ).fetchone()
    if not company_state or company_state["status"] != "active":
        return jsonify({
            "authenticated": False,
            "company_status": company_state["status"] if company_state else "unknown"
        }), 423

    return jsonify({
        "authenticated": True,
        "account_type": "employee",
        "employee": dict(employee)
    })


@app.route('/api/session')
def check_session():
    if session.get("employee_id"):
        return jsonify({
            "authenticated": False,
            "error": "This is an employee session"
        }), 403

    cid = session.get('company_id')
    if not cid:
        return jsonify({"authenticated": False}), 401

    db = get_db()
    company = db.execute(
        "SELECT id, name FROM companies WHERE id=?",
        (cid,)
    ).fetchone()

    if not company:
        session.clear()
        return jsonify({"authenticated": False}), 401

    return jsonify({
        "authenticated": True,
        "company_id": company['id'],
        "name": company['name']
    })



@app.route('/api/departments', methods=['GET', 'POST'])
def company_departments():
    cid = session.get("company_id")
    if not cid:
        return jsonify({"error": "Authentication required"}), 401

    db = get_db()

    if request.method == "GET":
        rows = db.execute(
            """SELECT id, name, active, created
               FROM departments WHERE company_id = ?
               ORDER BY name COLLATE NOCASE""",
            (cid,),
        ).fetchall()
        return jsonify([dict(row) for row in rows])

    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()

    if not name or len(name) > 80:
        return jsonify({"error": "Department name is required (maximum 80 characters)"}), 400

    exists = db.execute(
        """SELECT id FROM departments
           WHERE company_id = ? AND lower(name) = lower(?)""",
        (cid, name),
    ).fetchone()
    if exists:
        return jsonify({"error": "That department already exists"}), 409

    department_id = uuid.uuid4().hex[:12]
    db.execute(
        """INSERT INTO departments (id, company_id, name, active, created)
           VALUES (?, ?, ?, 1, ?)""",
        (department_id, cid, name, datetime.now().isoformat()),
    )
    db.commit()
    return jsonify({"id": department_id, "name": name, "active": True}), 201


@app.route('/api/departments/<department_id>', methods=['PATCH'])
def update_company_department(department_id):
    cid = session.get("company_id")
    if not cid:
        return jsonify({"error": "Authentication required"}), 401

    db = get_db()
    department = db.execute(
        """SELECT id, name, active FROM departments
           WHERE id = ? AND company_id = ?""",
        (department_id, cid),
    ).fetchone()

    if not department:
        return jsonify({"error": "Department not found"}), 404

    data = request.get_json(silent=True) or {}
    name = str(data.get("name", department["name"])).strip()
    active = data.get("active", bool(department["active"]))

    if not name or len(name) > 80:
        return jsonify({"error": "Department name is required (maximum 80 characters)"}), 400
    if not isinstance(active, bool):
        return jsonify({"error": "active must be true or false"}), 400

    duplicate = db.execute(
        """SELECT id FROM departments
           WHERE company_id = ? AND lower(name) = lower(?) AND id != ?""",
        (cid, name, department_id),
    ).fetchone()
    if duplicate:
        return jsonify({"error": "That department already exists"}), 409

    db.execute(
        "UPDATE departments SET name = ?, active = ? WHERE id = ? AND company_id = ?",
        (name, int(active), department_id, cid),
    )
    db.execute(
        "UPDATE users SET department = ? WHERE company_id = ? AND department_id = ?",
        (name, cid, department_id),
    )
    db.commit()
    return jsonify({"id": department_id, "name": name, "active": active})


@app.route('/api/branches', methods=['GET', 'POST'])
def company_branches():
    cid = session.get("company_id")
    if not cid:
        return jsonify({"error": "Authentication required"}), 401

    db = get_db()

    if request.method == "GET":
        rows = db.execute(
            """SELECT id, name, address, active, created
               FROM branches WHERE company_id = ?
               ORDER BY name COLLATE NOCASE""",
            (cid,),
        ).fetchall()
        return jsonify([dict(row) for row in rows])

    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    address = str(data.get("address", "")).strip()

    if not name or len(name) > 100:
        return jsonify({"error": "Branch name is required (maximum 100 characters)"}), 400
    if len(address) > 250:
        return jsonify({"error": "Address must not exceed 250 characters"}), 400

    exists = db.execute(
        """SELECT id FROM branches
           WHERE company_id = ? AND lower(name) = lower(?)""",
        (cid, name),
    ).fetchone()
    if exists:
        return jsonify({"error": "That branch already exists"}), 409

    branch_id = uuid.uuid4().hex[:12]
    db.execute(
        """INSERT INTO branches
           (id, company_id, name, address, active, created)
           VALUES (?, ?, ?, ?, 1, ?)""",
        (branch_id, cid, name, address, datetime.now().isoformat()),
    )
    db.commit()
    return jsonify({
        "id": branch_id,
        "name": name,
        "address": address,
        "active": True,
    }), 201


@app.route('/api/branches/<branch_id>', methods=['PATCH'])
def update_company_branch(branch_id):
    cid = session.get("company_id")
    if not cid:
        return jsonify({"error": "Authentication required"}), 401

    db = get_db()
    branch = db.execute(
        """SELECT id, name, address, active FROM branches
           WHERE id = ? AND company_id = ?""",
        (branch_id, cid),
    ).fetchone()

    if not branch:
        return jsonify({"error": "Branch not found"}), 404

    data = request.get_json(silent=True) or {}
    name = str(data.get("name", branch["name"])).strip()
    address = str(data.get("address", branch["address"])).strip()
    active = data.get("active", bool(branch["active"]))

    if not name or len(name) > 100:
        return jsonify({"error": "Branch name is required (maximum 100 characters)"}), 400
    if len(address) > 250:
        return jsonify({"error": "Address must not exceed 250 characters"}), 400
    if not isinstance(active, bool):
        return jsonify({"error": "active must be true or false"}), 400

    duplicate = db.execute(
        """SELECT id FROM branches
           WHERE company_id = ? AND lower(name) = lower(?) AND id != ?""",
        (cid, name, branch_id),
    ).fetchone()
    if duplicate:
        return jsonify({"error": "That branch already exists"}), 409

    db.execute(
        """UPDATE branches SET name = ?, address = ?, active = ?
           WHERE id = ? AND company_id = ?""",
        (name, address, int(active), branch_id, cid),
    )
    db.commit()
    return jsonify({
        "id": branch_id,
        "name": name,
        "address": address,
        "active": active,
    })


@app.route('/api/staff', methods=['POST'])
def add_staff():
    d = request.get_json(silent=True) or {}
    cid = session.get("company_id")
    name = str(d.get("name", "")).strip()
    email = str(d.get("email", "")).strip().lower()
    password = d.get("password", "")
    role = str(d.get("role", "staff")).strip()
    department = str(d.get("department", "General")).strip() or "General"

    if not cid:
        return jsonify({"error": "Authentication required"}), 401
    if str(d.get("company_id", "")) != str(cid):
        return jsonify({"error": "Access denied"}), 403
    if not name or not email:
        return jsonify({"error": "Employee name and email are required"}), 400
    policy_error = password_policy_error(password)
    if policy_error:
        return jsonify({"error": policy_error}), 400
    if role not in ("staff", "HR"):
        return jsonify({"error": "Unsupported employee role"}), 400

    db = get_db()
    duplicate = db.execute(
        "SELECT id FROM users WHERE company_id=? AND lower(email)=?",
        (cid, email)
    ).fetchone()
    if duplicate:
        return jsonify({"error": "An employee with this email already exists"}), 409

    department_id = str(d.get("department_id", "")).strip()
    branch_id = str(d.get("branch_id", "")).strip()
    job_title = str(d.get("job_title", "")).strip()

    if len(job_title) > 100:
        return jsonify({"error": "Job title must not exceed 100 characters"}), 400

    if department_id:
        dept = db.execute(
            """SELECT id, name FROM departments
               WHERE id = ? AND company_id = ? AND active = 1""",
            (department_id, cid),
        ).fetchone()
        if not dept:
            return jsonify({"error": "Department not found or inactive"}), 400
        department = dept["name"]
    else:
        dept = db.execute(
            """SELECT id, name FROM departments
               WHERE company_id = ? AND lower(name) = lower(?) AND active = 1""",
            (cid, department),
        ).fetchone()
        if dept:
            department_id = dept["id"]
            department = dept["name"]
        else:
            department_id = uuid.uuid4().hex[:12]
            db.execute(
                """INSERT INTO departments
                   (id, company_id, name, active, created)
                   VALUES (?, ?, ?, 1, ?)""",
                (department_id, cid, department, datetime.now().isoformat()),
            )

    if branch_id:
        branch = db.execute(
            """SELECT id FROM branches
               WHERE id = ? AND company_id = ? AND active = 1""",
            (branch_id, cid),
        ).fetchone()
        if not branch:
            return jsonify({"error": "Branch not found or inactive"}), 400
    else:
        branch_id = None

    uid = uuid.uuid4().hex[:8]
    db.execute(
        """INSERT INTO users
           (id, company_id, name, email, role, department,
            department_id, branch_id, job_title, photo, photo_hash,
            password, created, active)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
        (
            uid, cid, name, email, role, department, department_id,
            branch_id, job_title, "default.png", "",
            generate_password_hash(password), datetime.now().isoformat()
        )
    )
    db.commit()
    return jsonify({"id": uid, "active": True}), 201



@app.route('/api/staff/<cid>/<user_id>/active', methods=['PATCH'])
def set_staff_active(cid, user_id):
    company_id = session.get("company_id")
    if not company_id:
        return jsonify({"error": "Authentication required"}), 401
    if str(cid) != str(company_id):
        return jsonify({"error": "Access denied"}), 403

    data = request.get_json(silent=True) or {}
    active = data.get("active")

    if not isinstance(active, bool):
        return jsonify({"error": "active must be true or false"}), 400

    db = get_db()
    employee = db.execute(
        "SELECT id, active, employment_status FROM users WHERE id=? AND company_id=?",
        (user_id, company_id)
    ).fetchone()

    if not employee:
        return jsonify({"error": "Employee not found"}), 404

    old_status = employee["employment_status"] or (
        "active" if employee["active"] else "inactive"
    )
    new_status = "active" if active else "inactive"
    db.execute(
        """UPDATE users SET active=?, employment_status=?
           WHERE id=? AND company_id=?""",
        (1 if active else 0, new_status, user_id, company_id)
    )
    if old_status != new_status:
        db.execute(
            """INSERT INTO lifecycle_status_history
               (id, company_id, subject_type, subject_id, old_status,
                new_status, reason, changed_by, created_at)
               VALUES (?, ?, 'employee', ?, ?, ?, ?, ?, ?)""",
            (
                uuid.uuid4().hex, company_id, user_id, old_status,
                new_status, "Legacy active toggle", company_id,
                datetime.now().isoformat()
            )
        )
    db.commit()

    return jsonify({
        "id": user_id,
        "active": active,
        "employment_status": new_status,
        "message": "Employee activated" if active else "Employee deactivated"
    })


@app.route('/api/staff/<cid>')
def list_staff(cid):
    db = get_db()
    rows = db.execute(
        """SELECT u.id, u.name, u.email, u.role, u.department,
                  u.department_id, u.branch_id, u.job_title,
                  b.name AS branch_name, u.created, u.active,
                  u.employment_status
           FROM users u
           LEFT JOIN branches b
             ON b.id = u.branch_id AND b.company_id = u.company_id
           WHERE u.company_id = ?
           ORDER BY u.created DESC""",
        (cid,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])
@app.route('/api/attendance/clock-in', methods=['POST'])
def ci():
    d = request.get_json(silent=True) or {}
    cid = session.get('company_id')

    if not cid:
        return jsonify({"error": "Authentication required"}), 401

    if str(d.get('company_id', '')) != str(cid):
        return jsonify({"error": "Access denied"}), 403

    uid = d.get('user_id')
    if not uid:
        return jsonify({"error": "Staff member is required"}), 400

    db = get_db()
    staff = db.execute(
        "SELECT id FROM users WHERE id=? AND company_id=?",
        (uid, cid)
    ).fetchone()

    if not staff:
        return jsonify({"error": "Staff member not found"}), 404

    try:
        lat = float(d.get('lat'))
        lng = float(d.get('lng'))
        if not (-90 <= lat <= 90 and -180 <= lng <= 180):
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({"error": "Valid GPS coordinates are required"}), 400

    settings = db.execute(
        "SELECT * FROM company_settings WHERE company_id=?",
        (cid,)
    ).fetchone()

    if not settings:
        db.execute(
            """INSERT INTO company_settings
               (company_id, moniepoint_account, moniepoint_name,
                office_lat, office_lng, office_radius)
               VALUES (?, '', '', 6.5244, 3.3792, 50)""",
            (cid,)
        )
        db.commit()
        settings = db.execute(
            "SELECT * FROM company_settings WHERE company_id=?",
            (cid,)
        ).fetchone()

    office_lat = float(settings['office_lat'])
    office_lng = float(settings['office_lng'])
    radius = float(settings['office_radius'])
    distance = haversine(lat, lng, office_lat, office_lng)

    if distance > radius:
        return jsonify({
            "msg": f"Too far! {distance:.0f}m from office (max {radius:.0f}m)."
        }), 403

    today = datetime.now().date().isoformat()
    existing = db.execute(
        "SELECT id FROM attendance WHERE company_id=? AND user_id=? AND date=?",
        (cid, uid, today)
    ).fetchone()

    if existing:
        return jsonify({"msg": "Already clocked in today"}), 400

    photo_hash = d.get('photo_hash', '')
    if photo_hash:
        duplicate = db.execute(
            """SELECT id FROM attendance
               WHERE company_id=? AND user_id=? AND photo_hash=?""",
            (cid, uid, photo_hash)
        ).fetchone()
        if duplicate:
            return jsonify({"msg": "Previously submitted photo reference"}), 400

    aid = uuid.uuid4().hex[:8]
    db.execute(
        """INSERT INTO attendance
           (id, company_id, user_id, date, clock_in, clock_out,
            status, lat, lng, distance, photo_hash)
           VALUES (?, ?, ?, ?, ?, NULL, 'present', ?, ?, ?, ?)""",
        (
            aid, cid, uid, today, datetime.now().isoformat(),
            lat, lng, distance, photo_hash
        )
    )
    db.commit()

    return jsonify({"msg": f"Clocked in! {distance:.0f}m from office"})

@app.route('/api/attendance/clock-out', methods=['POST'])
def co():
    d = request.get_json(silent=True) or {}
    cid = session.get('company_id')
    uid = d.get('user_id')

    if not cid:
        return jsonify({"error": "Authentication required"}), 401
    if not uid:
        return jsonify({"error": "Staff member is required"}), 400

    db = get_db()
    today = datetime.now().date().isoformat()

    rec = db.execute(
        """SELECT * FROM attendance
           WHERE company_id=? AND user_id=? AND date=?""",
        (cid, uid, today)
    ).fetchone()

    if not rec:
        return jsonify({"msg": "No clock-in"}), 400
    if rec['clock_out']:
        return jsonify({"msg": "Already out"}), 400

    db.execute(
        """UPDATE attendance SET clock_out=?
           WHERE company_id=? AND user_id=? AND date=? AND clock_out IS NULL""",
        (datetime.now().isoformat(), cid, uid, today)
    )
    db.commit()

    return jsonify({"msg": "Clocked out"})


@app.route('/api/attendance/<cid>')
def att(cid):
    db=get_db(); rows=db.execute("SELECT a.*,u.name FROM attendance a JOIN users u ON a.user_id=u.id WHERE a.company_id=? ORDER BY a.date DESC",(cid,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/attendance/<cid>/<attendance_id>/correct', methods=['POST'])
def correct_attendance(cid, attendance_id):
    company_id = session.get("company_id")
    if not company_id:
        return jsonify({"error": "Authentication required"}), 401
    if str(cid) != str(company_id):
        return jsonify({"error": "Access denied"}), 403

    data = request.get_json(silent=True) or {}
    reason = data.get("reason")
    changes = data.get("changes")

    if not isinstance(reason, str) or len(reason.strip()) < 8:
        return jsonify({
            "error": "Provide a correction reason of at least 8 characters"
        }), 400

    allowed_fields = {"date", "clock_in", "clock_out", "status"}
    if not isinstance(changes, dict) or not changes:
        return jsonify({"error": "Provide attendance changes"}), 400
    if set(changes) - allowed_fields:
        return jsonify({
            "error": "Only date, clock_in, clock_out, and status may be corrected"
        }), 400

    clean_changes = {}
    for field, value in changes.items():
        if field == "date":
            if not isinstance(value, str):
                return jsonify({"error": "date must use YYYY-MM-DD format"}), 400
            try:
                from datetime import date as _date
                _date.fromisoformat(value)
                if len(value) != 10:
                    raise ValueError()
            except ValueError:
                return jsonify({"error": "date must use YYYY-MM-DD format"}), 400
            clean_changes[field] = value

        elif field == "status":
            if not isinstance(value, str) or value not in (
                "present", "absent", "late", "leave"
            ):
                return jsonify({"error": "Unsupported attendance status"}), 400
            clean_changes[field] = value

        else:
            if value is None or value == "":
                clean_changes[field] = None
            elif isinstance(value, str) and len(value) <= 64:
                try:
                    datetime.fromisoformat(value)
                except ValueError:
                    return jsonify({
                        "error": field + " must be a valid ISO datetime or empty"
                    }), 400
                clean_changes[field] = value
            else:
                return jsonify({
                    "error": field + " must be a valid ISO datetime or empty"
                }), 400

    db = get_db()
    record = db.execute(
        """SELECT a.*, u.id AS verified_employee_id
           FROM attendance a
           JOIN users u ON u.id=a.user_id AND u.company_id=a.company_id
           WHERE a.id=? AND a.company_id=?""",
        (attendance_id, company_id)
    ).fetchone()

    if not record:
        return jsonify({"error": "Attendance record not found"}), 404

    final_values = {
        "date": record["date"],
        "clock_in": record["clock_in"],
        "clock_out": record["clock_out"],
        "status": record["status"],
    }
    final_values.update(clean_changes)

    clock_in = final_values["clock_in"]
    clock_out = final_values["clock_out"]

    if clock_in and clock_out:
        try:
            in_time = datetime.fromisoformat(clock_in)
            out_time = datetime.fromisoformat(clock_out)
        except (TypeError, ValueError):
            return jsonify({"error": "Invalid clock-in or clock-out timestamp"}), 400

        if in_time.tzinfo != out_time.tzinfo:
            return jsonify({
                "error": "Clock-in and clock-out must use compatible time zones"
            }), 400

        if out_time < in_time:
            return jsonify({
                "error": "Clock-out cannot be earlier than clock-in"
            }), 400

    duplicate = db.execute(
        """SELECT id FROM attendance
           WHERE company_id=? AND user_id=? AND date=? AND id<>?
           LIMIT 1""",
        (
            company_id,
            record["user_id"],
            final_values["date"],
            attendance_id,
        )
    ).fetchone()

    if duplicate:
        return jsonify({
            "error": "This employee already has an attendance record for that date"
        }), 409

    old_values = {}
    new_values = {}
    for field, value in clean_changes.items():
        old_values[field] = record[field]
        new_values[field] = value

    assignments = ", ".join(field + "=?" for field in clean_changes)
    values = list(clean_changes.values()) + [attendance_id, company_id]

    try:
        db.execute("BEGIN IMMEDIATE")

        # Recheck uniqueness inside the write transaction to reduce races.
        duplicate = db.execute(
            """SELECT id FROM attendance
               WHERE company_id=? AND user_id=? AND date=? AND id<>?
               LIMIT 1""",
            (
                company_id,
                record["user_id"],
                final_values["date"],
                attendance_id,
            )
        ).fetchone()

        if duplicate:
            db.rollback()
            return jsonify({
                "error": "This employee already has an attendance record for that date"
            }), 409

        cursor = db.execute(
            "UPDATE attendance SET " + assignments +
            " WHERE id=? AND company_id=?",
            values
        )
        if cursor.rowcount != 1:
            db.rollback()
            return jsonify({"error": "Attendance record changed; retry the correction"}), 409

        db.execute(
            """INSERT INTO attendance_audit
               (id, company_id, attendance_id, employee_id, action,
                old_values, new_values, reason, admin_id, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                uuid.uuid4().hex,
                company_id,
                attendance_id,
                record["user_id"],
                "attendance_corrected",
                json.dumps(old_values),
                json.dumps(new_values),
                reason.strip(),
                company_id,
                datetime.now().isoformat()
            )
        )
        db.commit()
    except Exception:
        db.rollback()
        raise

    return jsonify({
        "message": "Attendance corrected",
        "attendance_id": attendance_id,
        "changes": new_values
    })


@app.route('/api/attendance/<cid>/audit')
def attendance_audit(cid):
    company_id = session.get("company_id")
    if not company_id:
        return jsonify({"error": "Authentication required"}), 401
    if str(cid) != str(company_id):
        return jsonify({"error": "Access denied"}), 403

    rows = get_db().execute(
        """SELECT id, company_id, attendance_id, employee_id, action,
                  old_values, new_values, reason, admin_id, created_at
           FROM attendance_audit
           WHERE company_id=?
           ORDER BY created_at DESC
           LIMIT 100""",
        (company_id,)
    ).fetchall()

    return jsonify([dict(row) for row in rows])


@app.route('/api/attendance/status/<user_id>')
def att_status(user_id):
    cid = session.get('company_id')
    if not cid:
        return jsonify({"error": "Authentication required"}), 401

    today = datetime.now().date().isoformat()
    db = get_db()

    rec = db.execute(
        """SELECT * FROM attendance
           WHERE company_id=? AND user_id=? AND date=?""",
        (cid, user_id, today)
    ).fetchone()

    if not rec:
        return jsonify({"status": "not_in"})

    distance = rec['distance'] if 'distance' in rec.keys() else 0

    if rec['clock_in'] and not rec['clock_out']:
        return jsonify({
            "status": "in",
            "clock_in": rec['clock_in'],
            "distance": distance
        })

    return jsonify({
        "status": "out",
        "clock_in": rec['clock_in'],
        "clock_out": rec['clock_out'],
        "distance": distance
    })


@app.route('/api/stats/<cid>')
def stats(cid):
    db=get_db(); staff=db.execute("SELECT COUNT(*) c FROM users WHERE company_id=?",(cid,)).fetchone()['c']
    present=db.execute("SELECT COUNT(*) c FROM attendance WHERE company_id=? AND date=?",(cid,datetime.now().date().isoformat())).fetchone()['c']
    return jsonify({"staff":staff,"present":present})
@app.route('/api/settings', methods=['GET','POST'])
def settings_route():
    cid = session.get('company_id')
    if not cid:
        return jsonify({"error": "Authentication required"}), 401

    db = get_db()
    cur = db.execute(
        "SELECT * FROM company_settings WHERE company_id=?",
        (cid,)
    ).fetchone()

    if not cur:
        db.execute(
            """INSERT INTO company_settings
               (company_id, moniepoint_account, moniepoint_name,
                office_lat, office_lng, office_radius)
               VALUES (?, '', '', 6.5244, 3.3792, 50)""",
            (cid,)
        )
        db.commit()
        cur = db.execute(
            "SELECT * FROM company_settings WHERE company_id=?",
            (cid,)
        ).fetchone()

    if request.method == 'POST':
        d = request.get_json(silent=True) or {}
        account = d.get('account', cur['moniepoint_account'])
        name = d.get('name', cur['moniepoint_name'])
        lat = d.get('office_lat', cur['office_lat'])
        lng = d.get('office_lng', cur['office_lng'])
        radius = d.get('office_radius', cur['office_radius'])

        try:
            lat, lng, radius = float(lat), float(lng), float(radius)
            if not (-90 <= lat <= 90 and -180 <= lng <= 180):
                raise ValueError
            if not (1 <= radius <= 100000):
                raise ValueError
        except (TypeError, ValueError):
            return jsonify({"error": "Invalid office coordinates or radius"}), 400

        db.execute(
            """UPDATE company_settings
               SET moniepoint_account=?, moniepoint_name=?,
                   office_lat=?, office_lng=?, office_radius=?
               WHERE company_id=?""",
            (account, name, lat, lng, radius, cid)
        )
        db.commit()
        cur = db.execute(
            "SELECT * FROM company_settings WHERE company_id=?",
            (cid,)
        ).fetchone()

    return jsonify(dict(cur))

@app.route('/api/subscribe', methods=['POST'])
def subscribe():
    plans = {
        "pro": {"amount": 5000, "days": 31},
        "yearly": {"amount": 45000, "days": 367},
        "premium": {"amount": 150000, "days": 1825},
    }
    data = request.get_json(silent=True) or {}
    company_id = session.get("company_id")
    plan = str(data.get("plan", "")).strip().lower()
    proof = str(data.get("proof", "")).strip()

    if not company_id:
        return jsonify({"error": "Please log in to your company account"}), 401
    if plan not in plans:
        return jsonify({"error": "Invalid subscription plan"}), 400
    if len(proof) < 3:
        return jsonify({"error": "Enter a valid bank transfer reference"}), 400

    db = get_db()
    company = db.execute(
        "SELECT id FROM companies WHERE id=?", (company_id,)
    ).fetchone()
    if not company:
        session.clear()
        return jsonify({"error": "Company account not found"}), 401

    pending = db.execute(
        "SELECT id FROM subscriptions WHERE company_id=? AND plan=? AND status='pending'",
        (company_id, plan)
    ).fetchone()
    if pending:
        return jsonify({
            "error": "A payment for this plan is already awaiting review",
            "id": pending["id"]
        }), 409

    sid = uuid.uuid4().hex[:8]
    created = datetime.now().isoformat()
    db.execute(
        "INSERT INTO subscriptions (id, company_id, plan, amount, status, proof, created, expires) "
        "VALUES (?, ?, ?, ?, 'pending', ?, ?, NULL)",
        (sid, company_id, plan, plans[plan]["amount"], proof, created)
    )
    db.commit()
    return jsonify({
        "id": sid,
        "status": "pending",
        "amount": plans[plan]["amount"],
        "message": "Payment submitted for owner verification"
    }), 201

@app.route('/api/subscriptions/<cid>')
def subs(cid):
    db=get_db(); rows=db.execute("SELECT * FROM subscriptions WHERE company_id=? ORDER BY created DESC",(cid,)).fetchall(); return jsonify([dict(r) for r in rows])
@app.route('/api/subscriptions/all')
def all_subs():
    db=get_db(); rows=db.execute("SELECT s.*, c.name as company_name FROM subscriptions s JOIN companies c ON s.company_id=c.id ORDER BY s.created DESC").fetchall(); return jsonify([dict(r) for r in rows])
@app.route('/api/subscriptions/approve/<sid>', methods=['POST'])
def approve_sub(sid):
    db=get_db(); db.execute("UPDATE subscriptions SET status='active' WHERE id=?",(sid,)); sub=db.execute("SELECT * FROM subscriptions WHERE id=?",(sid,)).fetchone()
    if sub: db.execute("UPDATE companies SET plan=? WHERE id=?",(sub['plan'], sub['company_id'])); db.commit(); return jsonify({"msg":"Approved"})
@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"msg":"Logged out"})
@app.route('/favicon.ico')
def favicon():
    from flask import Response
    svg = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
    <rect width="64" height="64" rx="14" fill="#111827"/>
    <path d="M15 16h8v13h18V16h8v32h-8V36H23v12h-8z" fill="#ffffff"/>
    <circle cx="51" cy="49" r="6" fill="#22c55e"/>
    </svg>"""
    return Response(svg, mimetype="image/svg+xml")


@app.route('/')
def home():
    return render_template('home.html')



@app.route('/sw.js')
def service_worker():
    from flask import Response
    worker = r"""
const CACHE_NAME = 'saas-hr-shell-v1';
const APP_SHELL = [
  '/owner-login',
  '/owner-dashboard'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(APP_SHELL))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys => Promise.all(
      keys.filter(key => key.startsWith('saas-hr-shell-') &&
                         key !== CACHE_NAME)
          .map(key => caches.delete(key))
    )).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  const request = event.request;
  const url = new URL(request.url);

  if (request.method !== 'GET' ||
      url.origin !== self.location.origin) {
    return;
  }

  // Never cache authentication, company records, payroll,
  // subscription APIs, or other private API responses.
  if (url.pathname.startsWith('/api/')) {
    return;
  }

  // Use the network for page navigation first; show a cached
  // app page only when offline. Do not cache other resources yet.
  if (request.mode === 'navigate' &&
      APP_SHELL.includes(url.pathname)) {
    event.respondWith(
      fetch(request).catch(async () => {
        const cached = await caches.match(request);
        if (cached) return cached;
        return new Response(
          '<!doctype html><html><meta name="viewport" content="width=device-width,initial-scale=1"><title>Offline</title><body style="font-family:Arial;padding:24px"><h1>You are offline</h1><p>Reconnect to the internet to sign in or load current company data.</p></body></html>',
          {headers: {'Content-Type': 'text/html; charset=utf-8'}}
        );
      })
    );
  }
});
"""
    return Response(
        worker,
        mimetype="application/javascript",
        headers={
            "Service-Worker-Allowed": "/",
            "Cache-Control": "no-cache"
        }
    )


@app.route('/owner-login')
def owner_login_page():
    return render_template('owner_login.html')


@app.route('/owner-dashboard')
def owner_dashboard_page():
    return render_template('owner_dashboard.html')

@app.route('/api/owner/login', methods=['POST'])
def owner_login():
    data = request.get_json(silent=True) or {}
    email = str(data.get('email', '')).strip().lower()
    password = data.get('password', '')

    if not isinstance(password, str) or not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    admin = authenticate_owner(email, password)

    if not admin:
        return jsonify({"error": "Invalid owner credentials"}), 401

    session.clear()
    session['platform_admin_id'] = admin['id']
    session['auth_version'] = get_or_create_auth_version("owner", admin['id'])
    return jsonify({"authenticated": True, "email": admin['email']})

@app.route('/api/owner/session')
def owner_session():
    owner_id = session.get('platform_admin_id')
    if (
        not owner_id
        or session.get('company_id')
        or session.get('employee_id')
    ):
        return jsonify({"authenticated": False}), 401

    admin = get_db().execute(
        "SELECT id, email FROM platform_admins WHERE id=?",
        (owner_id,)
    ).fetchone()

    if not admin:
        session.clear()
        return jsonify({"authenticated": False}), 401

    return jsonify({"authenticated": True, "email": admin['email']})

@app.route('/api/owner/logout', methods=['POST'])
def owner_logout():
    session.clear()
    return jsonify({"message": "Logged out"})


@app.route('/api/company/lifecycle')
def company_lifecycle_status():
    cid = session.get("company_id")
    if not cid:
        return jsonify({"error": "Authentication required"}), 401
    row = get_db().execute(
        """SELECT status, reason, updated_by, updated_at
           FROM company_lifecycle WHERE company_id=?""",
        (cid,)
    ).fetchone()
    if not row:
        return jsonify({
            "company_id": cid,
            "status": "active",
            "reason": "",
            "updated_at": None
        })
    return jsonify({"company_id": cid, **dict(row)})


@app.route('/api/staff/<cid>/<user_id>/status', methods=['PATCH'])
def set_employee_lifecycle_status(cid, user_id):
    company_id = session.get("company_id")
    if not company_id:
        return jsonify({"error": "Authentication required"}), 401
    if str(cid) != str(company_id):
        return jsonify({"error": "Access denied"}), 403

    data = request.get_json(silent=True) or {}
    status = str(data.get("status", "")).strip().lower()
    reason = str(data.get("reason", "")).strip()
    allowed = {"active", "on_leave", "inactive", "suspended", "former_employee"}

    if status not in allowed:
        return jsonify({"error": "Unsupported employee status"}), 400
    if not reason or len(reason) > 500:
        return jsonify({"error": "A reason of 1-500 characters is required"}), 400

    db = get_db()
    employee = db.execute(
        """SELECT id, active, employment_status FROM users
           WHERE id=? AND company_id=?""",
        (user_id, company_id)
    ).fetchone()
    if not employee:
        return jsonify({"error": "Employee not found"}), 404

    old_status = employee["employment_status"] or (
        "active" if employee["active"] else "inactive"
    )
    active = 1 if status in ("active", "on_leave") else 0

    if old_status != status:
        db.execute(
            """UPDATE users SET employment_status=?, active=?
               WHERE id=? AND company_id=?""",
            (status, active, user_id, company_id)
        )
        db.execute(
            """INSERT INTO lifecycle_status_history
               (id, company_id, subject_type, subject_id, old_status,
                new_status, reason, changed_by, created_at)
               VALUES (?, ?, 'employee', ?, ?, ?, ?, ?, ?)""",
            (
                uuid.uuid4().hex, company_id, user_id, old_status,
                status, reason, company_id, datetime.now().isoformat()
            )
        )
        db.commit()

    return jsonify({
        "id": user_id,
        "employment_status": status,
        "active": bool(active)
    })


@app.route('/api/staff/<cid>/<user_id>/status-history')
def employee_lifecycle_history(cid, user_id):
    company_id = session.get("company_id")
    if not company_id:
        return jsonify({"error": "Authentication required"}), 401
    if str(cid) != str(company_id):
        return jsonify({"error": "Access denied"}), 403

    db = get_db()
    employee = db.execute(
        "SELECT id FROM users WHERE id=? AND company_id=?",
        (user_id, company_id)
    ).fetchone()
    if not employee:
        return jsonify({"error": "Employee not found"}), 404

    rows = db.execute(
        """SELECT old_status, new_status, reason, changed_by, created_at
           FROM lifecycle_status_history
           WHERE company_id=? AND subject_type='employee' AND subject_id=?
           ORDER BY created_at DESC""",
        (company_id, user_id)
    ).fetchall()
    return jsonify([dict(row) for row in rows])


@app.route('/api/owner/companies')
def owner_companies():
    rows = get_db().execute(
        """SELECT c.id, c.name, c.email, c.plan, c.created,
                  COALESCE(l.status, 'active') AS operational_status
           FROM companies c
           LEFT JOIN company_lifecycle l ON l.company_id=c.id
           ORDER BY c.created DESC"""
    ).fetchall()
    return jsonify([dict(row) for row in rows])


@app.route('/api/owner/companies/<cid>/status', methods=['PATCH'])
def owner_set_company_lifecycle_status(cid):
    status_data = request.get_json(silent=True) or {}
    status = str(status_data.get("status", "")).strip().lower()
    reason = str(status_data.get("reason", "")).strip()
    allowed = {"active", "paused", "suspended", "closed"}

    if status not in allowed:
        return jsonify({"error": "Unsupported company status"}), 400
    if not reason or len(reason) > 500:
        return jsonify({"error": "A reason of 1-500 characters is required"}), 400

    db = get_db()
    company = db.execute("SELECT id FROM companies WHERE id=?", (cid,)).fetchone()
    if not company:
        return jsonify({"error": "Company not found"}), 404

    current = db.execute(
        "SELECT status FROM company_lifecycle WHERE company_id=?",
        (cid,)
    ).fetchone()
    old_status = current["status"] if current else "active"
    now = datetime.now().isoformat()
    owner_id = str(session.get("platform_admin_id"))

    if current:
        db.execute(
            """UPDATE company_lifecycle
               SET status=?, reason=?, updated_by=?, updated_at=?
               WHERE company_id=?""",
            (status, reason, owner_id, now, cid)
        )
    else:
        db.execute(
            """INSERT INTO company_lifecycle
               (company_id, status, reason, updated_by, updated_at)
               VALUES (?, ?, ?, ?, ?)""",
            (cid, status, reason, owner_id, now)
        )

    if old_status != status:
        db.execute(
            """INSERT INTO lifecycle_status_history
               (id, company_id, subject_type, subject_id, old_status,
                new_status, reason, changed_by, created_at)
               VALUES (?, ?, 'company', ?, ?, ?, ?, ?, ?)""",
            (
                uuid.uuid4().hex, cid, cid, old_status, status,
                reason, owner_id, now
            )
        )
    db.commit()
    return jsonify({
        "company_id": cid,
        "operational_status": status,
        "message": "Company status updated"
    })


@app.route('/api/owner/companies/<cid>/status-history')
def owner_company_lifecycle_history(cid):
    db = get_db()
    company = db.execute("SELECT id FROM companies WHERE id=?", (cid,)).fetchone()
    if not company:
        return jsonify({"error": "Company not found"}), 404

    rows = db.execute(
        """SELECT old_status, new_status, reason, changed_by, created_at
           FROM lifecycle_status_history
           WHERE company_id=? AND subject_type='company' AND subject_id=?
           ORDER BY created_at DESC""",
        (cid, cid)
    ).fetchall()
    return jsonify([dict(row) for row in rows])


@app.route('/api/owner/subscriptions')
def owner_subscriptions():
    rows = get_db().execute("""
        SELECT s.id, s.company_id, s.plan, s.amount, s.status,
               s.proof, s.created, s.expires, c.name AS company_name,
               c.email AS company_email
        FROM subscriptions s
        LEFT JOIN companies c ON c.id = s.company_id
        ORDER BY s.created DESC
    """).fetchall()
    return jsonify([dict(row) for row in rows])

@app.route('/api/owner/subscriptions/approve/<sid>', methods=['POST'])
def owner_approve_subscription(sid):
    plans = {
        "pro": {"amount": 5000, "days": 31},
        "yearly": {"amount": 45000, "days": 367},
        "premium": {"amount": 150000, "days": 1825},
    }
    db = get_db()
    db.execute("BEGIN IMMEDIATE")

    sub = db.execute(
        "SELECT id, company_id, plan, amount, status FROM subscriptions WHERE id=?",
        (sid,)
    ).fetchone()

    if not sub:
        db.rollback()
        return jsonify({"error": "Subscription not found"}), 404
    if sub["status"] != "pending":
        db.rollback()
        return jsonify({"error": "Only pending subscriptions can be approved"}), 409
    if sub["plan"] not in plans or float(sub["amount"] or 0) != plans[sub["plan"]]["amount"]:
        db.rollback()
        return jsonify({"error": "Subscription plan or amount is invalid"}), 400

    company = db.execute(
        "SELECT id FROM companies WHERE id=?", (sub["company_id"],)
    ).fetchone()
    if not company:
        db.rollback()
        return jsonify({"error": "Company not found"}), 404

    now = datetime.now()
    base = now
    rows = db.execute(
        "SELECT expires FROM subscriptions WHERE company_id=? AND status='active' AND expires IS NOT NULL",
        (sub["company_id"],)
    ).fetchall()

    for row in rows:
        try:
            expiry = datetime.fromisoformat(row["expires"])
            if expiry.tzinfo is not None:
                expiry = expiry.replace(tzinfo=None)
            if expiry > base:
                base = expiry
        except (TypeError, ValueError):
            continue

    expires = (base + timedelta(days=plans[sub["plan"]]["days"])).isoformat()
    db.execute(
        "UPDATE subscriptions SET status='active', expires=? WHERE id=? AND status='pending'",
        (expires, sid)
    )
    if db.execute("SELECT changes()").fetchone()[0] != 1:
        db.rollback()
        return jsonify({"error": "Subscription was already processed"}), 409

    db.execute(
        "UPDATE companies SET plan=? WHERE id=?",
        (sub["plan"], sub["company_id"])
    )
    db.commit()
    return jsonify({
        "message": "Subscription approved",
        "company_id": sub["company_id"],
        "plan": sub["plan"],
        "duration_days": plans[sub["plan"]]["days"],
        "expires": expires
    })

def get_password_reset_base_url():
    configured = os.environ.get("SAAS_HR_BASE_URL", "").strip()

    if not configured:
        if IS_PRODUCTION:
            raise RuntimeError(
                "SAAS_HR_BASE_URL must be configured in production"
            )
        configured = "http://127.0.0.1:5000"

    parsed = urlparse(configured)

    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError("SAAS_HR_BASE_URL is invalid")

    if IS_PRODUCTION and parsed.scheme != "https":
        raise RuntimeError(
            "SAAS_HR_BASE_URL must use HTTPS in production"
        )

    return configured.rstrip("/")


def send_password_reset_email(recipient, link):
    host = os.environ.get("SMTP_HOST", "smtp.gmail.com").strip()
    username = os.environ.get("SMTP_USERNAME", "").strip()
    password = os.environ.get("SMTP_PASSWORD", "")
    sender = os.environ.get("SMTP_FROM", username).strip()

    if not host or not username or not password or not sender:
        raise RuntimeError(
            "SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD and SMTP_FROM "
            "must be configured"
        )

    try:
        port = int(os.environ.get("SMTP_PORT", "587"))
    except ValueError:
        raise RuntimeError("SMTP_PORT must be a valid port number") from None

    if not 1 <= port <= 65535:
        raise RuntimeError("SMTP_PORT is outside the valid range")

    message = EmailMessage()
    message["Subject"] = "Reset your SaaS-HR password"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        "We received a request to reset your SaaS-HR password.\n\n"
        "Open the link below within 15 minutes to choose a new password:\n\n"
        f"{link}\n\n"
        "If you did not request this, you can ignore this email.\n"
        "Do not share this link with anyone."
    )

    # Gmail submission uses STARTTLS. Never send credentials before TLS.
    with smtplib.SMTP(host, port, timeout=15) as server:
        server.ehlo()
        server.starttls(context=ssl.create_default_context())
        server.ehlo()
        server.login(username, password)
        server.send_message(message)


@app.route('/api/password/forgot', methods=['POST'])
def password_recovery_request():
    data = request.get_json(silent=True) or {}
    email = str(data.get('email', '')).strip().lower()

    generic = {
        "message": "If an account exists for that email, recovery instructions will be sent."
    }

    if not email or len(email) > 254:
        return jsonify(generic), 200

    db = get_db()
    accounts = []

    owner = db.execute(
        "SELECT id, email FROM platform_admins WHERE lower(email)=?",
        (email,)
    ).fetchone()
    if owner:
        accounts.append(("owner", owner["id"], owner["email"]))

    company = db.execute(
        "SELECT id, email FROM companies WHERE lower(email)=?",
        (email,)
    ).fetchone()
    if company:
        accounts.append(("company", company["id"], company["email"]))

    employees = db.execute(
        """SELECT id, email FROM users
           WHERE lower(email)=? AND active=1
             AND email IS NOT NULL AND trim(email)<>''""",
        (email,)
    ).fetchall()

    for employee in employees:
        accounts.append(("employee", employee["id"], employee["email"]))

    # Always return the same public response, regardless of account existence.
    if not accounts:
        return jsonify(generic), 200

    now = datetime.now(timezone.utc)
    try:
        # Use a configured trusted URL, not the incoming Host header.
        base_url = get_password_reset_base_url()

        for account_type, account_id, recipient in accounts:
            # Invalidate previous unused reset links for this account.
            db.execute(
                "UPDATE password_resets SET used=1 WHERE account_type=? AND account_id=? AND used=0",
                (account_type, account_id)
            )

            token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            reset_id = uuid.uuid4().hex

            db.execute(
                """INSERT INTO password_resets
                   (id, account_type, account_id, token_hash, expires_at, used, created_at)
                   VALUES (?, ?, ?, ?, ?, 0, ?)""",
                (
                    reset_id,
                    account_type,
                    account_id,
                    token_hash,
                    (now + timedelta(minutes=15)).isoformat(),
                    now.isoformat()
                )
            )

            link = f"{base_url}/reset-password?token={token}"
            send_password_reset_email(recipient, link)

        db.commit()
    except Exception:
        db.rollback()
        app.logger.exception("Password recovery email could not be sent")
        # Never expose reset tokens or account existence in the response.
        return jsonify(generic), 200

    return jsonify(generic), 200


@app.route('/api/password/reset', methods=['POST'])
def password_recovery_reset():
    data = request.get_json(silent=True) or {}
    token = data.get("token", "")
    password = data.get("password", "")

    if not isinstance(token, str) or not token or len(token) > 200:
        return jsonify({"error": "Invalid or expired reset link"}), 400
    policy_error = password_policy_error(password)
    if policy_error:
        return jsonify({"error": policy_error}), 400

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    password_hash = generate_password_hash(password)
    db = get_db()

    try:
        # Serialize redemption attempts before checking token status.
        db.execute("BEGIN IMMEDIATE")
        reset = db.execute(
            "SELECT * FROM password_resets WHERE token_hash=? AND used=0",
            (token_hash,)
        ).fetchone()

        if not reset:
            db.rollback()
            return jsonify({"error": "Invalid or expired reset link"}), 400

        try:
            expires = datetime.fromisoformat(reset["expires_at"])
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            db.rollback()
            return jsonify({"error": "Invalid or expired reset link"}), 400

        if expires <= datetime.now(timezone.utc):
            db.execute(
                "UPDATE password_resets SET used=1 WHERE id=? AND used=0",
                (reset["id"],)
            )
            db.commit()
            return jsonify({"error": "Invalid or expired reset link"}), 400

        if reset["account_type"] == "owner":
            cursor = db.execute(
                "UPDATE platform_admins SET password=? WHERE id=?",
                (password_hash, reset["account_id"])
            )
        elif reset["account_type"] == "company":
            cursor = db.execute(
                "UPDATE companies SET password=? WHERE id=?",
                (password_hash, reset["account_id"])
            )
        elif reset["account_type"] == "employee":
            cursor = db.execute(
                "UPDATE users SET password=? WHERE id=? AND active=1",
                (password_hash, reset["account_id"])
            )
        else:
            db.rollback()
            return jsonify({"error": "Invalid or expired reset link"}), 400

        if cursor.rowcount != 1:
            db.rollback()
            return jsonify({"error": "Invalid or expired reset link"}), 400

        # Incrementing this value revokes sessions issued before this reset.
        db.execute(
            """
            INSERT INTO auth_versions (account_type, account_id, version)
            VALUES (?, ?, 2)
            ON CONFLICT(account_type, account_id)
            DO UPDATE SET version = auth_versions.version + 1
            """,
            (reset["account_type"], str(reset["account_id"])),
        )

        consumed = db.execute(
            "UPDATE password_resets SET used=1 WHERE id=? AND used=0",
            (reset["id"],)
        )
        if consumed.rowcount != 1:
            db.rollback()
            return jsonify({"error": "Invalid or expired reset link"}), 400

        db.execute(
            """UPDATE password_resets SET used=1
               WHERE account_type=? AND account_id=? AND used=0""",
            (reset["account_type"], reset["account_id"])
        )
        db.commit()

    except Exception:
        db.rollback()
        app.logger.exception("Password reset transaction failed")
        return jsonify({"error": "Unable to reset password right now"}), 500

    return jsonify({"message": "Password reset successful. Please log in again."}), 200


@app.route('/forgot-password')
def forgot_password_page():
    return render_template('forgot_password.html')


@app.route('/reset-password')
def reset_password_page():
    token = request.args.get('token', '')
    return render_template('reset_password.html', token=token)



if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', '5000')),
        debug=os.environ.get('SAAS_HR_DEBUG', '').lower() == 'true'
    )
