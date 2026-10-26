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

from flask import Flask, request, jsonify, g, render_template_string, session, abort
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
            "SELECT active FROM users WHERE id=? AND company_id=?",
            (employee_id, cid)
        ).fetchone()
        if not employee_record or not employee_record["active"]:
            session.clear()
            return jsonify({"error": "Employee account is inactive"}), 401

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
    html = html[:position] + helper + html[position:]
    response.set_data(html)
    return response

@app.route('/api/company/register', methods=['POST'])
def reg():
    d=request.json; cid=uuid.uuid4().hex[:8]; db=get_db()
    try:
        db.execute("INSERT INTO companies VALUES (?,?,?,?,?,?)",(cid,d['name'],d['email'],generate_password_hash(d['password']),'free',datetime.now().isoformat()))
        db.commit()
        return jsonify({"company_id":cid}),201
    except: return jsonify({"error":"exists"}),400
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
        """SELECT id, company_id, name, email, role, active
           FROM users WHERE id = ? AND company_id = ?""",
        (employee_id, company_id)
    ).fetchone()

    if not employee or not employee["active"]:
        session.clear()
        return jsonify({"authenticated": False}), 401

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
    if not isinstance(password, str) or len(password) < 10:
        return jsonify({
            "error": "Set an employee password with at least 10 characters"
        }), 400
    if role not in ("staff", "HR"):
        return jsonify({"error": "Unsupported employee role"}), 400

    db = get_db()
    duplicate = db.execute(
        "SELECT id FROM users WHERE company_id=? AND lower(email)=?",
        (cid, email)
    ).fetchone()
    if duplicate:
        return jsonify({"error": "An employee with this email already exists"}), 409

    uid = uuid.uuid4().hex[:8]
    db.execute(
        """INSERT INTO users
           (id, company_id, name, email, role, department, photo,
            photo_hash, password, created, active)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
        (
            uid, cid, name, email, role, department, "default.png", "",
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
        "SELECT id, active FROM users WHERE id=? AND company_id=?",
        (user_id, company_id)
    ).fetchone()

    if not employee:
        return jsonify({"error": "Employee not found"}), 404

    db.execute(
        "UPDATE users SET active=? WHERE id=? AND company_id=?",
        (1 if active else 0, user_id, company_id)
    )
    db.commit()

    return jsonify({
        "id": user_id,
        "active": active,
        "message": "Employee activated" if active else "Employee deactivated"
    })


@app.route('/api/staff/<cid>')
def list_staff(cid):
    db = get_db()
    rows = db.execute(
        """SELECT id, name, email, role, department, created, active
           FROM users WHERE company_id=? ORDER BY created DESC""",
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
    return render_template_string("""
<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><link href="https://cdnjs.cloudflare.com/ajax/libs/remixicon/4.2.0/remixicon.min.css" rel="stylesheet">
<style>*{margin:0;padding:0;box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont}body{background:#f5f6f8;padding-bottom:90px}.topbar{background:#0a0a0a;color:#fff;padding:16px 20px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:10}.badge{background:#1a1a1a;border:1px solid #2a2a2a;padding:6px 12px;border-radius:20px;font-size:11px}.card{background:#fff;border-radius:20px;padding:16px;margin-top:12px}.tab{display:none}.tab.active{display:block}.bottom-nav{position:fixed;bottom:0;left:0;right:0;background:#fff;display:flex;justify-content:space-around;padding:8px 0 20px;border-top:1px solid #eee;z-index:20}.nav-item{flex:1;text-align:center;color:#9a9a9a;font-size:10px;cursor:pointer}.nav-item.active{color:#000}.nav-item i{font-size:22px;display:block}.btn{width:100%;padding:14px;border-radius:14px;border:0;font-weight:700;cursor:pointer}.btn-black{background:#000;color:#fff}.btn-ghost{background:#f5f5f5}.btn-sm{width:auto;padding:8px 14px;font-size:12px}input,select{width:100%;padding:14px;border-radius:14px;border:1.5px solid #eee;margin:7px 0}.list-item{display:flex;justify-content:space-between;padding:14px 0;border-bottom:1px solid #f6f6f6}.avatar{width:42px;height:42px;background:#111;color:#fff;border-radius:12px;display:flex;align-items:center;justify-content:center;font-weight:800}.login{position:fixed;inset:0;background:#000;z-index:100;display:flex;align-items:center;justify-content:center;padding:20px}</style></head><body>
<div id="loginScreen" class="login">
<div class="card" style="width:100%;max-width:380px">
<h2>SaaS-HR</h2>
<p>Create your company account or log in.</p>
<div id="loginForm">
<h3>Company Login</h3>
<input id="loginEmail" type="email" placeholder="Company email" autocomplete="username">
<input id="loginPass" type="password" placeholder="Password" autocomplete="current-password">
<p style="text-align:right;margin:8px 0"><a href="/forgot-password">Forgot password?</a></p>
<button class="btn btn-black" onclick="doLogin()">Login</button>
<p>New to SaaS-HR? <button type="button" onclick="showRegisterForm()">Register a company</button></p>
</div>
<div id="registerForm" style="display:none">
<h3>Register Your Company</h3>
<input id="registerName" placeholder="Company name" autocomplete="organization">
<input id="registerEmail" type="email" placeholder="Company email" autocomplete="email">
<input id="registerPass" type="password" placeholder="Create password (at least 8 characters)" autocomplete="new-password">
<button class="btn btn-black" onclick="registerCompany()">Create Company Account</button>
<p>Already registered? <button type="button" onclick="showLoginForm()">Back to login</button></p>
</div>
<p id="registerMessage" role="status"></p>
</div>
</div>
<div class="topbar"><h2 id="topTitle">Home</h2><div style="display:flex;align-items:center"><button onclick="doLogout()" style="background:#222;color:#fff;border:1px solid #333;padding:7px 14px;border-radius:20px;font-size:12px;margin-right:10px">Logout</button><div class="badge"><span id="compId">84c932fa</span></div></div></div>
<div class="container"><div id="tab-home" class="tab active"><div style="display:grid;grid-template-columns:1fr 1fr;gap:12px"><div class="card"><p>Staff</p><h3 id="stStaff" style="font-size:26px">0</h3></div><div class="card"><p>Present</p><h3 id="stPresent" style="font-size:26px">0</h3><p style="color:#10b981;font-size:11px">50m fence</p></div></div><div class="card"><h4>Live</h4><div id="liveList"></div></div></div>
<div id="tab-staff" class="tab"><div class="card"><h4>Add Staff</h4><input id="sname" placeholder="Name"><input id="semail" placeholder="Email"><select id="srole"><option>staff</option><option>HR</option></select><input id="sdept" value="Engineering"><input id="spass" type="password" placeholder="Employee password (at least 10 characters)" minlength="10" autocomplete="new-password"><button class="btn btn-black" onclick="addStaff()">Add</button></div><div class="card"><h4>Staff - 50m</h4><div id="staffList"></div></div></div>
<div id="tab-time" class="tab"><div class="card"><h4>Attendance</h4><div id="clockBoard"></div><div id="attList" style="margin-top:10px"></div></div></div>
<div id="tab-pay" class="tab"><div class="card"><h4>Plans</h4><button class="btn btn-black" onclick="openPay('pro',5000)">Pay Pro ₦5k</button></div><div class="card" style="display:none" id="payBox"><p>Acct <b id="mpAccount">-</b> Name <b id="mpName">-</b> Amt <b id="mpAmount">-</b></p><input id="proof" placeholder="ref"><button class="btn btn-black" onclick="submitProof()">Submit</button></div><div class="card"><div id="mySubs"></div></div></div>
<div id="tab-settings" class="tab"><div class="card"><h4>Office GPS 50m</h4><div style="display:grid;grid-template-columns:1fr 1fr;gap:8px"><input id="setLat" type="number" step="0.000001"><input id="setLng" type="number" step="0.000001"></div><input id="setRadius" value="50" type="number"><button class="btn btn-ghost" onclick="useMyLocation()">📍 My Location</button><button class="btn btn-black" style="margin-top:8px" onclick="saveOffice()">Save Office</button><p id="officeStatus"></p></div><div class="card"><h4>Moniepoint</h4><input id="setAccount"><input id="setName"><button class="btn btn-black" onclick="saveSettings()">Save</button></div><div class="card"><h4>Approve</h4><div id="allSubs"></div><button class="btn btn-ghost" onclick="loadAllSubs()">Load</button></div></div></div>
<div class="bottom-nav"><div class="nav-item active" onclick="navTo('home',this)"><i class="ri-home-5-fill"></i>Home</div><div class="nav-item" onclick="navTo('staff',this)"><i class="ri-team-line"></i>Staff</div><div class="nav-item" onclick="navTo('time',this)"><i class="ri-time-line"></i>Time</div><div class="nav-item" onclick="navTo('pay',this)"><i class="ri-wallet-3-line"></i>Pay</div><div class="nav-item" onclick="navTo('settings',this)"><i class="ri-settings-3-line"></i>You</div></div>
<script>
let CID='';
const loginScreen=document.getElementById('loginScreen');

function showRegisterForm(){
    document.getElementById('loginForm').style.display='none';
    document.getElementById('registerForm').style.display='block';
    document.getElementById('registerMessage').innerText='';
}

function showLoginForm(){
    document.getElementById('registerForm').style.display='none';
    document.getElementById('loginForm').style.display='block';
    document.getElementById('registerMessage').innerText='';
}

async function registerCompany(){
    const name=document.getElementById('registerName').value.trim();
    const email=document.getElementById('registerEmail').value.trim();
    const password=document.getElementById('registerPass').value;
    const message=document.getElementById('registerMessage');

    if(!name||!email||!password){
        message.innerText='Please fill in all fields.';
        return;
    }
    if(password.length<8){
        message.innerText='Password must contain at least 8 characters.';
        return;
    }

    message.innerText='Creating company account...';
    try{
        const response=await fetch('/api/company/register',{
            method:'POST',
            credentials:'same-origin',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({name,email,password})
        });
        const result=await response.json();

        if(response.ok && result.company_id){
            document.getElementById('loginEmail').value=email;
            document.getElementById('loginPass').value=password;
            message.innerText='Company registered! Logging you in...';
            await doLogin();
        }else{
            message.innerText=result.error==='exists'
                ?'Registration failed. This email may already be registered.'
                :(result.error||'Registration failed. Please try again.');
        }
    }catch(error){
        message.innerText='Could not connect to the server. Please try again.';
    }
}

function showDashboard(company){
    CID=company.company_id;
    localStorage.setItem('cid',CID);
    document.getElementById('compId').innerText=CID;
    loginScreen.style.display='none';
    loadStats();
    loadStaff();
    loadSettings();
}

function showLogin(){
    CID='';
    localStorage.removeItem('cid');
    document.getElementById('compId').innerText='Not logged in';
    loginScreen.style.display='flex';
}

async function checkSession(){
    try{
        const r=await fetch('/api/session',{credentials:'same-origin'});
        if(!r.ok){
            showLogin();
            return;
        }
        const company=await r.json();
        if(company.authenticated && company.company_id){
            showDashboard(company);
        }else{
            showLogin();
        }
    }catch(error){
        showLogin();
    }
}

async function doLogin(){
    const email=document.getElementById('loginEmail').value.trim();
    const password=document.getElementById('loginPass').value;

    if(!email||!password){
        alert('Enter your email and password.');
        return;
    }

    try{
        const r=await fetch('/api/company/login',{
            method:'POST',
            credentials:'same-origin',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({email:email,password:password})
        });
        const j=await r.json();

        if(r.ok && j.company_id){
            showDashboard({company_id:j.company_id,name:j.name});
        }else{
            alert(j.error||'Login failed. Check your details.');
        }
    }catch(error){
        alert('Cannot connect. Please try again when the server is available.');
    }
}

async function doLogout(){
    if(!confirm('Logout?'))return;

    try{
        await fetch('/api/logout',{
            method:'POST',
            credentials:'same-origin'
        });
    }finally{
        localStorage.removeItem('cid');
        showLogin();
        location.reload();
    }
}

checkSession();

function navTo(t,el){document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));document.getElementById('tab-'+t).classList.add('active');if(el){document.querySelectorAll('.nav-item').forEach(x=>x.classList.remove('active'));el.classList.add('active');}if(t=='home')loadStats();if(t=='staff')loadStaff();if(t=='time')loadTimePage();if(t=='pay'){loadSettings();loadMySubs();}if(t=='settings'){loadSettings();loadAllSubs();}}
async function loadStats(){let r=await fetch('/api/stats/'+CID);let d=await r.json();document.getElementById('stStaff').innerText=d.staff;document.getElementById('stPresent').innerText=d.present;}
async function addStaff(){let body={company_id:CID,name:sname.value,email:semail.value,role:srole.value,department:sdept.value,password:spass.value};if(!body.name||!body.email)return alert('Name and email are required');if(!body.password||body.password.length<10)return alert('Set a password of at least 10 characters');let r=await fetch('/api/staff',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});let d=await r.json();if(!r.ok)return alert(d.error||'Could not add employee');alert('Employee added. Share the password securely.');spass.value='';loadStaff();loadStats();}
async function loadStaff(){let r=await fetch('/api/staff/'+CID);let staff=await r.json();let html='';for(let u of staff){let st=await (await fetch('/api/attendance/status/'+u.id)).json();let btn=st.status=='not_in'?`<button class="btn btn-black btn-sm" onclick="doClockIn('${u.id}')">In</button>`:st.status=='in'?`<button class="btn btn-ghost btn-sm" onclick="doClockOut('${u.id}')">Out ${Math.round(st.distance||0)}m</button>`:`Done ${Math.round(st.distance||0)}m ✓`;html+=`<div class="list-item"><div style="display:flex;gap:8px"><div class="avatar">${u.name[0].toUpperCase()}</div><div><b>${u.name}</b></div></div>${btn}</div>`;}document.getElementById('staffList').innerHTML=html||'No staff';document.getElementById('liveList').innerHTML=html;}
async function loadTimePage(){let r=await fetch('/api/staff/'+CID);let staff=await r.json();let board='';for(let u of staff){let st=await (await fetch('/api/attendance/status/'+u.id)).json();let btn=st.status=='not_in'?`<button class="btn btn-black btn-sm" onclick="doClockIn('${u.id}')">IN</button>`:st.status=='in'?`<button class="btn btn-ghost btn-sm" onclick="doClockOut('${u.id}')">OUT</button>`:`✓`;board+=`<div class="list-item"><b>${u.name}</b> ${btn}</div>`;}document.getElementById('clockBoard').innerHTML=board;loadAtt();}
async function doClockIn(uid){navigator.geolocation.getCurrentPosition(async pos=>{let r=await fetch('/api/attendance/clock-in',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({company_id:CID,user_id:uid,lat:pos.coords.latitude,lng:pos.coords.longitude,photo_hash:btoa(uid+Date.now()).slice(0,40)})});let j=await r.json();alert(j.msg);loadStaff();loadTimePage();loadStats();},()=>alert('Enable GPS'),{enableHighAccuracy:true});}
async function doClockOut(uid){let r=await fetch('/api/attendance/clock-out',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({company_id:CID,user_id:uid})});let j=await r.json();alert(j.msg);loadStaff();loadTimePage();loadStats();}
async function loadAtt(){let r=await fetch('/api/attendance/'+CID);let d=await r.json();document.getElementById('attList').innerHTML=d.map(a=>`<div class="list-item"><b>${a.name}</b> ${a.date} ${Math.round(a.distance||0)}m</div>`).join('')||'None';}
async function loadSettings(){let r=await fetch('/api/settings');let d=await r.json();mpAccount.innerText=d.moniepoint_account||'-';mpName.innerText=d.moniepoint_name||'-';setAccount.value=d.moniepoint_account||'';setName.value=d.moniepoint_name||'';setLat.value=d.office_lat||6.5244;setLng.value=d.office_lng||3.3792;setRadius.value=d.office_radius||50;officeStatus.innerText=`Fence ${d.office_radius}m`;}
async function useMyLocation(){navigator.geolocation.getCurrentPosition(p=>{setLat.value=p.coords.latitude;setLng.value=p.coords.longitude;});}
async function saveOffice(){await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({office_lat:parseFloat(setLat.value),office_lng:parseFloat(setLng.value),office_radius:parseFloat(setRadius.value)})});alert('Saved');loadSettings();}
async function saveSettings(){await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({account:setAccount.value,name:setName.value})});alert('Saved');}
function openPay(p,a){curPlan=p;curAmount=a;mpAmount.innerText='₦'+a;payBox.style.display='block';}
async function submitProof(){await fetch('/api/subscribe',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({company_id:CID,plan:curPlan,amount:curAmount,proof:proof.value})});alert('Submitted');loadMySubs();}
async function loadMySubs(){let r=await fetch('/api/subscriptions/'+CID);let d=await r.json();mySubs.innerHTML=d.map(s=>`<div>${s.plan} ${s.status}</div>`).join('')||'None';}
async function loadAllSubs(){let r=await fetch('/api/subscriptions/all');let d=await r.json();allSubs.innerHTML=d.map(s=>`<div class="list-item"><b>${s.company_id}</b> <button class="btn btn-black btn-sm" onclick="approveSub('${s.id}')">Approve</button></div>`).join('')||'None';}
async function approveSub(id){await fetch('/api/subscriptions/approve/'+id,{method:'POST'});alert('Approved');loadAllSubs();}
</script></body></html>
    """)



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
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SaaS-HR Platform Owner</title>
<style>
*{box-sizing:border-box;font-family:Arial,sans-serif}
body{margin:0;background:#f1f5f9;min-height:100vh;display:grid;place-items:center;padding:20px}
.card{background:white;padding:28px;border-radius:16px;width:100%;max-width:420px;box-shadow:0 8px 30px #0001}
h1{font-size:25px;margin-bottom:8px}p{color:#64748b}
input,button{width:100%;padding:14px;margin-top:14px;border-radius:9px;font-size:16px}
input{border:1px solid #cbd5e1}
button{background:#111827;color:white;border:0;cursor:pointer}
#message{overflow-wrap:anywhere;color:#b91c1c}
</style>
</head>
<body>
<div class="card">
<h1>SaaS-HR Owner</h1>
<p>Sign in to manage your SaaS-HR platform.</p>
<form id="loginForm">
<input id="email" type="email" autocomplete="username" placeholder="Owner email" required>
<input id="password" type="password" autocomplete="current-password" placeholder="Password" required>
<button id="submit" type="submit">Sign in</button>
</form>
<p style="text-align:right;margin:8px 0"><a href="/forgot-password">Forgot password?</a></p>
<p id="message" role="status" aria-live="polite"></p>
</div>
<script>
document.getElementById('loginForm').addEventListener('submit',async e=>{
 e.preventDefault();
 const button=document.getElementById('submit');
 const message=document.getElementById('message');
 button.disabled=true;
 message.textContent='Signing in...';
 try{
  const r=await fetch('/api/owner/login',{
   method:'POST',
   headers:{'Content-Type':'application/json'},
   credentials:'same-origin',
   body:JSON.stringify({
    email:document.getElementById('email').value.trim(),
    password:document.getElementById('password').value
   })
  });
  const d=await r.json();
  if(!r.ok) throw new Error(d.error||'Owner login failed.');
  location.href='/owner-dashboard';
 }catch(err){
  message.textContent=err.message||'Unable to sign in. Check your connection.';
 }finally{
  button.disabled=false;
 }
});
</script>
<script>
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js')
      .catch(error => console.error('Service worker registration failed:', error));
  });
}
</script>
</body>
</html>
""")


@app.route('/owner-dashboard')
def owner_dashboard_page():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SaaS-HR Platform Dashboard</title>
<style>
*{box-sizing:border-box;font-family:Arial,sans-serif}
body{margin:0;background:#f1f5f9;color:#0f172a}
header{background:#111827;color:white;padding:18px 22px;display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
header h1{font-size:21px;margin:0}
button{border:0;border-radius:8px;padding:10px 14px;cursor:pointer;background:#111827;color:white}
header button{background:white;color:#111827}
main{max-width:1100px;margin:25px auto;padding:0 16px}
section{background:white;border-radius:13px;padding:18px;margin-bottom:22px;overflow-x:auto}
h2{margin-top:0;font-size:20px}
table{width:100%;border-collapse:collapse;min-width:570px}
th,td{text-align:left;padding:12px;border-bottom:1px solid #e2e8f0;font-size:14px}
th{background:#f8fafc}
.status{display:inline-block;padding:5px 9px;border-radius:20px;background:#e2e8f0}
#message{color:#b91c1c}
@media(max-width:600px){main{margin:14px auto}section{padding:12px}th,td{padding:9px}}
</style>
</head>
<body>
<header>
<h1>SaaS-HR Platform Owner</h1>
<div><span id="ownerEmail"></span> <button id="logout">Log out</button></div>
</header>
<main>
<p id="message" role="status" aria-live="polite">Checking owner session...</p>
<section>
<h2>Registered Companies</h2>
<div id="companies">Loading companies...</div>
</section>
<section>
<h2>Subscriptions</h2>
<div id="subscriptions">Loading subscriptions...</div>
</section>
</main>
<script>
const message=document.getElementById('message');
function cell(value){
 const td=document.createElement('td');
 td.textContent=value==null?'':String(value);
 return td;
}
function table(headers,rows){
 const t=document.createElement('table');
 const thead=document.createElement('thead');
 const hr=document.createElement('tr');
 headers.forEach(h=>{const th=document.createElement('th');th.textContent=h;hr.appendChild(th)});
 thead.appendChild(hr);t.appendChild(thead);
 const body=document.createElement('tbody');
 rows.forEach(row=>body.appendChild(row));
 t.appendChild(body);return t;
}
async function api(url,options={}){
 const r=await fetch(url,{credentials:'same-origin',...options});
 const d=await r.json();
 if(r.status===401){location.href='/owner-login';throw new Error('Owner session expired. Please sign in again.')}
 if(!r.ok)throw new Error(d.error||'Request failed.');
 return d;
}
async function loadCompanies(){
 const data=await api('/api/owner/companies');
 const rows=data.map(c=>{
  const tr=document.createElement('tr');
  [c.name,c.email,c.plan,c.created].forEach(v=>tr.appendChild(cell(v)));
  return tr;
 });
 const box=document.getElementById('companies');
 box.replaceChildren();
 if(!rows.length){box.textContent='No companies registered yet.';return}
 box.appendChild(table(['Company','Email','Plan','Created'],rows));
}
async function loadSubscriptions(){
 const data=await api('/api/owner/subscriptions');
 const rows=data.map(s=>{
  const tr=document.createElement('tr');
  [s.company_name||s.company_id,s.plan,'₦'+Number(s.amount||0).toLocaleString(),s.status,s.created].forEach(v=>tr.appendChild(cell(v)));
  const action=document.createElement('td');
  if(String(s.status).toLowerCase()!=='approved' && String(s.status).toLowerCase()!=='active'){
   const button=document.createElement('button');
   button.textContent='Approve';
   button.addEventListener('click',async()=>{
    if(!confirm('Approve this subscription?'))return;
    button.disabled=true;
    try{
     await api('/api/owner/subscriptions/approve/'+encodeURIComponent(s.id),{method:'POST'});
     await loadSubscriptions();
     message.textContent='Subscription approved.';
    }catch(e){message.textContent=e.message;button.disabled=false}
   });
   action.appendChild(button);
  }else{
   action.textContent='—';
  }
  tr.appendChild(action);return tr;
 });
 const box=document.getElementById('subscriptions');
 box.replaceChildren();
 if(!rows.length){box.textContent='No subscriptions found.';return}
 box.appendChild(table(['Company','Plan','Amount','Status','Created','Action'],rows));
}
async function start(){
 try{
  const d=await api('/api/owner/session');
  document.getElementById('ownerEmail').textContent=d.email||'Owner';
  await Promise.all([loadCompanies(),loadSubscriptions()]);
  message.textContent='';
 }catch(e){message.textContent=e.message}
}
document.getElementById('logout').addEventListener('click',async()=>{
 try{await fetch('/api/owner/logout',{method:'POST',credentials:'same-origin'})}
 finally{location.href='/owner-login'}
});
start();
</script>
<script>
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js')
      .catch(error => console.error('Service worker registration failed:', error));
  });
}
</script>
</body>
</html>
""")

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

@app.route('/api/owner/companies')
def owner_companies():
    rows = get_db().execute(
        "SELECT id, name, email, plan, created FROM companies ORDER BY created DESC"
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
    if not isinstance(password, str) or len(password) < 12:
        return jsonify({"error": "Password must be at least 12 characters"}), 400

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
        else:
            db.rollback()
            return jsonify({"error": "Invalid or expired reset link"}), 400

        if cursor.rowcount != 1:
            db.rollback()
            return jsonify({"error": "Invalid or expired reset link"}), 400

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
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Forgot Password | SaaS-HR</title>
<style>
*{box-sizing:border-box;font-family:Arial,sans-serif}
body{margin:0;background:#f5f6f8;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:white;padding:25px;border-radius:18px;width:100%;max-width:400px}
input,button{width:100%;padding:14px;border-radius:10px;margin-top:12px}
input{border:1px solid #ddd}
button{background:#000;color:white;border:0;font-weight:bold}
a{color:#333}#message{overflow-wrap:anywhere}
</style>
</head>
<body>
<div class="card">
<h2>SaaS-HR</h2>
<h3>Forgot your password?</h3>
<p>Enter your account email. If an account matches, reset instructions will be sent.</p>
<form id="forgotForm">
<input id="email" type="email" autocomplete="email" placeholder="Account email" required>
<button type="submit">Send Reset Link</button>
</form>
<p id="message" role="status" aria-live="polite"></p>
<p><a href="/">Back to login</a></p>
</div>
<script>
document.getElementById('forgotForm').addEventListener('submit',async function(event){
    event.preventDefault();
    const message=document.getElementById('message');
    const button=this.querySelector('button');
    button.disabled=true;
    message.textContent='Sending request...';
    try{
        const response=await fetch('/api/password/forgot',{
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({email:document.getElementById('email').value.trim()})
        });
        const data=await response.json();
        message.textContent=data.message||data.error||'If the account exists, reset instructions will be sent.';
    }catch(error){
        message.textContent='Unable to send the request. Check your connection and try again.';
    }finally{
        button.disabled=false;
    }
});
</script>
</body>
</html>
""")


@app.route('/reset-password')
def reset_password_page():
    token = request.args.get('token', '')
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Reset Password | SaaS-HR</title>
<style>
*{box-sizing:border-box;font-family:Arial,sans-serif}
body{margin:0;background:#f5f6f8;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:white;padding:25px;border-radius:18px;width:100%;max-width:400px}
input,button{width:100%;padding:14px;border-radius:10px;margin-top:12px}
input{border:1px solid #ddd}
button{background:#000;color:white;border:0;font-weight:bold}
a{color:#333}#message{overflow-wrap:anywhere}
</style>
</head>
<body>
<div class="card">
<h2>SaaS-HR</h2>
<h3>Choose a new password</h3>
<p>Use at least 12 characters.</p>
<form id="resetForm">
<input id="password" type="password" autocomplete="new-password" minlength="12" placeholder="New password (12+ characters)" required>
<input id="confirm" type="password" autocomplete="new-password" minlength="12" placeholder="Confirm new password" required>
<button type="submit">Reset Password</button>
</form>
<p id="message" role="status" aria-live="polite"></p>
<p><a href="/">Back to login</a></p>
</div>
<script>
const token={{ token|tojson }};
const form=document.getElementById('resetForm');
const message=document.getElementById('message');
if(!token){
    message.textContent='Reset token missing. Please request a new link.';
    form.querySelector('button').disabled=true;
}
form.addEventListener('submit',async function(event){
    event.preventDefault();
    const password=document.getElementById('password').value;
    const confirm=document.getElementById('confirm').value;
    if(password.length<12){message.textContent='Password must contain at least 12 characters.';return;}
    if(password!==confirm){message.textContent='The passwords do not match.';return;}
    const button=form.querySelector('button');
    button.disabled=true;
    message.textContent='Resetting password...';
    try{
        const response=await fetch('/api/password/reset',{
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({token:token,password:password})
        });
        const data=await response.json();
        message.textContent=data.message||data.error||'Unable to reset password.';
        if(response.ok){
            form.style.display='none';
            const link=document.createElement('a');
            link.href='/';
            link.textContent='Go to login';
            message.appendChild(document.createElement('br'));
            message.appendChild(link);
        }
    }catch(error){
        message.textContent='Connection error. Please try again.';
    }finally{
        button.disabled=false;
    }
});
</script>
</body>
</html>
""", token=token)



if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', '5000')),
        debug=os.environ.get('SAAS_HR_DEBUG', '').lower() == 'true'
    )
