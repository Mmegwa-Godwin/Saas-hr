import os

from app_factory import app
from auth_helpers import enforce_csrf_for_mutation, require_company_session, require_employee_session, require_owner_session
from config import AppConfig
from database import get_db
from utils import haversine
from validators import is_valid_email, normalize_email, validate_company_id, validate_password

# app is now created by app_factory for a cleaner startup path.
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


@app.route('/api/company/register', methods=['POST'])
def reg():
    d = request.get_json(silent=True) or {}
    name = str(d.get('name', '')).strip()
    email = normalize_email(d.get('email'))
    password = d.get('password', '')

    if not name or not is_valid_email(email):
        return jsonify({"error": "Valid company name and email are required"}), 400
    if not validate_password(password, minimum=8):
        return jsonify({"error": "Password must contain at least 8 characters"}), 400

    cid = uuid.uuid4().hex[:8]
    db = get_db()
    try:
        db.execute(
            "INSERT INTO companies VALUES (?,?,?,?,?,?)",
            (cid, name, email, generate_password_hash(password), 'free', datetime.now().isoformat()),
        )
        db.commit()
        return jsonify({"company_id": cid}), 201
    except Exception:
        return jsonify({"error": "exists"}), 400


@app.route('/api/company/login', methods=['POST'])
def login():
    d = request.get_json(silent=True) or {}
    db = get_db()
    email = normalize_email(d.get('email'))
    password = d.get('password', '')
    if not isinstance(password, str):
        password = ''

    if not is_valid_email(email):
        return jsonify({"error": "Valid email is required"}), 400

    c = db.execute(
        "SELECT * FROM companies WHERE lower(email)=?",
        (email,),
    ).fetchone()
    if c and check_password_hash(c['password'], password):
        session.clear()
        session['company_id'] = c['id']
        session['company_name'] = c['name']
        return jsonify({"company_id": c['id'], "name": c['name']})
    return jsonify({"error": "invalid"}), 401


@app.route('/api/employee/login', methods=['POST'])
def employee_login():
    data = request.get_json(silent=True) or {}
    company_id = str(data.get('company_id', '')).strip()
    email = normalize_email(data.get('email'))
    password = data.get('password', '')

    if not validate_company_id(company_id) or not is_valid_email(email) or not isinstance(password, str) or not password:
        return jsonify({"error": "Company ID, email and password are required"}), 400

    db = get_db()
    employee = db.execute(
        """SELECT u.id, u.company_id, u.name, u.email, u.role, u.password,
                  u.active, c.name AS company_name
           FROM users u
           JOIN companies c ON c.id = u.company_id
           WHERE u.company_id = ? AND lower(u.email) = ?""",
        (company_id, email)
    ).fetchone()

    if not employee or not employee["active"] or not check_password_hash(employee["password"], password):
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
        "role": employee['role'],
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
        (employee_id, company_id),
    ).fetchone()

    if not employee or not employee["active"]:
        session.clear()
        return jsonify({"authenticated": False}), 401

    return jsonify({
        "authenticated": True,
        "account_type": "employee",
        "employee": dict(employee),
    })


@app.route('/api/session')
def check_session():
    if session.get("employee_id"):
        return jsonify({"authenticated": False, "error": "This is an employee session"}), 403

    cid = session.get('company_id')
    if not cid:
        return jsonify({"authenticated": False}), 401

    company = get_db().execute(
        "SELECT id, name FROM companies WHERE id=?",
        (cid,),
    ).fetchone()

    if not company:
        session.clear()
        return jsonify({"authenticated": False}), 401

    return jsonify({
        "authenticated": True,
        "company_id": company['id'],
        "name": company['name'],
    })


@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"msg": "Logged out"})


@app.route('/api/owner/login', methods=['POST'])
def owner_login():
    data = request.get_json(silent=True) or {}
    email = normalize_email(data.get('email'))
    password = data.get('password', '')

    if not isinstance(password, str) or not is_valid_email(email) or not password:
        return jsonify({"error": "Email and password are required"}), 400

    admin = get_db().execute(
        "SELECT id, email, password FROM platform_admins WHERE email=?",
        (email,),
    ).fetchone()

    if not admin or not check_password_hash(admin['password'], password):
        return jsonify({"error": "Invalid owner credentials"}), 401

    session.clear()
    session['platform_admin_id'] = admin['id']
    return jsonify({"authenticated": True, "email": admin['email']})


@app.route('/api/owner/session')
def owner_session():
    owner_id = session.get('platform_admin_id')
    if not owner_id or session.get('company_id'):
        return jsonify({"authenticated": False}), 401

    admin = get_db().execute(
        "SELECT id, email FROM platform_admins WHERE id=?",
        (owner_id,),
    ).fetchone()

    if not admin:
        session.clear()
        return jsonify({"authenticated": False}), 401

    return jsonify({"authenticated": True, "email": admin['email']})


@app.route('/api/owner/logout', methods=['POST'])
def owner_logout():
    session.clear()
    return jsonify({"message": "Logged out"})


@app.route('/api/password/forgot', methods=['POST'])
def password_recovery_request():
    from utils import get_password_reset_base_url, send_password_reset_email
    data = request.get_json(silent=True) or {}
    email = normalize_email(data.get('email'))

    generic = {"message": "If an account exists for that email, recovery instructions will be sent."}

    if not email or len(email) > 254 or not is_valid_email(email):
        return jsonify(generic), 200

    db = get_db()
    accounts = []

    owner = db.execute(
        "SELECT id, email FROM platform_admins WHERE lower(email)=?",
        (email,),
    ).fetchone()
    if owner:
        accounts.append(("owner", owner["id"], owner["email"]))

    company = db.execute(
        "SELECT id, email FROM companies WHERE lower(email)=?",
        (email,),
    ).fetchone()
    if company:
        accounts.append(("company", company["id"], company["email"]))

    if not accounts:
        return jsonify(generic), 200

    now = datetime.now(timezone.utc)
    try:
        base_url = get_password_reset_base_url()
        for account_type, account_id, recipient in accounts:
            db.execute(
                "UPDATE password_resets SET used=1 WHERE account_type=? AND account_id=? AND used=0",
                (account_type, account_id),
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
                    now.isoformat(),
                ),
            )
            link = f"{base_url}/reset-password?token={token}"
            send_password_reset_email(recipient, link)
        db.commit()
    except Exception:
        db.rollback()
        app.logger.exception("Password recovery email could not be sent")
        return jsonify(generic), 200

    return jsonify(generic), 200


@app.route('/api/password/reset', methods=['POST'])
def password_recovery_reset():
    data = request.get_json(silent=True) or {}
    token = data.get("token", "")
    password = data.get("password", "")

    if not isinstance(token, str) or not token or len(token) > 200:
        return jsonify({"error": "Invalid or expired reset link"}), 400
    if not validate_password(password, minimum=12):
        return jsonify({"error": "Password must be at least 12 characters"}), 400

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    db = get_db()
    now = datetime.now(timezone.utc)

    reset = db.execute(
        "SELECT * FROM password_resets WHERE token_hash=? AND used=0",
        (token_hash,),
    ).fetchone()

    if not reset:
        return jsonify({"error": "Invalid or expired reset link"}), 400

    try:
        expires = datetime.fromisoformat(reset["expires_at"])
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid or expired reset link"}), 400

    if expires <= now:
        db.execute("UPDATE password_resets SET used=1 WHERE id=?", (reset["id"],))
        db.commit()
        return jsonify({"error": "Invalid or expired reset link"}), 400

    password_hash = generate_password_hash(password)

    if reset["account_type"] == "owner":
        cursor = db.execute(
            "UPDATE platform_admins SET password=? WHERE id=?",
            (password_hash, reset["account_id"]),
        )
    elif reset["account_type"] == "company":
        cursor = db.execute(
            "UPDATE companies SET password=? WHERE id=?",
            (password_hash, reset["account_id"]),
        )
    else:
        return jsonify({"error": "Invalid or expired reset link"}), 400

    if cursor.rowcount != 1:
        db.rollback()
        return jsonify({"error": "Invalid or expired reset link"}), 400

    db.execute(
        "UPDATE password_resets SET used=1 WHERE account_type=? AND account_id=?",
        (reset["account_type"], reset["account_id"]),
    )
    db.commit()
    return jsonify({"message": "Password reset successful. Please log in again."}), 200
