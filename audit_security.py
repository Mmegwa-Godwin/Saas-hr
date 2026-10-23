import ast
import re
from pathlib import Path

source_path = Path("app.py")

if not source_path.exists():
    print("ERROR: app.py not found in", Path.cwd())
    raise SystemExit(1)

source = source_path.read_text()
lines = source.splitlines()

print("=" * 65)
print("SAAS HR SECURITY AUDIT")
print("Target:", source_path.resolve())
print("Mode: READ ONLY")
print("=" * 65)

try:
    tree = ast.parse(source)
    print("\n[1] PYTHON SYNTAX")
    print("PASS: app.py parses successfully")
except SyntaxError as exc:
    print("\nFAIL: Syntax error:", exc)
    raise SystemExit(1)

# ----------------------------------------------------------
# Route inventory
# ----------------------------------------------------------
print("\n[2] ROUTE INVENTORY")

routes = []
for node in ast.walk(tree):
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        continue

    for decorator in node.decorator_list:
        text = ast.get_source_segment(source, decorator) or ""

        if not re.search(r"\bapp\.route\s*\(", text):
            continue

        route_match = re.search(r"""['"]([^'"]+)['"]""", text)
        route = route_match.group(1) if route_match else "<dynamic route>"

        methods_match = re.search(r"""methods\s*=\s*\[([^\]]*)\]""", text)
        if methods_match:
            methods = ",".join(
                re.findall(r"""['"]([A-Z]+)['"]""", methods_match.group(1))
            )
        else:
            methods = "GET (default; verify manually)"

        routes.append((node.lineno, route, methods, node.name, node))

for lineno, route, methods, name, node in sorted(routes):
    mutating = any(
        method in methods.split(",")
        for method in ("POST", "PUT", "PATCH", "DELETE")
    )

    label = "REVIEW MUTATION" if mutating else "READ/OTHER"
    print(
        f"L{lineno}: [{label}] {methods:20} "
        f"{route:48} -> {name}"
    )

print("\nTotal Flask routes found:", len(routes))

# ----------------------------------------------------------
# CSRF and request guards
# ----------------------------------------------------------
print("\n[3] SECURITY GUARDS AND CSRF")

guard_names = ("security_guard", "csrf", "csrf_protect")
for name in guard_names:
    matches = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and name.lower() in node.name.lower()
    ]

    if not matches:
        print(f"INFO: No function named like {name!r} found")
        continue

    for node in matches:
        start = node.lineno
        end = getattr(node, "end_lineno", start)
        print(f"\n--- {node.name} (lines {start}-{end}) ---")
        for number in range(start, min(end, start + 100) + 1):
            print(f"{number:4}: {lines[number - 1]}")

print("\nCSRF/config references:")
patterns = re.compile(
    r"csrf|X-CSRF|before_request|compare_digest|"
    r"request\.method|session\.clear|session\.pop",
    re.IGNORECASE
)
for number, line in enumerate(lines, 1):
    if patterns.search(line):
        print(f"{number:4}: {line.strip()[:180]}")

# ----------------------------------------------------------
# Authentication, tenant isolation, production config
# ----------------------------------------------------------
print("\n[4] AUTHENTICATION / TENANT / PRODUCTION REFERENCES")

patterns = re.compile(
    r"company_id|employee_id|login_required|"
    r"SECRET_KEY|secret_key|SESSION_COOKIE|"
    r"PERMANENT_SESSION|SESSION_PERMANENT|"
    r"HttpOnly|SameSite|Secure|debug\s*=|"
    r"app\.run|send_file|send_from_directory|"
    r"except\s*:|except Exception|traceback|"
    r"sqlite3\.connect|password|hash|CORS|"
    r"MAX_CONTENT_LENGTH|TRUSTED_HOSTS",
    re.IGNORECASE
)

for number, line in enumerate(lines, 1):
    if patterns.search(line):
        print(f"{number:4}: {line.strip()[:200]}")

# ----------------------------------------------------------
# Decorators and route function excerpts
# ----------------------------------------------------------
print("\n[5] MUTATING ROUTE EXCERPTS")

for lineno, route, methods, name, node in sorted(routes):
    if not any(
        method in methods.split(",")
        for method in ("POST", "PUT", "PATCH", "DELETE")
    ):
        continue

    start = max(1, node.lineno - 3)
    end = min(len(lines), getattr(node, "end_lineno", node.lineno) + 1)

    print(f"\n--- {route} [{methods}] -> {name}, lines {start}-{end} ---")
    for number in range(start, min(end, start + 45) + 1):
        print(f"{number:4}: {lines[number - 1]}")

print("\n" + "=" * 65)
print("AUDIT COLLECTION COMPLETE")
print("This report is a review aid, not a security certification.")
print("No application or database files were modified by this script.")
print("=" * 65)
