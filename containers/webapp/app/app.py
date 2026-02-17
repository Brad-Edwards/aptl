"""TechVault Solutions Customer Portal.

Intentionally vulnerable web application for purple team testing.
Vulnerabilities are documented inline with VULN: markers.
"""

import hashlib
import logging
import os
import subprocess
import uuid

import jwt
import psycopg2
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

app = Flask(__name__)
app.secret_key = "techvault-secret-key-2024"  # VULN: Hardcoded weak secret
JWT_SECRET = "techvault-jwt-weak"  # VULN: Weak JWT secret

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("techvault")

DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "db"),
    "port": os.environ.get("DB_PORT", "5432"),
    "dbname": os.environ.get("DB_NAME", "techvault"),
    "user": os.environ.get("DB_USER", "techvault"),
    "password": os.environ.get("DB_PASSWORD", "techvault_db_pass"),
}


def get_db():
    """Get database connection."""
    return psycopg2.connect(**DB_CONFIG)


# --- Authentication ---


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # VULN: SQL injection in login query
    conn = get_db()
    cur = conn.cursor()
    query = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password_hash = '{hashlib.md5(password.encode()).hexdigest()}'"
    log.info("Login attempt for user: %s from %s", username, request.remote_addr)

    try:
        cur.execute(query)
        user = cur.fetchone()
    except Exception as e:
        # VULN: Verbose error messages expose internals
        log.error("Login query error: %s", e)
        conn.close()
        return jsonify({"error": str(e)}), 500

    conn.close()

    if user:
        session["user_id"] = user[0]
        session["username"] = user[1]
        session["role"] = user[2]
        log.info("Login success: %s (role=%s)", user[1], user[2])
        return redirect(url_for("dashboard"))

    flash("Invalid credentials")
    return render_template("login.html"), 401


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# --- Dashboard ---


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM customers")
    customer_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM files WHERE user_id = %s", (session["user_id"],))
    file_count = cur.fetchone()[0]
    cur.execute("SELECT content, page, created_at FROM comments ORDER BY created_at DESC LIMIT 5")
    comments = cur.fetchall()
    conn.close()

    return render_template(
        "dashboard.html",
        username=session["username"],
        role=session["role"],
        customer_count=customer_count,
        file_count=file_count,
        comments=comments,
    )


# --- Admin Panel ---


@app.route("/admin")
def admin():
    if "user_id" not in session:
        return redirect(url_for("login"))
    # VULN: No role check - any authenticated user can access admin
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, email, role, is_active, last_login FROM users ORDER BY id")
    users = cur.fetchall()
    cur.execute("SELECT * FROM backup_config")  # VULN: Exposes AWS creds
    backups = cur.fetchall()
    conn.close()
    return render_template("admin.html", users=users, backups=backups, role=session.get("role"))


# --- File Operations ---


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template("upload.html", username=session["username"])

    f = request.files.get("file")
    if not f:
        flash("No file selected")
        return redirect(url_for("upload"))

    # VULN: No file type validation, no size limit
    # VULN: Path traversal possible via filename
    filename = f.filename
    upload_dir = "/tmp/uploads"
    os.makedirs(upload_dir, exist_ok=True)
    filepath = os.path.join(upload_dir, filename)
    f.save(filepath)

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO files (user_id, filename, original_name, file_size, mime_type, upload_path) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
        (session["user_id"], filename, f.filename, os.path.getsize(filepath), f.content_type, filepath),
    )
    file_id = cur.fetchone()[0]
    conn.commit()
    conn.close()

    log.info("File upload: %s by user %s", filename, session["username"])
    flash(f"File uploaded: {filename} (ID: {file_id})")
    return redirect(url_for("dashboard"))


# --- API Endpoints ---


@app.route("/api/v1/files/<int:file_id>")
def api_get_file(file_id):
    # VULN: IDOR - no ownership check, any user can access any file
    api_key = request.headers.get("X-API-Key") or request.args.get("api_key")
    if not api_key and "user_id" not in session:
        return jsonify({"error": "Authentication required"}), 401

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, user_id, filename, file_size, mime_type, created_at FROM files WHERE id = %s", (file_id,))
    f = cur.fetchone()
    conn.close()

    if not f:
        return jsonify({"error": "File not found"}), 404

    return jsonify({
        "id": f[0],
        "user_id": f[1],
        "filename": f[2],
        "file_size": f[3],
        "mime_type": f[4],
        "created_at": str(f[5]),
    })


@app.route("/api/v1/users/<int:user_id>")
def api_get_user(user_id):
    # VULN: IDOR - no authorization check
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, username, email, role, department, api_key FROM users WHERE id = %s",
        (user_id,),
    )
    u = cur.fetchone()
    conn.close()

    if not u:
        return jsonify({"error": "User not found"}), 404

    # VULN: Exposes API key in response
    return jsonify({
        "id": u[0],
        "username": u[1],
        "email": u[2],
        "role": u[3],
        "department": u[4],
        "api_key": u[5],
    })


@app.route("/api/v1/customers")
def api_customers():
    api_key = request.headers.get("X-API-Key") or request.args.get("api_key")
    if not api_key and "user_id" not in session:
        return jsonify({"error": "Authentication required"}), 401

    # VULN: No rate limiting
    conn = get_db()
    cur = conn.cursor()

    # VULN: SQL injection via search parameter
    search = request.args.get("search", "")
    if search:
        query = f"SELECT id, company_name, contact_name, contact_email, plan_tier FROM customers WHERE company_name LIKE '%{search}%'"
        cur.execute(query)
    else:
        cur.execute("SELECT id, company_name, contact_name, contact_email, plan_tier FROM customers")

    customers = cur.fetchall()
    conn.close()

    return jsonify([
        {"id": c[0], "company": c[1], "contact": c[2], "email": c[3], "plan": c[4]}
        for c in customers
    ])


@app.route("/api/v1/token", methods=["POST"])
def api_token():
    """Generate JWT token."""
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")

    conn = get_db()
    cur = conn.cursor()
    pw_hash = hashlib.md5(password.encode()).hexdigest()
    cur.execute("SELECT id, username, role FROM users WHERE username = %s AND password_hash = %s", (username, pw_hash))
    user = cur.fetchone()
    conn.close()

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    # VULN: Weak JWT secret, no expiration
    token = jwt.encode({"user_id": user[0], "username": user[1], "role": user[2]}, JWT_SECRET, algorithm="HS256")
    return jsonify({"token": token})


# --- Network Tools (Command Injection) ---


@app.route("/tools/ping", methods=["GET", "POST"])
def ping_tool():
    if "user_id" not in session:
        return redirect(url_for("login"))

    result = None
    if request.method == "POST":
        host = request.form.get("host", "")
        # VULN: Command injection - user input passed directly to shell
        log.info("Ping tool used by %s: target=%s", session["username"], host)
        try:
            output = subprocess.run(
                f"ping -c 3 {host}",
                shell=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            result = output.stdout + output.stderr
        except subprocess.TimeoutExpired:
            result = "Ping timed out"

    return render_template("tools.html", result=result, username=session["username"])


# --- Search (XSS) ---


@app.route("/search")
def search():
    if "user_id" not in session:
        return redirect(url_for("login"))

    q = request.args.get("q", "")
    results = []
    if q:
        conn = get_db()
        cur = conn.cursor()
        # VULN: SQL injection in search
        cur.execute(f"SELECT id, username, email, department FROM users WHERE username LIKE '%{q}%' OR email LIKE '%{q}%' OR department LIKE '%{q}%'")
        results = cur.fetchall()
        conn.close()

    # VULN: Search query reflected in page without sanitization (XSS)
    return render_template("search.html", query=q, results=results, username=session["username"])


# --- Comments (Stored XSS) ---


@app.route("/comment", methods=["POST"])
def add_comment():
    if "user_id" not in session:
        return redirect(url_for("login"))

    content = request.form.get("content", "")
    page = request.form.get("page", "/dashboard")

    # VULN: No input sanitization - stored XSS
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO comments (user_id, content, page) VALUES (%s, %s, %s)",
        (session["user_id"], content, page),
    )
    conn.commit()
    conn.close()

    return redirect(url_for("dashboard"))


# --- Debug / Info Disclosure ---


@app.route("/debug")
def debug():
    # VULN: Debug endpoint exposed in production
    return jsonify({
        "app": "TechVault Portal",
        "version": "2.4.1",
        "python": "3.11",
        "framework": "Flask 3.1.0",
        "database": DB_CONFIG["host"],
        "db_port": DB_CONFIG["port"],
        "db_name": DB_CONFIG["dbname"],
        "db_user": DB_CONFIG["user"],
        "secret_key_length": len(app.secret_key),
        "jwt_algorithm": "HS256",
        "environment": os.environ.get("FLASK_ENV", "unknown"),
    })


@app.route("/robots.txt")
def robots():
    return (
        "User-agent: *\n"
        "Disallow: /admin\n"
        "Disallow: /api/internal\n"
        "Disallow: /debug\n"
        "Disallow: /backup\n"
        "Allow: /\n"
    ), 200, {"Content-Type": "text/plain"}


@app.route("/.env")
def env_file():
    # VULN: Exposed .env file
    return (
        "# TechVault Portal Configuration\n"
        "DB_HOST=db\n"
        "DB_PORT=5432\n"
        "DB_NAME=techvault\n"
        f"DB_USER={DB_CONFIG['user']}\n"
        f"DB_PASSWORD={DB_CONFIG['password']}\n"
        f"SECRET_KEY={app.secret_key}\n"
        f"JWT_SECRET={JWT_SECRET}\n"
    ), 200, {"Content-Type": "text/plain"}


# --- Error Handlers ---


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found", "path": request.path}), 404


@app.errorhandler(500)
def server_error(e):
    # VULN: Verbose error details
    return jsonify({"error": "Internal server error", "details": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
