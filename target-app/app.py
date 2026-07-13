"""Deliberately vulnerable Flask target app with structured logging."""

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template_string, request

app = Flask(__name__)

DATA_DIR = Path(os.environ.get("DATA_DIR", "/app/data"))
DB_PATH = DATA_DIR / "users.db"
ACCESS_LOG = DATA_DIR / "access.log"
BLOCKLIST_PATH = DATA_DIR / "blocklist.json"

LOGIN_PAGE = """
<!DOCTYPE html>
<html><head><title>Target App Login</title></head>
<body>
<h2>Secure Portal Login</h2>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
{% if blocked %}<p style="color:red">Access denied — your IP has been blocked.</p>{% endif %}
{% if success %}<p style="color:green">Welcome, {{ user }}! <a href="/logout">Logout</a></p>{% endif %}
{% if not success and not blocked %}
<form method="POST" action="/login">
  <label>Username: <input name="username" type="text"></label><br>
  <label>Password: <input name="password" type="password"></label><br>
  <button type="submit">Login</button>
</form>
{% endif %}
</body></html>
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()


def _load_blocklist() -> set[str]:
    if not BLOCKLIST_PATH.exists():
        return set()
    with open(BLOCKLIST_PATH, encoding="utf-8") as f:
        data = json.load(f)
    return {entry["ip"] for entry in data.get("blocked_ips", [])}


def _log_access(method: str, path: str, status: int, username: str = "", blocked: bool = False):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": _utc_now(),
        "ip": _client_ip(),
        "method": method,
        "path": path,
        "status": status,
        "username": username,
        "user_agent": request.headers.get("User-Agent", ""),
        "blocked": blocked,
    }
    if blocked:
        entry["block_reason"] = "ip_blocklist"
    with open(ACCESS_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def init_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)"
    )
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        conn.execute(
            "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
            ("admin", "admin123", "admin@local"),
        )
    conn.commit()
    conn.close()


@app.before_request
def check_blocklist():
    if request.path in ("/health",):
        return None
    if _client_ip() in _load_blocklist():
        _log_access(request.method, request.path, 403, blocked=True)
        if request.path.startswith("/api/"):
            return jsonify({"error": "blocked"}), 403
        return render_template_string(LOGIN_PAGE, blocked=True), 403
    return None


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/")
def index():
    return render_template_string(LOGIN_PAGE)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return redirect("/")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn = sqlite3.connect(DB_PATH)
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    try:
        row = conn.execute(query).fetchone()
    except sqlite3.Error:
        row = None
    conn.close()

    if row:
        _log_access("POST", "/login", 200, username=username)
        return render_template_string(LOGIN_PAGE, success=True, user=username)

    _log_access("POST", "/login", 401, username=username)
    return render_template_string(LOGIN_PAGE, error="Invalid credentials"), 401


@app.route("/api/users")
def api_users():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT id, username, email FROM users").fetchall()
    conn.close()
    users = [{"id": r[0], "username": r[1], "email": r[2]} for r in rows]
    _log_access("GET", "/api/users", 200)
    return jsonify({"users": users})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
