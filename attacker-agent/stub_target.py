"""Local stub vulnerable Flask app for Day 1 testing before target-app is available."""

import sqlite3
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template_string, request

app = Flask(__name__)
DB_PATH = Path("data/stub_users.db")

LOGIN_PAGE = """
<!DOCTYPE html>
<html><head><title>Stub Login</title></head>
<body>
<h2>Stub Target Login</h2>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
{% if success %}<p style="color:green">Welcome, {{ user }}! <a href="/logout">Logout</a></p>{% endif %}
{% if not success %}
<form method="POST" action="/login">
  <label>Username: <input name="username" type="text"></label><br>
  <label>Password: <input name="password" type="password"></label><br>
  <button type="submit">Login</button>
</form>
{% endif %}
</body></html>
"""


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)"
    )
    conn.execute("DELETE FROM users")
    conn.execute(
        "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
        ("admin", "admin123", "admin@local"),
    )
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return render_template_string(LOGIN_PAGE)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return redirect("/")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # Intentionally vulnerable — string concatenation SQLi
    conn = sqlite3.connect(DB_PATH)
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    try:
        row = conn.execute(query).fetchone()
    except sqlite3.Error:
        row = None
    conn.close()

    if row:
        return render_template_string(LOGIN_PAGE, success=True, user=username)
    return render_template_string(LOGIN_PAGE, error="Invalid credentials")


@app.route("/api/users")
def api_users():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT id, username, email FROM users").fetchall()
    conn.close()
    users = [{"id": r[0], "username": r[1], "email": r[2]} for r in rows]
    return jsonify({"users": users})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
