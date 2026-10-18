"""SECURE version of the Student Notes app - every finding from REPORT.md is remediated."""
import hmac
import os
import re
import secrets
import sqlite3
import subprocess
import time

from flask import (Flask, abort, jsonify, render_template_string, request,
                   send_from_directory, session)
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.abspath(os.path.dirname(__file__))
UPLOADS = os.path.join(BASE, "uploads")
DB = os.environ.get("NOTES_DB", os.path.join(BASE, "notes_secure.db"))
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
HOST_RE = re.compile(r"^(?!-)[A-Za-z0-9.-]{1,253}$")
MAX_ATTEMPTS, WINDOW = 5, 300            # 5 failed logins per 5 minutes per IP
attempts = {}

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),   # F8: from environment
    SESSION_COOKIE_HTTPONLY=True,                                        # F13
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
    MAX_CONTENT_LENGTH=16 * 1024,
)
DUMMY_HASH = generate_password_hash(secrets.token_hex(8))


def get_db():
    return sqlite3.connect(DB)


def init_db():
    db = get_db()
    db.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)")
    db.execute("CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, owner TEXT, body TEXT)")
    admin_pw = os.environ.get("ADMIN_PASSWORD")                          # F8: no hardcoded password
    if admin_pw and not db.execute("SELECT 1 FROM users").fetchone():
        db.execute("INSERT INTO users(username,password) VALUES('admin', ?)", (generate_password_hash(admin_pw),))
        db.execute("INSERT INTO notes(owner,body) VALUES('admin','Admin secret: backup key is 4f9a-77c1')")
    db.commit()


def require_user():
    user = session.get("user")                                           # F3: signed session, no pickle
    if not user:
        abort(401)
    return user


@app.before_request
def csrf_protect():                                                      # F11
    if request.method == "POST":
        sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
        expected = session.get("csrf", "")
        if not expected or not hmac.compare_digest(sent, expected):
            abort(403)


@app.after_request
def security_headers(resp):                                              # F13
    resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.errorhandler(500)
def server_error(_):                                                     # F10: no stack traces
    return jsonify(error="internal server error"), 500


@app.route("/csrf-token")
def csrf_token():
    session["csrf"] = session.get("csrf") or secrets.token_hex(16)
    return jsonify(csrf_token=session["csrf"])


@app.route("/register", methods=["POST"])
def register():
    u, p = request.form.get("username", ""), request.form.get("password", "")
    if not USERNAME_RE.match(u) or len(p) < 8:
        return jsonify(error="invalid username or password too short"), 400
    try:
        db = get_db()
        db.execute("INSERT INTO users(username,password) VALUES(?,?)", (u, generate_password_hash(p)))  # F9
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="username taken"), 409
    return jsonify(message="registered"), 201


@app.route("/login", methods=["POST"])
def login():
    ip, now = request.remote_addr or "?", time.time()
    recent = [t for t in attempts.get(ip, []) if now - t < WINDOW]
    if len(recent) >= MAX_ATTEMPTS:                                      # F12
        return jsonify(error="too many attempts, try later"), 429
    u, p = request.form.get("username", ""), request.form.get("password", "")
    row = get_db().execute("SELECT password FROM users WHERE username=?", (u,)).fetchone()  # F1
    ok = check_password_hash(row[0] if row else DUMMY_HASH, p) and row is not None
    if not ok:
        attempts[ip] = recent + [now]
        return jsonify(error="invalid credentials"), 401                 # generic, no reflection (F5)
    attempts.pop(ip, None)
    session.clear()
    session["user"], session["csrf"] = u, secrets.token_hex(16)
    return jsonify(message="logged in", csrf_token=session["csrf"])


@app.route("/notes", methods=["POST"])
def add_note():
    user = require_user()
    body = request.form.get("body", "")[:2000]
    db = get_db()
    db.execute("INSERT INTO notes(owner,body) VALUES(?,?)", (user, body))
    db.commit()
    return jsonify(message="saved"), 201


@app.route("/note/<int:note_id>")
def note(note_id):
    user = require_user()
    row = get_db().execute("SELECT body FROM notes WHERE id=? AND owner=?", (note_id, user)).fetchone()  # F7
    if not row:
        abort(404)
    return jsonify(body=row[0])


@app.route("/search")
def search():
    user = require_user()
    q = request.args.get("q", "")
    rows = get_db().execute(
        "SELECT body FROM notes WHERE owner=? AND body LIKE ?", (user, "%" + q + "%")).fetchall()  # F1
    return render_template_string(                                       # F4 + F5: data passed as context, auto-escaped
        "<h1>Results for {{ q }}</h1>{% for r in rows %}<p>{{ r[0] }}</p>{% endfor %}", q=q, rows=rows)


@app.route("/ping")
def ping():
    require_user()
    host = request.args.get("host", "")
    if not HOST_RE.match(host):                                          # F2: strict allow-list validation
        abort(400)
    try:
        # list arguments + validated host + no shell (justification for the nosec below)
        out = subprocess.run(["ping", "-c", "1", "-W", "2", host], capture_output=True,  # nosec B603 B607
                             text=True, timeout=5, shell=False)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return jsonify(error="ping unavailable"), 503
    return jsonify(output=out.stdout)


@app.route("/download")
def download():
    require_user()
    return send_from_directory(UPLOADS, request.args.get("file", ""))    # F6: safe_join blocks traversal


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)                    # F10