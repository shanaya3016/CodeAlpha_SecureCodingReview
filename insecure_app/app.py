"""INTENTIONALLY VULNERABLE demo app ("Student Notes").
Created only for the CodeAlpha Secure Coding Review task. NEVER deploy this."""
import base64
import hashlib
import os
import pickle
import sqlite3
import subprocess

from flask import Flask, make_response, render_template_string, request, send_file

BASE = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.secret_key = "supersecret123"          # [F8] hardcoded secret
ADMIN_PASSWORD = "admin123"                # [F8] hardcoded credential
DB = os.environ.get("NOTES_DB", os.path.join(BASE, "notes_vuln.db"))


def get_db():
    return sqlite3.connect(DB)


def init_db():
    db = get_db()
    db.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    db.execute("CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, owner TEXT, body TEXT)")
    if not db.execute("SELECT 1 FROM users").fetchone():
        pw = hashlib.md5(ADMIN_PASSWORD.encode()).hexdigest()
        db.execute("INSERT INTO users(username,password) VALUES('admin', ?)", (pw,))
        db.execute("INSERT INTO notes(owner,body) VALUES('admin','Admin secret: backup key is 4f9a-77c1')")
    db.commit()


def current_user():
    raw = request.cookies.get("session")
    if not raw:
        return None
    return pickle.loads(base64.b64decode(raw)).get("user")      # [F3] insecure deserialization


@app.route("/register", methods=["POST"])
def register():
    db = get_db()
    pw = hashlib.md5(request.form["password"].encode()).hexdigest()   # [F9] weak hash, no salt
    db.execute("INSERT INTO users(username,password) VALUES(?,?)", (request.form["username"], pw))
    db.commit()
    return "registered"


@app.route("/login", methods=["POST"])                           # [F12] no rate limiting
def login():
    u, p = request.form["username"], request.form["password"]
    q = "SELECT username FROM users WHERE username='%s' AND password='%s'" % (
        u, hashlib.md5(p.encode()).hexdigest())                   # [F1] SQL injection
    row = get_db().execute(q).fetchone()
    if not row:
        return "Login failed for " + u, 401                       # [F5] reflected XSS
    resp = make_response("Welcome " + row[0])
    resp.set_cookie("session", base64.b64encode(pickle.dumps({"user": row[0]})).decode())  # [F13] no HttpOnly/Secure
    return resp


@app.route("/notes", methods=["POST"])                           # [F11] no CSRF protection
def add_note():
    user = current_user()
    if not user:
        return "login required", 401
    db = get_db()
    db.execute("INSERT INTO notes(owner,body) VALUES(?,?)", (user, request.form["body"]))
    db.commit()
    return "saved"


@app.route("/note/<int:note_id>")
def note(note_id):
    if not current_user():
        return "login required", 401
    row = get_db().execute("SELECT body FROM notes WHERE id=?", (note_id,)).fetchone()  # [F7] IDOR
    return row[0] if row else ("not found", 404)


@app.route("/search")
def search():
    user = current_user()
    if not user:
        return "login required", 401
    q = request.args.get("q", "")
    sql = "SELECT body FROM notes WHERE owner='%s' AND body LIKE '%%%s%%'" % (user, q)  # [F1] SQL injection
    rows = get_db().execute(sql).fetchall()
    html = "<h1>Results for " + q + "</h1>" + "".join("<p>%s</p>" % r[0] for r in rows)
    return render_template_string(html)                          # [F4] SSTI, [F5] XSS


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    out = subprocess.run("ping -c 1 " + host, shell=True, capture_output=True, text=True)  # [F2] command injection
    return "<pre>" + out.stdout + out.stderr + "</pre>"


@app.route("/download")
def download():
    return send_file(os.path.join(BASE, "uploads", request.args["file"]))  # [F6] path traversal


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)               # [F10] debug + bind all interfaces