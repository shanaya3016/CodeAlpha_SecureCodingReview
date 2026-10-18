# Secure Coding Review Report

**Project:** CodeAlpha Cyber Security Internship – Task 3
**Auditor:** [Noor ul Aien] · **Date:** 16 October 2026
**Target:** "Student Notes" web app · Python 3 / Flask / SQLite (`insecure_app/app.py`, 109 lines)

---

## 1. Scope and Objective

| Item | Detail |
|---|---|
| Language / framework | Python 3, Flask, SQLite |
| Application | Student Notes: register, login, add/view notes, search, ping tool, file download |
| Goal | Find security vulnerabilities, document them, recommend and apply fixes |
| Standards used | OWASP Top 10 (2021), CWE, OWASP ASVS |

## 2. Methodology

1. **Static analysis:** Bandit 1.9.4 (`bandit -r insecure_app`). Output in `scan_results/bandit_insecure.txt`.
2. **Manual code review:** line-by-line review of every route against an OWASP checklist (injection, authentication, session management, access control, input validation, output encoding, secrets, configuration, logging/errors). Needed because static tools miss logic flaws.
3. **Dynamic proof of exploitation:** `verify_findings.py` runs one working attack per finding using Flask's test client, against both apps.
4. **Remediation and re-test:** fixes applied in `secure_app/app.py`; Bandit and the same attacks re-run.

## 3. Summary of Findings

| ID | Vulnerability | Severity | CWE | OWASP 2021 | Found by |
|---|---|---|---|---|---|
| F1 | SQL Injection (login, search) | **Critical** | CWE-89 | A03 Injection | Bandit B608 + manual |
| F2 | OS Command Injection (`/ping`) | **Critical** | CWE-78 | A03 Injection | Bandit B602 + manual |
| F3 | Insecure Deserialization (pickle session cookie) | **Critical** | CWE-502 | A08 Integrity Failures | Bandit B301 + manual |
| F4 | Server-Side Template Injection (`/search`) | **Critical** | CWE-1336 | A03 Injection | Manual |
| F5 | Cross-Site Scripting (reflected + stored) | High | CWE-79 | A03 Injection | Manual |
| F6 | Path Traversal (`/download`) | High | CWE-22 | A01 Broken Access Control | Manual |
| F7 | IDOR / Broken Access Control (`/note/<id>`) | High | CWE-639 | A01 Broken Access Control | Manual |
| F8 | Hardcoded secret key and admin password | High | CWE-798 | A07 Auth Failures | Bandit B105 |
| F9 | Weak, unsalted password hashing (MD5) | High | CWE-328 | A02 Cryptographic Failures | Bandit B324 |
| F10 | Debug mode on and binding to all interfaces | High | CWE-489 | A05 Misconfiguration | Bandit B201, B104 |
| F11 | Missing CSRF protection | Medium | CWE-352 | A01 Broken Access Control | Manual |
| F12 | No brute-force / rate limiting on login | Medium | CWE-307 | A07 Auth Failures | Manual |
| F13 | Missing security headers, cookie without HttpOnly/Secure | Medium | CWE-1004, CWE-614 | A05 Misconfiguration | Manual |

**Key observation:** Bandit found 6 of the 13 issue types (13 raw alerts: 5 High, 4 Medium, 4 Low). The other 7 (SSTI, XSS, path traversal, IDOR, CSRF, brute force, cookie/header flaws) were found only by manual review. Static analysis alone is not enough.

## 4. Detailed Findings and Remediation

### F1 – SQL Injection · Critical
**Vulnerable code (login):**
```python
q = "SELECT username FROM users WHERE username='%s' AND password='%s'" % (u, md5(p))
```
**Impact:** an attacker can bypass login or read/modify the whole database.
**Proof:** username `admin'--` logs in as admin without a password. The same flaw exists in `/search`.
**Fix:** parameterized queries; never build SQL with string formatting.
```python
get_db().execute("SELECT password FROM users WHERE username=?", (u,))
```

### F2 – OS Command Injection · Critical
**Vulnerable code:** `subprocess.run("ping -c 1 " + host, shell=True, ...)`
**Impact:** remote code execution on the server.
**Proof:** `host=127.0.0.1 & echo 1338` returned `1338`, confirming the injected command ran.
**Fix:** validate input with a strict allow-list regex, pass arguments as a list, `shell=False`, add a timeout, require authentication.

### F3 – Insecure Deserialization · Critical
**Vulnerable code:** the session cookie is `base64(pickle.dumps(...))` and is loaded with `pickle.loads` on every request.
**Impact:** pickle can execute arbitrary code. A crafted cookie gave remote code execution without logging in.
**Proof:** a cookie with a malicious `__reduce__` created a file on the server.
**Fix:** use Flask's signed `session` (JSON, HMAC-signed with `SECRET_KEY`). Never unpickle data a user controls.

### F4 – Server-Side Template Injection · Critical
**Vulnerable code:** `render_template_string("<h1>Results for " + q + "</h1>")`
**Impact:** user input becomes template code; can lead to data leaks and code execution.
**Proof:** `q={{7*7}}` rendered `49`.
**Fix:** keep the template constant and pass user data only as variables: `render_template_string("...{{ q }}...", q=q)`.

### F5 – Cross-Site Scripting · High
**Vulnerable code:** user input (login error, search term, note body) is concatenated into HTML.
**Impact:** script runs in the victim's browser: session theft, defacement, phishing.
**Proof:** `<script>alert(1)</script>` came back unescaped.
**Fix:** Jinja auto-escaping, generic error messages that do not reflect input, and a Content-Security-Policy header (see F13).

### F6 – Path Traversal · High
**Vulnerable code:** `send_file(os.path.join(BASE, "uploads", request.args["file"]))`
**Impact:** read any file, including the application's source code and secrets.
**Proof:** `file=../app.py` returned the source code.
**Fix:** `send_from_directory(UPLOADS, filename)`, which rejects `..`; also require login.

### F7 – IDOR / Broken Access Control · High
**Vulnerable code:** `SELECT body FROM notes WHERE id=?` (no owner check).
**Impact:** any user can read any other user's notes by guessing IDs.
**Proof:** a new user `bob` read the admin's note 1 ("backup key").
**Fix:** enforce ownership on the server: `WHERE id=? AND owner=?`, and return 404 otherwise.

### F8 – Hardcoded Secrets · High
**Vulnerable code:** `app.secret_key = "supersecret123"`, `ADMIN_PASSWORD = "admin123"`.
**Impact:** anyone with the source (e.g. public GitHub) can forge sessions and log in as admin.
**Fix:** load secrets from environment variables; generate a random key if none is set; never commit `.env` files.

### F9 – Weak Password Hashing · High
**Vulnerable code:** `hashlib.md5(password).hexdigest()` (fast, unsalted, broken).
**Impact:** after a database leak, passwords are cracked in seconds with rainbow tables or GPUs.
**Fix:** a slow, salted password hash: `generate_password_hash(p)` / `check_password_hash(stored, p)`. Also enforce a minimum password length (8+).

### F10 – Debug Mode and Bind to All Interfaces · High
**Vulnerable code:** `app.run(host="0.0.0.0", debug=True)`
**Impact:** the Werkzeug debugger allows code execution, and stack traces leak internals.
**Fix:** `debug=False`, bind to `127.0.0.1` behind a reverse proxy, and return a generic 500 error page.

### F11 – Missing CSRF Protection · Medium
**Impact:** a malicious site can make a logged-in user's browser post notes or change data.
**Proof:** `POST /notes` succeeded with no token.
**Fix:** per-session CSRF token checked on every POST (`hmac.compare_digest`), plus `SameSite=Lax` cookies.

### F12 – No Brute-Force Protection · Medium
**Impact:** unlimited password guessing.
**Proof:** 8 wrong logins in a row were never blocked.
**Fix:** limit to 5 failed attempts per 5 minutes per IP (HTTP 429); use generic "invalid credentials" messages.

### F13 – Missing Security Headers and Cookie Flags · Medium
**Impact:** weaker defence against XSS, clickjacking and MIME sniffing; cookies readable by JavaScript.
**Fix:** `HttpOnly`, `Secure`, `SameSite=Lax` on cookies; headers `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`.

## 5. Secure Coding Best Practices

1. **Never trust input.** Validate with allow-lists (type, length, format) on the server side.
2. **Separate code from data.** Parameterized queries, argument lists instead of shell strings, template variables instead of string-built templates.
3. **Encode output** for the context (HTML, URL, JS). Keep auto-escaping on.
4. **Never deserialize untrusted data** with pickle. Use JSON plus a signature.
5. **Hash passwords** with scrypt, bcrypt or Argon2; add MFA and rate limiting.
6. **Keep secrets out of code.** Environment variables or a vault; rotate them if leaked.
7. **Enforce authorization on every request** (deny by default, check ownership server-side).
8. **Harden configuration:** no debug in production, minimal privileges, HTTPS everywhere, security headers.
9. **Fail safely:** generic error messages for users, detailed logs for admins only.
10. **Automate:** run SAST (Bandit/Semgrep), dependency scanning (`pip-audit`) and tests in CI on every commit, and do peer code reviews.

## 6. Verification (After Fixes)

| Check | Insecure app | Secure app |
|---|---|---|
| Bandit issues | 13 (5 High, 4 Medium, 4 Low) | **1** (Low, accepted — see below) |
| Working exploits (13 attacks) | **13 / 13** | **0 / 13** |

Re-run anytime: `python verify_findings.py`

**Accepted risk:** the single remaining Low finding is an informational Bandit warning about importing `subprocess`. The only use of `subprocess` in `secure_app` validates the host against a strict allow-list regex, passes arguments as a list, and never uses `shell=True`, so there is no injection risk. This is a standard, documented accepted risk rather than an unfixed vulnerability.

## 7. Limitations

- The review covers one small application; production systems also need dependency audits, infrastructure review and penetration testing.
- The in-memory rate limiter in the secure version is per-process. Use Redis/Flask-Limiter for multi-server deployments.
- The `/ping` tool is kept only to demonstrate the fix; real deployments should remove such features.

## 8. References

- OWASP Top 10 (2021): https://owasp.org/Top10/
- OWASP ASVS and Cheat Sheet Series: https://cheatsheetseries.owasp.org/
- CWE Top 25: https://cwe.mitre.org/
- Bandit documentation: https://bandit.readthedocs.io/