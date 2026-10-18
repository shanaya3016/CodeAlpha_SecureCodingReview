# CodeAlpha_SecureCodingReview

**Task 3 – Secure Coding Review** | CodeAlpha Cyber Security Internship

A complete security audit of a small Python/Flask web application ("Student Notes"): vulnerabilities are found with **static analysis (Bandit)** and **manual code review**, proven with working exploits, fixed, and re-verified.

## What is inside

| Path | Purpose |
|---|---|
| `REPORT.md` | Full audit report: methodology, 13 findings, remediation, best practices |
| `insecure_app/app.py` | Application under audit (intentionally vulnerable) |
| `secure_app/app.py` | Remediated version of the same application |
| `verify_findings.py` | Runs the same 13 attacks against both apps |
| `scan_results/` | Bandit reports (before/after) and verification results |

## Task requirements checklist

| Requirement | Where |
|---|---|
| Select a language and application to audit | Python + Flask, `insecure_app/` (REPORT §1) |
| Perform a code review to identify vulnerabilities | REPORT §3-4 (13 findings, CWE + OWASP mapped) |
| Use static analyzers / manual inspection | Bandit + manual review + dynamic proof (REPORT §2, `scan_results/`) |
| Provide recommendations and best practices | REPORT §5 |
| Document findings and remediation steps | REPORT §4 (each finding) + `secure_app/app.py` |

## Run it

```bash
pip install -r requirements.txt
bandit -r insecure_app          # static analysis: 13 issues (5 High)
bandit -r secure_app            # after fixes: 1 Low (accepted risk, see REPORT §6)
python verify_findings.py       # 13/13 exploited -> 0/13 after fixes
```

> ⚠️ `insecure_app` is intentionally insecure. Run it only on your own machine for learning, never on a public server.

## Result

| | Insecure app | Secure app |
|---|---|---|
| Bandit issues | 13 (5 High, 4 Medium, 4 Low) | 1 (Low, accepted risk) |
| Working exploits | 13 / 13 | 0 / 13 |

Author: [Noor ul Aien]