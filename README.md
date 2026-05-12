# 🛡️ SecureAccess — SecAI+ Access Governance Workbench

SecureAccess is a desktop IAM/RBAC project upgraded for **SecAI+ relevance**: deterministic credential security, AI-assisted audit analysis, anomaly detection, and explainable risk scoring aligned to attacker behavior frameworks.

## What’s New (SecAI+)
- Real password hashing and validation using PBKDF2-HMAC-SHA256 with salted hashes and constant-time compare.
- Credential lockout enforcement based on configurable policy thresholds.
- AI-assisted audit log triage (`analyze_audit_log_ai`) with MITRE ATT&CK/CWE mappings.
- Access anomaly detection (`detect_access_anomalies`) for failed login bursts.
- Explainable risk scoring (`explainable_risk_score`) for users/roles/requests with transparent scoring factors.
- Security tests for authentication, password policy/history, analytics, and risk logic.

## Existing Features (Preserved)
- Dashboard, users, roles, access requests, access reviews, audit log, password policy, integrations, and reports.

## Demo / Run Instructions
```bash
pip install -r requirements.txt
python app.py
```

### Security Logic Demo (CLI)
```bash
python -m unittest tests/test_security_logic.py
```

## Screenshots
1. Run `python app.py` and open **Dashboard** for posture metrics.
2. Open **Audit Log** and trigger failed login test events via Python shell using `Database.log_audit(...)`.
3. Export CSV to inspect events used by analytics.

## Threat Model (Condensed)
### Assets
- User credentials, role assignments, access request decisions, audit evidence.

### Adversaries
- External credential attackers (brute force/password spraying).
- Insider misuse (unauthorized role grants).
- Compromised internal account with weak MFA hygiene.

### Primary Abuse Paths
- Credential guessing against privileged users.
- Silent privilege escalation through role grants.
- Repeated failed logins preceding account takeover.

### Defensive Controls in this Project
- Salted password hashing and password-history reuse prevention.
- Policy-driven lockout and failed login counters.
- Audit triage heuristics mapped to MITRE ATT&CK (T1110, T1078) and CWE-307.
- Explainable risk factors supporting analyst review.

## Security Limitations
- AI analysis is heuristic and local; this is not an ML SOC pipeline.
- No external threat intel enrichment feed yet.
- No signed audit records / tamper-evident log chain.
- Desktop app has no built-in centralized identity provider integration for user login UI yet.

## MITRE ATT&CK / CWE Mapping Used
- **T1110 (Brute Force)**: failed login burst and authentication failures.
- **T1078 (Valid Accounts)**: role and access lifecycle events.
- **CWE-307**: excessive authentication attempts.

## Tests
- `tests/test_security_logic.py` validates new security behavior.

## License
MIT
