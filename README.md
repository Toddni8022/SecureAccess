# SecureAccess — User Access Management Platform

![CI](https://github.com/Toddni8022/SecureAccess/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%20|%203.11%20|%203.12-blue)
![Coverage](https://img.shields.io/badge/coverage-97%25-brightgreen)
![License](https://img.shields.io/badge/license-MIT-orange)

A desktop IAM (Identity & Access Management) tool for security teams who need user provisioning, role-based access control, periodic access reviews, and compliance reporting — without a cloud dependency or per-seat SaaS cost.

Designed for air-gapped environments, compliance-focused SMBs, and teams that need SOX/HIPAA/PCI-DSS audit artefacts on demand.

---

## The problem it solves

Cloud IAM tools (Okta, JumpCloud) assume you want a hosted directory. Many regulated environments can't or won't send identity data to a third party. Existing open-source alternatives are either heavyweight Java applications or raw LDAP tooling with no audit workflow.

SecureAccess gives a security team:
- A full user lifecycle (create → review → revoke) with justification tracking at every step
- An immutable audit log exportable for compliance submissions
- Periodic access certification campaigns (the quarterly "should this person still have this role?" review that auditors require)
- All data stored locally in an encrypted-at-rest-capable SQLite database

---

## Engineering highlights

| Area | Decision | Why |
|---|---|---|
| Password storage | bcrypt with per-hash salts | Resistant to rainbow tables; cost factor tunable as hardware improves |
| Dynamic SQL | Column-name whitelist + parameterised values | Prevents SQL injection through `**kwargs`-style ORM methods |
| Testing | 46 pytest unit tests, 97% database layer coverage | In-memory SQLite fixture — no disk I/O, no teardown needed |
| CI | GitHub Actions matrix: Python 3.10 / 3.11 / 3.12 | Catches f-string syntax regressions and dependency drift early |
| Packaging | PyInstaller single-file binary | Ships to machines with no Python installed |
| GUI | CustomTkinter (Tkinter wrapper) | Zero native dependencies; identical look on Windows, macOS, Linux |

---

## Features

**Dashboard** — live security posture: user status breakdown, MFA coverage rate, pending access requests, role-risk distribution

**User Management** — full CRUD with status tracking (`active / inactive / locked / pending_review`), MFA method per user, CSV export

**Role-Based Access Control** — roles carry risk levels (`low / medium / high / critical`), max session duration, and MFA requirements; all assignments record who granted access and why

**Access Request Workflow** — grant/revoke requests require a business justification; reviewer decisions are timestamped and stored

**Periodic Access Reviews** — create a certification campaign, step through every user–role pair, certify or revoke; completion tracked against a due date

**Audit Log** — append-only log with severity levels (`info / warning / critical`), full-text search, CSV export

**Compliance Reports** — User Access, MFA Compliance, Privileged Access, Inactive Users, Role Summary, Audit Summary; all exportable to CSV

**System Integrations** — connector framework for provisioning against Active Directory, Azure AD, AWS IAM, Okta, Linux/SSH, and generic databases

---

## Quick start

```bash
git clone https://github.com/Toddni8022/SecureAccess.git
cd SecureAccess
pip install -r requirements.txt
python app.py
```

The application seeds a demo dataset on first run (10 users, 7 roles, sample audit entries) so every screen is immediately populated.

**Build a standalone executable:**

```bash
pip install -r requirements-dev.txt
python build.py          # produces dist/SecureAccess (or .exe on Windows)
```

---

## Running the tests

```bash
pip install -r requirements-dev.txt
pytest tests/ -v --cov=database --cov-report=term-missing
```

All tests run against an in-memory SQLite database — no setup, no cleanup.

---

## Project layout

```
SecureAccess/
├── app.py                  # GUI (CustomTkinter) + application logic
├── database.py             # Database layer — all SQL lives here
├── connectors.py           # System integration connector framework
├── build.py                # PyInstaller build script
├── requirements.txt        # Runtime dependencies
├── requirements-dev.txt    # Build + test dependencies
├── tests/
│   └── test_database.py    # 46 unit tests
└── .github/workflows/
    └── ci.yml              # CI: test matrix + build artifact
```

**Data location:**
- Windows: `%LOCALAPPDATA%\SecureAccess\secureaccess.db`
- macOS / Linux: `~/.local/share/SecureAccess/secureaccess.db`

---

## Scope

SecureAccess is a **single-admin desktop tool**. It manages the records of who has access to what — it does not replace an IdP, enforce sessions at runtime, or synchronise in real time with external directories. The connector framework is architected for extension to real provisioning calls.

---

## License

MIT — see [LICENSE](LICENSE).

---

*Portfolio project — Todd Nicholas*
