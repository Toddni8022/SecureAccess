# SecureAccess

SecureAccess is a Python desktop application for identity and access management workflows. It is built as a security portfolio project that models the work security, IT, and compliance teams do every day: user lifecycle management, role-based access control, access requests, periodic reviews, audit trails, reports, and system provisioning.

The project now includes a security foundation layer with authenticated launch, password hashing, role permission resolution, session tracking, tamper-evident audit logging, JSON backup export, and automated tests.

## Why this project matters

A lot of security portfolio projects are either toy login screens or generic dashboards. SecureAccess is different because it focuses on a real business problem: how teams manage who has access to what, why they have it, who approved it, and whether that access is still appropriate.

## Current capabilities

### Desktop IAM workflow

- Dashboard for user status, MFA coverage, pending requests, and audit warnings
- User CRUD with search, filtering, MFA tracking, department, title, notes, and CSV export
- Role-based access control with risk levels, session duration, MFA requirements, assignments, revocations, and justification tracking
- Access request workflow for grant, revoke, and modify requests
- Periodic access reviews for certification and revocation workflows
- Audit log search, severity filtering, and export
- Password policy management
- Compliance report generation
- Integration panel for provisioning connectors

### Security foundation

- Authenticated launcher in `secure_launcher.py`
- Password hashing with bcrypt when available
- PBKDF2 fallback for environments without bcrypt
- Password policy validation
- Failed login tracking and lockout
- Session creation, validation, and revocation
- Role permission backfill and permission resolution
- Tamper-evident audit log hashing with previous-hash chaining
- Audit chain verification
- JSON backup export with SHA-256 manifest
- Automated unit tests for authentication, password policy, lockout, audit integrity, and backups

### Connectors

SecureAccess includes a connector framework for:

- Active Directory / LDAP
- Microsoft Entra ID
- AWS IAM
- Linux / PAM over SSH
- Okta
- MySQL / PostgreSQL style database access

The current connector implementations are demo/simulation connectors that show realistic provisioning flows and responses. They are designed so live connector modes can be added incrementally without rewriting the app.

## Install and run

```bash
git clone https://github.com/Toddni8022/SecureAccess.git
cd SecureAccess
pip install -r requirements.txt
python secure_launcher.py
```

Default demo login:

```text
Username: admin
Password: SecureAccess!ChangeMe1
```

For a safer first launch, set an environment variable before running:

```bash
set SECUREACCESS_BOOTSTRAP_PASSWORD=YourStrongPasswordHere
python secure_launcher.py
```

On macOS or Linux:

```bash
export SECUREACCESS_BOOTSTRAP_PASSWORD="YourStrongPasswordHere"
python secure_launcher.py
```

You can still run the original unauthenticated UI for development:

```bash
python app.py
```

## Run tests

```bash
python -m unittest discover -s tests
```

## Project structure

```text
SecureAccess/
├── app.py                     # Main CustomTkinter desktop application
├── secure_launcher.py          # Authenticated launcher
├── security_core.py            # Auth, sessions, audit integrity, backups, permissions
├── database.py                 # SQLite persistence layer
├── connectors.py               # Provisioning connector framework
├── build.py                    # PyInstaller build script
├── requirements.txt            # Runtime dependencies
├── tests/
│   └── test_security_core.py   # Security core unit tests
├── docs/
│   ├── architecture.md         # Architecture and trust boundaries
│   └── production-hardening.md # Honest production readiness notes
└── README.md
```

## Data storage

SecureAccess stores its SQLite database in the user's local application data folder:

```text
Windows: %LOCALAPPDATA%\SecureAccess\secureaccess.db
macOS:   ~/.local/share/SecureAccess/secureaccess.db
Linux:   ~/.local/share/SecureAccess/secureaccess.db
```

## What is production-like vs simulated

Production-like pieces:

- Password hashing
- Password policy checks
- Failed login lockout
- Session table
- Permission resolution from role JSON
- Tamper-evident audit hashes
- Audit chain verification
- JSON backup export with SHA-256
- Automated tests

Simulated pieces:

- External identity provider provisioning
- Live AD / Entra / AWS / Okta / Linux changes
- Enterprise-grade immutable storage
- Full SSO / MFA enforcement
- Centralized secret management

That distinction is intentional. This is a portfolio project that shows the architecture and security thinking clearly without pretending to be a drop-in enterprise IAM product.

## Roadmap to true 10/10

1. Wire permission checks directly into every GUI action
2. Add one real live connector mode, preferably AWS IAM with boto3 or Linux SSH with Paramiko
3. Add encrypted local backups
4. Add screenshots and a 90-second demo video
5. Add GitHub release builds for Windows
6. Add role review evidence packets for auditors
7. Add SSO support using OIDC
8. Add a read-only compliance dashboard

## Tech stack

- Python 3.10+
- CustomTkinter
- SQLite
- bcrypt with PBKDF2 fallback
- PyInstaller
- unittest

## Security note

SecureAccess is a security portfolio project and should not be deployed as-is to manage real production identities. The code now includes stronger security foundations, but a real enterprise deployment would still require professional review, hardened secret handling, real SSO/MFA, secure update delivery, centralized logging, and a tested recovery process.

## License

MIT License

Built by Todd Nicholas
