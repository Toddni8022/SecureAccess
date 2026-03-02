# Architecture — SecureAccess

## System Overview

SecureAccess is a professional desktop GUI application built for security teams to manage user identities, enforce role-based access control (RBAC), conduct periodic access reviews, and maintain a comprehensive audit trail. It runs entirely on-premise with no external cloud dependencies, storing all data in a local SQLite database.

The application is built with Python and [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) for the GUI, making it cross-platform (Windows, macOS, Linux). It integrates with external identity providers (Active Directory, Azure AD, Okta, etc.) through a modular connector architecture.

---

## Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                      SecureAccess GUI Layer                      │
│               (CustomTkinter — Dark Theme, Python)               │
│                                                                  │
│  ┌───────────┐ ┌───────┐ ┌───────┐ ┌──────────┐ ┌──────────┐   │
│  │ Dashboard │ │ Users │ │ Roles │ │ Requests │ │ Reviews  │   │
│  └───────────┘ └───────┘ └───────┘ └──────────┘ └──────────┘   │
│  ┌──────────┐ ┌──────────────────┐ ┌──────────────────────────┐ │
│  │  Audit   │ │ Password Policy  │ │    Integrations/Reports   │ │
│  └──────────┘ └──────────────────┘ └──────────────────────────┘ │
└────────────────────┬──────────────────────┬─────────────────────┘
                     │                      │
       ┌─────────────▼──────────┐  ┌────────▼──────────────────────┐
       │     Database Layer      │  │       Connector Layer          │
       │  (SQLite via sqlite3)   │  │   (External Identity Systems)  │
       │                         │  │                                │
       │  Tables:                │  │  • ActiveDirectoryConnector    │
       │  • users                │  │  • AzureADConnector            │
       │  • roles                │  │  • AWSIAMConnector             │
       │  • user_roles           │  │  • OktaConnector               │
       │  • access_requests      │  │  • LinuxConnector              │
       │  • audit_log            │  │  • DatabaseConnector           │
       │  • password_policy      │  │  • (extensible via BaseConn.)  │
       │  • access_reviews       │  └────────────────────────────────┘
       │  • review_decisions     │
       └─────────────────────────┘
```

---

## Data Flow

### User Provisioning Flow

```
Security Analyst
      │
      ▼
[Access Request Created] ──► [Audit Log Entry]
      │
      ▼
[Manager/Admin Approves]
      │
      ▼
[ConnectorManager.provision_user()]
      │
      ├──► ActiveDirectoryConnector.create_user()
      ├──► AzureADConnector.create_user()
      └──► [Audit Log Entry — provisioning result]
```

### Access Review Flow

```
Scheduled Review Campaign
      │
      ▼
[Access Review Created] ──► [Users notified]
      │
      ▼
[Reviewer certifies each user-role pair]
      │
      ├── Certified ──► Access retained, audit logged
      └── Revoked   ──► ConnectorManager.disable_user()
                         Audit logged
```

---

## Directory Structure

```
SecureAccess/
├── app.py                          # Main application entry point (GUI)
├── database.py                     # SQLite database layer
├── connectors.py                   # External system connectors
├── build.py                        # PyInstaller build configuration
├── requirements.txt                # Python runtime dependencies
│
├── src/secure_access/              # Importable Python package
│   ├── __init__.py                 # Package metadata
│   ├── app.py                      # Entry point wrapper
│   ├── auth/                       # Authentication utilities
│   │   ├── __init__.py
│   │   └── password.py             # Hashing, verification, policy
│   ├── connectors/                 # Connector package wrappers
│   │   ├── __init__.py
│   │   ├── base.py                 # BaseConnector, ProvisioningResult
│   │   └── manager.py              # ConnectorManager, CONNECTORS registry
│   ├── database/                   # Database package wrappers
│   │   ├── __init__.py
│   │   └── models.py               # Database, get_db_path re-exports
│   ├── models/                     # Data models (enums)
│   │   ├── __init__.py
│   │   ├── user.py                 # UserStatus, MFAMethod
│   │   └── role.py                 # RiskLevel
│   ├── routes/                     # GUI view stubs
│   │   └── __init__.py
│   └── utils/                      # Shared utilities
│       ├── __init__.py
│       ├── csv_export.py           # CSV export helper
│       └── date_utils.py           # Date formatting helpers
│
├── tests/                          # Pytest test suite
│   ├── conftest.py                 # Shared fixtures
│   ├── test_auth.py
│   ├── test_connectors.py
│   └── test_database.py
│
├── docs/                           # Documentation
│   ├── architecture.md             # This file
│   ├── api.md                      # API reference
│   ├── connectors.md               # Connector guide
│   └── deployment.md               # Deployment guide
│
├── .github/workflows/              # CI/CD pipelines
│   ├── ci.yml                      # Test + lint on every push
│   └── release.yml                 # Build executables on tag
│
├── Dockerfile                      # Container image definition
├── docker-compose.yml              # Compose configuration
├── .env.example                    # Environment variable template
├── pyproject.toml                  # Project metadata + tool config
├── Makefile                        # Developer convenience targets
├── CONTRIBUTING.md
├── SECURITY.md
└── CHANGELOG.md
```

---

## Security Architecture

### Audit Trail

Every state-changing action in SecureAccess is recorded in the `audit_log` table with:

- **Actor** — the user who performed the action
- **Action** — a human-readable action code (e.g., `create_user`, `approve_request`)
- **Target** — the entity affected (username, role name, etc.)
- **Timestamp** — ISO 8601 UTC datetime
- **Severity** — `info`, `warning`, `critical`
- **Details** — JSON payload with context
- **IP Address** — originating IP (when available)

The audit log is append-only via the application layer; no delete or update APIs are exposed for audit records.

### Role-Based Access Control (RBAC)

Roles are classified by **risk level**: `low`, `medium`, `high`, `critical`.

| Risk Level | Examples | MFA Required | Max Session |
|------------|----------|-------------|-------------|
| low        | Standard User | No | 8h |
| medium     | Power User, Developer | Recommended | 8h |
| high       | Security Analyst, DBA | Yes | 4h |
| critical   | Administrator, Domain Admin | Yes | 2h |

Users are assigned roles via the `user_roles` junction table. Role assignments are tracked in the audit log.

### Password Policy

The `password_policy` table stores organization-wide password requirements:

- **Minimum length** (default: 12)
- **Complexity** — uppercase, lowercase, digits, special characters
- **Maximum age** (default: 90 days)
- **History** — prevents reuse of last N passwords (default: 12)
- **Account lockout** — threshold (default: 5 attempts) and duration (default: 30 minutes)

### Credential Security

- Connector secrets (passwords, API keys) are stored in the database and masked in the UI
- Passwords in the application layer use SHA-256 with a random 64-character hex salt
- No credentials are transmitted to external services except through the configured connectors

---

## Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| GUI | CustomTkinter 5.x | Cross-platform dark-theme desktop UI |
| Language | Python 3.10+ | Application logic |
| Database | SQLite 3 (stdlib) | Local, zero-config persistence |
| PDF Export | ReportLab 4.x | Compliance report generation |
| Image handling | Pillow 10.x | Icon and image support |
| Build | PyInstaller | Standalone executable packaging |
| CI/CD | GitHub Actions | Automated testing and releases |
| Container | Docker | Headless/server deployment |
| Linting | Ruff | Fast Python linter |
| Type checking | mypy | Static type analysis |
| Testing | pytest + pytest-cov | Unit tests and coverage |
