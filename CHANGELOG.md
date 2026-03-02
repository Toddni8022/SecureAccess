# Changelog

All notable changes to SecureAccess are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2025-03-02

### Added

#### Core Application
- Full desktop GUI application built with [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) in dark theme
- Cross-platform support: Windows 10+, macOS 12+, Ubuntu 22.04+
- Single-file standalone executable via PyInstaller (`python build.py`)

#### Dashboard
- Real-time security posture overview with key metrics
- Active users, pending access requests, overdue access reviews, MFA adoption rate
- Recent audit log feed with severity color coding
- Quick-action buttons for common security tasks

#### User Management
- Full CRUD operations for user accounts
- User fields: username, display name, email, department, title, status, MFA settings, notes
- Status management: `active`, `inactive`, `locked`, `pending_review`
- MFA tracking: method (`authenticator`, `sms`, `hardware_key`, `email`) and enabled status
- Search and filter by status, name, email, department
- Last login tracking

#### Role-Based Access Control (RBAC)
- Role management with risk level classification: `low`, `medium`, `high`, `critical`
- Per-role configuration: description, permissions (JSON), max session hours, MFA requirement
- User-role assignment management
- Default roles seeded: Administrator, Security Analyst, Power User, Developer, Standard User, Read-Only, Service Account, Compliance Auditor

#### Access Requests
- Submit access grant/revoke requests with business justification
- Approve and deny workflow with reviewer notes
- Status tracking: `pending`, `approved`, `denied`
- Audit logging of all request state changes

#### Access Reviews (Certification Campaigns)
- Create periodic access review campaigns
- Certify or revoke user-role pairs
- Track review completion status
- Audit logging of all certification decisions

#### Audit Log
- Immutable append-only audit trail
- Captures: actor, action, target, details, severity (`info`, `warning`, `critical`), timestamp, IP address
- Full-text search and severity filtering
- Export to CSV

#### Password Policy
- Configurable organization-wide password requirements:
  - Minimum length (default: 12)
  - Uppercase, lowercase, digit, special character requirements
  - Maximum age in days (default: 90)
  - Password history count (default: 12)
  - Account lockout threshold (default: 5 attempts) and duration (default: 30 minutes)

#### Compliance Reports
- 6 built-in report types:
  1. User Access Summary
  2. MFA Compliance Report
  3. Privileged Access Report
  4. Dormant Account Report
  5. Access Request History
  6. Role Assignment Report
- Export all reports to CSV
- PDF generation via ReportLab

#### System Integrations (Connectors)
- Modular connector architecture based on `BaseConnector`
- 6 connectors included:
  - **Active Directory / LDAP** — full user lifecycle + group management
  - **Microsoft Entra ID (Azure AD)** — Microsoft Graph API integration
  - **AWS IAM** — IAM user and group management
  - **Okta** — Universal identity platform
  - **Linux** — Local Linux user and group management
  - **Database** — Direct database user management
- Each connector supports: test connection, create user, disable, enable, delete, assign group, remove group, reset password
- Connector configuration UI with field masking for secrets
- Provisioning result log with timestamps

#### Database Layer
- SQLite database with WAL journal mode
- Foreign key constraints enforced
- Tables: `users`, `roles`, `user_roles`, `access_requests`, `audit_log`, `password_policy`, `access_reviews`, `review_decisions`
- Automatic database creation and schema migration on first launch
- Default seed data for roles, users, and password policy

#### Package Structure (`src/secure_access/`)
- Importable Python package wrapping root modules
- `auth.password` — `hash_password`, `verify_password`, `PasswordPolicy`
- `models.user` — `UserStatus`, `MFAMethod` enums
- `models.role` — `RiskLevel` enum
- `utils.csv_export` — `export_to_csv`
- `utils.date_utils` — `format_datetime`, `days_until`
- `connectors` — re-exports `ConnectorManager`, `CONNECTORS`
- `database` — re-exports `Database`, `get_db_path`

#### Tests (`tests/`)
- Pytest test suite with shared fixtures (`conftest.py`)
- `test_database.py` — 10 tests covering database initialization, seeding, CRUD
- `test_connectors.py` — 17 tests covering ProvisioningResult, AD connector, Azure AD connector, CONNECTORS registry, ConnectorManager
- `test_auth.py` — 13 tests covering password hashing, verification, and policy validation
- Temporary database fixture for test isolation

#### CI/CD (`.github/workflows/`)
- `ci.yml` — Runs on push to `main`/`master`/`copilot/**` and PRs:
  - Matrix testing across Python 3.10, 3.11, 3.12
  - Ruff linting
  - pytest with coverage reporting
  - Coverage artifact upload
- `release.yml` — Runs on version tags (`v*.*.*`):
  - Builds standalone executables for Windows, macOS, Linux
  - Creates GitHub Release with artifacts and auto-generated release notes

#### DevOps
- `Dockerfile` — Python 3.11-slim image with tkinter
- `docker-compose.yml` — Persistent volume for database data
- `.env.example` — Environment variable template
- `.dockerignore` — Optimized Docker build context

#### Code Quality
- `pyproject.toml` — Project metadata, Ruff, mypy, pytest, coverage configuration
- `setup.py` — Legacy setuptools compatibility
- `pytest.ini` — Pytest configuration
- `.coveragerc` — Coverage reporting configuration
- `.editorconfig` — Editor formatting standards
- `Makefile` — Developer convenience targets: `install`, `test`, `lint`, `typecheck`, `run`, `build`, `docker-build`, `docker-run`, `clean`
- Updated `.gitignore` — Comprehensive Python/IDE/build exclusions

#### Documentation (`docs/`)
- `architecture.md` — System overview, component diagram, data flow, security architecture, tech stack
- `api.md` — Database API reference, Connector API reference, data model schemas
- `connectors.md` — Connector configuration guide and instructions for adding new connectors
- `deployment.md` — Installation from source, PyInstaller builds, Docker deployment, environment variables, troubleshooting

#### Root Documentation
- `CONTRIBUTING.md` — Development setup, testing guide, code style, commit conventions, PR checklist
- `SECURITY.md` — Security policy, vulnerability reporting, response timeline, security considerations
- `CHANGELOG.md` — This file
- Updated `README.md` — Badges, feature matrix, connector table, architecture diagram, installation options, environment variable table, project structure

---

[1.0.0]: https://github.com/Toddni8022/SecureAccess/releases/tag/v1.0.0
