# 🛡️ SecureAccess — User Access Management Platform

> A professional desktop application for security teams to manage user identities, role-based access control, access requests, compliance reviews, and audit logging.

[![CI](https://github.com/Toddni8022/SecureAccess/actions/workflows/ci.yml/badge.svg)](https://github.com/Toddni8022/SecureAccess/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)](https://github.com/Toddni8022/SecureAccess/releases)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

## 📋 Table of Contents

- [Features](#-features)
- [Supported Connectors](#-supported-connectors)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Environment Variables](#-environment-variables)
- [Usage](#-usage)
- [Project Structure](#-project-structure)
- [Security Considerations](#-security-considerations)
- [Contributing](#-contributing)
- [License](#-license)

## ✨ Features

| Feature | Description | Status |
|---------|-------------|--------|
| 📊 Dashboard | Real-time security posture overview | ✅ |
| 👥 User Management | Full CRUD with status, MFA, department tracking | ✅ |
| 🔑 RBAC | Roles with risk levels, MFA requirements, session limits | ✅ |
| �� Access Requests | Approve/deny workflow with justification tracking | ✅ |
| 🔍 Access Reviews | Periodic certification campaigns | ✅ |
| 📜 Audit Logging | Immutable audit trail with severity levels | ✅ |
| ⚙️ Password Policy | Configurable complexity, expiry, lockout | ✅ |
| 🔗 Integrations | Connectors to 8+ external identity systems | ✅ |
| 📊 Compliance Reports | 6 report types exportable to CSV | ✅ |

## 🔗 Supported Connectors

| Connector | Protocol | Use Case |
|-----------|----------|----------|
| 🏢 Active Directory / LDAP | LDAP/LDAPS | On-premise identity |
| ☁️ Microsoft Entra ID (Azure AD) | Microsoft Graph API | Cloud identity |
| 🔐 Okta | SCIM / REST API | Universal identity |
| 🌐 Google Workspace | Google Directory API | G Suite identity |
| 🟠 AWS IAM | AWS SDK | Cloud access |
| 🐙 GitHub | GitHub REST API | Dev team access |
| 💬 Slack | Slack SCIM API | Workspace access |
| 🎫 Jira Service Management | Atlassian API | ITSM integration |

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    SecureAccess GUI                      │
│              (CustomTkinter — Dark Theme)                │
│                                                          │
│  Dashboard │ Users │ Roles │ Requests │ Reviews │ Audit  │
│            │       │       │          │         │        │
│        Reports │ Password Policy │ Integrations         │
└─────────────────┬──────────────────┬────────────────────┘
                  │                  │
    ┌─────────────▼──────────┐  ┌───▼──────────────────────┐
    │     Database Layer      │  │    Connector Layer         │
    │  (SQLite via sqlite3)   │  │  (8+ Identity Systems)    │
    │                         │  │                            │
    │  • Users                │  │  • Active Directory        │
    │  • Roles                │  │  • Azure AD / Entra ID     │
    │  • User Roles           │  │  • Okta                    │
    │  • Access Requests      │  │  • Google Workspace        │
    │  • Audit Log            │  │  • AWS IAM                 │
    │  • Password Policy      │  │  • GitHub                  │
    │  • Access Reviews       │  │  • Slack                   │
    └─────────────────────────┘  │  • Jira                    │
                                  └────────────────────────────┘
```

**Data Storage:** SQLite database stored in user's local app data:
- Windows: `%LOCALAPPDATA%\SecureAccess\secureaccess.db`
- macOS/Linux: `~/.local/share/SecureAccess/secureaccess.db`

## 🚀 Installation

### Option 1: Run from Source (Recommended for Development)

```bash
# Clone the repository
git clone https://github.com/Toddni8022/SecureAccess.git
cd SecureAccess

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Launch
python app.py
```

### Option 2: Build Standalone Executable

```bash
# Install dependencies + build
python build.py

# Executable location:
#   Windows: dist/SecureAccess.exe
#   macOS/Linux: dist/SecureAccess
```

### Option 3: Download Pre-built Release

Download the latest release from the [Releases](https://github.com/Toddni8022/SecureAccess/releases) page — no Python installation required.

### Option 4: Docker

```bash
# Build and run with Docker Compose
docker-compose up

# Or build manually
docker build -t secureaccess .
docker run --rm -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix secureaccess
```

## ⚙️ Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECUREACCESS_DB_PATH` | OS app data dir | Override database file path |
| `LOG_LEVEL` | `INFO` | Log verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `APP_THEME` | `dark` | UI theme (`dark`, `light`, `system`) |
| `DISPLAY` | `:0` | X11 display (Linux/Docker) |

Copy `.env.example` to `.env` to configure:
```bash
cp .env.example .env
```

## 🖥️ Usage

After launching, SecureAccess opens with the **Dashboard** showing your security posture at a glance.

### Key Workflows

**Adding a user:**
1. Navigate to **Users** → Click **+ Add User**
2. Fill in username, display name, email, department, title
3. Set MFA status and initial account status
4. Click **Save**

**Creating an access request:**
1. Navigate to **Access Requests** → Click **+ New Request**
2. Select user, role, and request type (grant/revoke)
3. Provide business justification
4. Submit for review

**Running a compliance report:**
1. Navigate to **Reports**
2. Select report type (User Access, MFA Compliance, Privileged Access, etc.)
3. Click **Generate** → **Export CSV**

See [docs/api.md](docs/api.md) for the full API reference.

## 📁 Project Structure

```
SecureAccess/
├── app.py                          # Main application (GUI)
├── database.py                     # Database layer (SQLite)
├── connectors.py                   # System integrations
├── build.py                        # PyInstaller build script
├── requirements.txt                # Runtime dependencies
│
├── src/secure_access/              # Package (importable modules)
│   ├── __init__.py
│   ├── app.py                      # Entry point for package use
│   ├── auth/                       # Auth & password utilities
│   ├── connectors/                 # Connector package wrappers
│   ├── database/                   # Database package wrappers
│   ├── models/                     # Data models (enums)
│   ├── routes/                     # GUI view stubs
│   └── utils/                      # CSV export, date utilities
│
├── tests/                          # Test suite
│   ├── conftest.py                 # Shared fixtures
│   ├── test_auth.py
│   ├── test_connectors.py
│   └── test_database.py
│
├── docs/                           # Documentation
│   ├── architecture.md
│   ├── api.md
│   ├── connectors.md
│   └── deployment.md
│
├── .github/workflows/              # CI/CD
│   ├── ci.yml
│   └── release.yml
│
├── Dockerfile                      # Container image
├── docker-compose.yml              # Multi-service compose
├── .env.example                    # Environment variable template
├── pyproject.toml                  # Project metadata + tool config
├── Makefile                        # Developer convenience commands
└── CHANGELOG.md
```

## 🔒 Security Considerations

- **Immutable Audit Trail:** All actions are logged with actor, timestamp, severity, and target
- **RBAC with Risk Levels:** Roles classified as low/medium/high/critical with MFA enforcement
- **Password Policy Enforcement:** Configurable length, complexity, expiry, history, and lockout
- **Access Review Campaigns:** Periodic certification to verify least-privilege
- **Local Storage Only:** No cloud dependencies; all data stays on your infrastructure
- **Credential Masking:** Connector passwords/secrets are masked in UI and logs
- **Foreign Key Constraints:** Database enforces referential integrity

See [SECURITY.md](SECURITY.md) for the security policy and vulnerability reporting process.

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Quick development setup
make install
make test
make lint
```

## 📄 License

MIT License — See [LICENSE](LICENSE) for details.

---

**Built by Todd Nicholas** | Security Professional Portfolio Project
