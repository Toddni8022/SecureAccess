# 🛡️ SecureAccess — User Access Management Platform

A professional desktop application for security teams to manage user identities, role-based access control, access requests, compliance reviews, and audit logging.

![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-blue)
![Python](https://img.shields.io/badge/python-3.10+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

## Features

### 📊 Dashboard
- Real-time security posture overview
- User status breakdown (active, inactive, locked, pending)
- MFA coverage metrics
- Pending request alerts
- Role distribution visualization

### 👥 User Management
- Full CRUD operations for user accounts
- Status management (active, inactive, locked, pending review)
- MFA tracking per user
- Department and title assignment
- Search and filter capabilities
- CSV export

### 🔑 Role-Based Access Control (RBAC)
- Define roles with risk levels (low, medium, high, critical)
- Set maximum session durations per role
- MFA requirements per role
- Assign/revoke roles with justification tracking
- Role member visibility

### 📋 Access Request Workflow
- Submit access grant/revoke requests
- Business justification requirements
- Approve/deny workflow with reviewer tracking
- Request history and status tracking

### 🔍 Periodic Access Reviews
- Create quarterly/periodic access certification campaigns
- Review all user-role assignments
- Certify or revoke access per item
- Track review completion status
- Due date management

### 📜 Audit Logging
- Complete immutable audit trail
- Severity levels (info, warning, critical)
- Search and filter capabilities
- CSV export for compliance reporting

### ⚙️ Password Policy Management
- Configurable minimum length, complexity requirements
- Password expiration settings
- Account lockout thresholds and duration
- Password history enforcement

### 📊 Compliance Reports
- User Access Report
- MFA Compliance Report
- Privileged Access Report
- Inactive Users Report
- Role Summary Report
- Audit Summary
- All reports exportable to CSV

## Installation

### Option 1: Run from Source
```bash
# Clone the repository
git clone https://github.com/Toddni8022/SecureAccess.git
cd SecureAccess

# Install dependencies
pip install -r requirements.txt

# Run
python app.py
```

### Option 2: Build Standalone Executable
```bash
# Install dependencies + build
python build.py

# The executable will be in dist/SecureAccess.exe (Windows)
# or dist/SecureAccess (macOS/Linux)
```

### Option 3: Download Pre-built
Download the latest release from the [Releases](https://github.com/Toddni8022/SecureAccess/releases) page.

## Tech Stack

- **Python 3.10+** — Core language
- **CustomTkinter** — Modern dark-themed GUI framework
- **SQLite** — Embedded database (zero configuration)
- **PyInstaller** — Cross-platform executable packaging

## Architecture

```
SecureAccess/
├── app.py              # Main application (GUI + logic)
├── database.py         # Database layer (SQLite ORM)
├── build.py            # PyInstaller build script
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

**Data Storage:** SQLite database stored in user's local app data:
- Windows: `%LOCALAPPDATA%\SecureAccess\secureaccess.db`
- macOS: `~/.local/share/SecureAccess/secureaccess.db`
- Linux: `~/.local/share/SecureAccess/secureaccess.db`

## Security Considerations

- All actions are logged to an immutable audit trail
- Role-based access with risk-level classification
- MFA tracking and compliance reporting
- Password policy enforcement
- Access review workflows for periodic certification
- Data stored locally — no cloud dependencies

## Use Cases

- **SOC Teams**: Manage analyst access levels and certifications
- **IT Security**: Enforce least-privilege access policies
- **Compliance**: Generate audit-ready reports for SOX, HIPAA, PCI-DSS
- **Small/Medium Businesses**: Lightweight IAM without enterprise cost

## Screenshots

*Run the application to see the modern dark-themed UI with dashboard, user management, role-based access control, and compliance reporting.*

## License

MIT License — See LICENSE file for details.

---

**Built by Todd Nicholas** | Security Professional Portfolio Project

