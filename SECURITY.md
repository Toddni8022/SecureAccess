# Security Policy — SecureAccess

## Supported Versions

The following versions of SecureAccess receive security updates:

| Version | Supported |
|---------|-----------|
| 1.x (latest) | ✅ Active |
| < 1.0 | ❌ End of life |

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in SecureAccess, please report it privately:

1. **Email:** Send details to the maintainer at the email address listed in the GitHub profile for `Toddni8022`. Mark the subject as `[SECURITY] SecureAccess Vulnerability Report`.

2. **GitHub Private Vulnerability Reporting:** Use GitHub's built-in [private vulnerability reporting](https://github.com/Toddni8022/SecureAccess/security/advisories/new) feature (if enabled on the repository).

### What to Include

Please provide as much of the following as possible:

- **Type of vulnerability** (e.g., SQL injection, path traversal, insecure credential storage)
- **Affected component** (`database.py`, `connectors.py`, `app.py`, etc.)
- **Steps to reproduce** the issue
- **Proof of concept** or exploit code (if safe to share)
- **Impact assessment** — what data or systems could be affected
- **Your suggested fix** (if you have one)

---

## Response Timeline

| Stage | Timeline |
|-------|----------|
| Initial acknowledgement | Within 48 hours |
| Severity assessment | Within 5 business days |
| Fix development | Within 30 days for critical/high severity |
| Public disclosure | After fix is released (coordinated disclosure) |

We will credit reporters in the release notes unless anonymity is requested.

---

## Security Considerations

### Data Storage

- All application data is stored in a **local SQLite database** on the user's machine. No data is sent to external servers except through explicitly configured connectors.
- The database path defaults to the OS-standard application data directory:
  - **Windows:** `%LOCALAPPDATA%\SecureAccess\secureaccess.db`
  - **macOS / Linux:** `~/.local/share/SecureAccess/secureaccess.db`
- The database file should be protected with appropriate filesystem permissions (mode 600 recommended).

### Password Handling

- Application-layer passwords (e.g., user account passwords in the demo) are hashed using **SHA-256 with a random 64-character hex salt**.
- Connector secrets (API keys, LDAP bind passwords) are stored in the SQLite database and masked in the UI. For production deployments, consider encrypting the database file at rest using OS-level tools (e.g., BitLocker, FileVault, LUKS).
- No plaintext passwords are logged in the audit trail.

### Audit Trail

- The audit log is **append-only** via the application layer — there are no exposed APIs to modify or delete audit records.
- All security-relevant actions (user creation, role changes, access approvals, connector provisioning) are logged with actor, timestamp, and severity.

### Connector Credentials

- Connector credentials should be treated as secrets. Limit the permissions of service accounts used by connectors to the minimum required (principle of least privilege).
- For Active Directory: use a dedicated service account with only the permissions needed for user and group management.
- For Azure AD: use an app registration with only the required Graph API permissions (not Global Administrator).
- For AWS IAM: use an IAM user or role with a custom policy scoped to the minimum required actions.

### Network Security

- Connectors that use plaintext protocols (LDAP on port 389) should be configured to use encrypted variants (LDAPS on port 636) in production.
- API keys and tokens should be rotated regularly and revoked when no longer needed.

### Known Limitations

- The application does not currently encrypt the SQLite database file at rest. Users should apply OS-level disk encryption for sensitive environments.
- The SHA-256 password hashing used internally is not bcrypt/argon2. This is a portfolio/demonstration application; production identity systems should use modern password hashing algorithms.
- The application has no built-in network server — it is a desktop application and does not expose network ports.

---

## Security Best Practices for Operators

1. Run SecureAccess on a **dedicated, hardened workstation** or privileged access workstation (PAW).
2. Restrict access to the database file to authorized administrators only.
3. Rotate connector credentials (API keys, service account passwords) on a regular schedule.
4. Review the audit log regularly for anomalous activity.
5. Keep SecureAccess and its dependencies up to date.
6. Use MFA for all administrator accounts in the application.
7. Apply OS-level disk encryption (BitLocker, FileVault, LUKS) to protect the database at rest.
