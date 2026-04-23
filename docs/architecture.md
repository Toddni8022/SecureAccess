# SecureAccess Architecture

## Purpose

SecureAccess models the access-management workflow used by security, IT, and compliance teams. The application is built as a desktop-first IAM portfolio project with a local SQLite database and a modular connector layer.

## High-level components

```text
User
  |
  v
secure_launcher.py
  |
  v
SecurityService
  |
  +--> password hashing
  +--> session tracking
  +--> permission resolution
  +--> tamper-evident audit chain
  +--> JSON backup export
  |
  v
SecureAccessApp
  |
  +--> dashboard
  +--> users
  +--> roles
  +--> access requests
  +--> access reviews
  +--> audit logs
  +--> reports
  +--> integrations
  |
  v
Database
  |
  v
SQLite local app database
```

## Trust boundaries

### Local desktop boundary

The desktop app runs locally on the user's machine. The SQLite database is stored in local application data. This makes the app easy to run and demo, but it also means the device itself is part of the trust boundary.

### Database boundary

The database is not treated as fully trusted. The audit log now supports chained hashes so tampering can be detected after the fact.

### Connector boundary

The connector layer is intentionally modular. The current connectors simulate realistic provisioning flows. Live connectors should be added one at a time with strict credential handling, least privilege, and dry-run modes.

## SecurityService responsibilities

`security_core.py` contains the security logic that should not live directly inside GUI code:

- Bootstrap the admin password
- Hash and verify passwords
- Validate password policy
- Track failed logins and lockouts
- Create and validate sessions
- Resolve permissions from user roles
- Record tamper-evident audit events
- Verify audit chain integrity
- Export backup files with SHA-256 manifests

## Audit integrity model

Each protected audit record contains:

- previous hash
- record hash
- integrity version
- metadata JSON

The record hash is calculated from the audit event fields plus the previous record hash. If a previous record is changed, deleted, or reordered, the verification chain reports an issue.

This is tamper-evident, not tamper-proof. For true immutability, records should also be shipped to append-only external storage or a centralized SIEM.

## Permission model

Roles store JSON permissions. The security service resolves all roles assigned to a user into a final permission map. Administrator receives `all: true`.

Examples:

```json
{
  "view_users": true,
  "edit_users": true,
  "manage_roles": true,
  "view_audit": true
}
```

The next production step is to call `require_permission()` before every GUI action that changes data.

## Backup model

`SecurityService.export_backup()` exports all application tables into a signed JSON-like manifest with:

- generated timestamp
- format version
- audit integrity status
- table data
- SHA-256 hash
- record count

The backup manifest is also logged in the audit chain.

## Recommended next live connector

The best first live connector is Linux over SSH because it is easy to test in a VM or WSL sandbox. The second best is AWS IAM because boto3 provides clean APIs and strong examples for least-privilege access.
