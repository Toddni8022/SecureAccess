# Production Hardening Notes

SecureAccess is much stronger than a basic demo, but it should still be treated as a portfolio project until the items below are completed.

## Implemented security foundations

- Authenticated launcher
- Password hashing with bcrypt when available
- PBKDF2 fallback when bcrypt is unavailable
- Password policy validation
- Failed login lockout
- Session records
- Role permission resolution
- Tamper-evident audit hash chain
- Audit verification
- JSON backup export
- Automated security core tests

## Still simulated

- Active Directory / LDAP provisioning
- Microsoft Entra ID provisioning
- AWS IAM provisioning
- Okta provisioning
- Linux user provisioning
- Database account provisioning

The connector layer returns realistic simulated responses today. Live mode should be added gradually and tested against sandbox accounts only.

## Must-have upgrades before real production use

### 1. Full GUI permission enforcement

Every destructive or sensitive GUI action should call:

```python
security.require_permission(current_user_id, "permission_name")
```

Sensitive actions include:

- create user
- edit user
- delete user
- assign role
- revoke role
- approve request
- deny request
- update password policy
- export audit logs
- configure integrations
- export backups

### 2. Centralized secrets

Do not store production API tokens, bind passwords, or private key paths in plain local config. Use:

- OS keyring
- Microsoft Credential Manager
- macOS Keychain
- Linux Secret Service
- enterprise vault integration

### 3. External audit sink

The local audit hash chain is tamper-evident, not truly immutable. Production deployments should forward audit events to:

- SIEM
- append-only object storage
- WORM-capable storage
- external log aggregator

### 4. Real MFA or SSO

The current app tracks MFA status. Production use needs real enforcement with:

- OIDC
- SAML
- Entra ID
- Okta
- Duo
- hardware-backed MFA where possible

### 5. Encrypted backups

Backup export should be encrypted before containing real user data. Recommended path:

- AES-GCM file encryption
- per-backup random key
- key protected by OS keyring or vault
- backup restore verification tests

### 6. Live connector dry-run mode

Every live connector should support:

- dry run
- least-privilege credentials
- scoped test environment
- rollback or cleanup where possible
- detailed error handling
- audit logging for every external operation

### 7. Packaging and release security

Before release builds:

- sign Windows executables
- pin dependencies
- scan dependencies
- add CI test enforcement
- generate checksums for releases
- document update process
