"""
SecureAccess Security Core

Production-oriented services layered on top of the existing SQLite database:
- password hashing with bcrypt when available and PBKDF2 fallback
- password policy validation
- login/session helpers with lockout tracking
- permission resolution from role JSON
- tamper-evident audit log hashing
- JSON backup/export helpers

This module is intentionally GUI-independent so it can be tested and reused by
the desktop app, CLI tools, and future API services.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional


try:
    import bcrypt  # type: ignore
except Exception:  # pragma: no cover - fallback used when bcrypt is unavailable
    bcrypt = None


DEFAULT_ROLE_PERMISSIONS: Dict[str, Dict[str, bool]] = {
    "Administrator": {"all": True},
    "Security Analyst": {
        "view_dashboard": True,
        "view_users": True,
        "edit_users": True,
        "manage_roles": True,
        "approve_requests": True,
        "run_access_reviews": True,
        "view_audit": True,
        "export_reports": True,
        "manage_integrations": True,
    },
    "Auditor": {
        "view_dashboard": True,
        "view_users": True,
        "run_access_reviews": True,
        "view_audit": True,
        "export_reports": True,
    },
    "Help Desk": {
        "view_dashboard": True,
        "view_users": True,
        "edit_users": True,
        "reset_password": True,
    },
    "Privileged User": {
        "view_dashboard": True,
        "view_users": True,
        "request_access": True,
    },
    "Standard User": {
        "view_dashboard": True,
        "request_access": True,
    },
    "Service Account": {
        "api_access": True,
    },
}


@dataclass(frozen=True)
class AuthResult:
    success: bool
    message: str
    user: Optional[sqlite3.Row] = None
    permissions: Optional[Dict[str, bool]] = None
    locked_until: Optional[str] = None


@dataclass(frozen=True)
class AuditIntegrityResult:
    ok: bool
    checked_records: int
    problems: List[str]


@dataclass(frozen=True)
class PasswordPolicyResult:
    ok: bool
    problems: List[str]


class SecurityService:
    """Security services for SecureAccess."""

    HASH_VERSION = "secureaccess-audit-v1"

    def __init__(self, db: Any):
        self.db = db
        self.conn: sqlite3.Connection = db.conn
        self.conn.row_factory = sqlite3.Row
        self.ensure_security_schema()

    def ensure_security_schema(self) -> None:
        """Apply additive security schema upgrades without breaking old DBs."""
        self._add_column_if_missing("audit_log", "previous_hash", "TEXT")
        self._add_column_if_missing("audit_log", "record_hash", "TEXT")
        self._add_column_if_missing("audit_log", "integrity_version", "TEXT")
        self._add_column_if_missing("audit_log", "metadata_json", "TEXT")

        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS app_sessions (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                revoked_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS backup_manifest (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                record_count INTEGER NOT NULL,
                audit_integrity_ok INTEGER NOT NULL
            )
            """
        )
        self.conn.commit()
        self.apply_default_role_permissions()

    def _add_column_if_missing(self, table: str, column: str, definition: str) -> None:
        existing = {row["name"] for row in self.conn.execute(f"PRAGMA table_info({table})")}
        if column not in existing:
            self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def apply_default_role_permissions(self) -> None:
        """Backfill meaningful permissions for seeded roles."""
        for role_name, permissions in DEFAULT_ROLE_PERMISSIONS.items():
            self.conn.execute(
                "UPDATE roles SET permissions = ?, updated_at = ? WHERE name = ?",
                (json.dumps(permissions, sort_keys=True), datetime.utcnow().isoformat(), role_name),
            )
        self.conn.commit()

    def hash_password(self, password: str) -> str:
        if not password:
            raise ValueError("Password cannot be empty.")

        if bcrypt is not None:
            hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))
            return "bcrypt$" + hashed.decode("utf-8")

        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000)
        return "pbkdf2_sha256$310000$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()

    def verify_password(self, password: str, stored_hash: str) -> bool:
        if not password or not stored_hash:
            return False

        if stored_hash.startswith("bcrypt$"):
            if bcrypt is None:
                return False
            return bool(bcrypt.checkpw(password.encode("utf-8"), stored_hash.removeprefix("bcrypt$").encode("utf-8")))

        if stored_hash.startswith("pbkdf2_sha256$"):
            try:
                _, rounds, salt_b64, digest_b64 = stored_hash.split("$", 3)
                salt = base64.b64decode(salt_b64)
                expected = base64.b64decode(digest_b64)
                actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(rounds))
                return hmac.compare_digest(actual, expected)
            except Exception:
                return False

        return False

    def validate_password_policy(self, password: str) -> PasswordPolicyResult:
        policy = self.db.get_password_policy()
        problems: List[str] = []

        if len(password) < int(policy["min_length"]):
            problems.append(f"Password must be at least {policy['min_length']} characters.")
        if policy["require_uppercase"] and not any(ch.isupper() for ch in password):
            problems.append("Password must include an uppercase letter.")
        if policy["require_lowercase"] and not any(ch.islower() for ch in password):
            problems.append("Password must include a lowercase letter.")
        if policy["require_digits"] and not any(ch.isdigit() for ch in password):
            problems.append("Password must include a number.")
        if policy["require_special"] and not any(not ch.isalnum() for ch in password):
            problems.append("Password must include a special character.")

        return PasswordPolicyResult(ok=not problems, problems=problems)

    def bootstrap_admin_password(self, password: Optional[str] = None) -> str:
        """
        Ensure the seeded admin account has a password.

        Returns a human-readable setup message. Prefer setting
        SECUREACCESS_BOOTSTRAP_PASSWORD before first launch.
        """
        user = self.get_user_by_username("admin")
        if not user:
            return "No seeded admin user found."

        if user["password_hash"]:
            return "Admin password is already configured."

        password = password or os.environ.get("SECUREACCESS_BOOTSTRAP_PASSWORD") or "SecureAccess!ChangeMe1"
        policy_result = self.validate_password_policy(password)
        if not policy_result.ok:
            raise ValueError("Bootstrap password failed policy: " + "; ".join(policy_result.problems))

        now = datetime.utcnow()
        self.conn.execute(
            """
            UPDATE users
            SET password_hash = ?, password_changed_at = ?, password_expires_at = ?, updated_at = ?
            WHERE username = 'admin'
            """,
            (
                self.hash_password(password),
                now.isoformat(),
                (now + timedelta(days=1)).isoformat(),
                now.isoformat(),
            ),
        )
        self.conn.commit()
        self.record_audit(
            actor="system",
            action="ADMIN_PASSWORD_BOOTSTRAPPED",
            target_type="user",
            target_id=int(user["id"]),
            target_name="admin",
            details="Seeded admin password configured. Change required after first login.",
            severity="warning",
        )
        return "Admin password configured. Default demo password expires quickly and should be changed."

    def get_user_by_username(self, username: str) -> Optional[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    def set_user_password(self, username: str, new_password: str, actor: str = "admin") -> None:
        policy_result = self.validate_password_policy(new_password)
        if not policy_result.ok:
            raise ValueError("; ".join(policy_result.problems))

        user = self.get_user_by_username(username)
        if not user:
            raise ValueError(f"Unknown user: {username}")

        policy = self.db.get_password_policy()
        expires_at = datetime.utcnow() + timedelta(days=int(policy["max_age_days"]))
        self.conn.execute(
            """
            UPDATE users
            SET password_hash = ?, password_changed_at = ?, password_expires_at = ?,
                failed_login_count = 0, locked_until = NULL, updated_at = ?
            WHERE username = ?
            """,
            (
                self.hash_password(new_password),
                datetime.utcnow().isoformat(),
                expires_at.isoformat(),
                datetime.utcnow().isoformat(),
                username,
            ),
        )
        self.conn.commit()
        self.record_audit(
            actor=actor,
            action="PASSWORD_CHANGED",
            target_type="user",
            target_id=int(user["id"]),
            target_name=username,
            details="Password hash changed and failed login counter reset.",
            severity="warning",
        )

    def authenticate(self, username: str, password: str) -> AuthResult:
        user = self.get_user_by_username(username)
        if not user:
            self.record_audit("system", "LOGIN_FAILED", "user", None, username, "Unknown username", "warning")
            return AuthResult(False, "Invalid username or password.")

        if user["status"] != "active":
            self.record_audit("system", "LOGIN_BLOCKED", "user", int(user["id"]), username, f"Status is {user['status']}", "warning")
            return AuthResult(False, f"Account is {user['status']}.")

        locked_until = user["locked_until"]
        if locked_until and datetime.fromisoformat(locked_until) > datetime.utcnow():
            return AuthResult(False, "Account is temporarily locked.", locked_until=locked_until)

        if not self.verify_password(password, user["password_hash"] or ""):
            self._record_failed_login(user)
            return AuthResult(False, "Invalid username or password.")

        self.conn.execute(
            """
            UPDATE users
            SET failed_login_count = 0, locked_until = NULL, last_login = ?, updated_at = ?
            WHERE id = ?
            """,
            (datetime.utcnow().isoformat(), datetime.utcnow().isoformat(), int(user["id"])),
        )
        self.conn.commit()
        fresh_user = self.get_user_by_username(username)
        permissions = self.resolve_user_permissions(int(user["id"]))
        self.record_audit("system", "LOGIN_SUCCESS", "user", int(user["id"]), username, "User authenticated.", "info")
        return AuthResult(True, "Authenticated.", fresh_user, permissions)

    def _record_failed_login(self, user: sqlite3.Row) -> None:
        policy = self.db.get_password_policy()
        failures = int(user["failed_login_count"] or 0) + 1
        locked_until = None
        if failures >= int(policy["lockout_threshold"]):
            locked_until = (datetime.utcnow() + timedelta(minutes=int(policy["lockout_duration_minutes"]))).isoformat()

        self.conn.execute(
            "UPDATE users SET failed_login_count = ?, locked_until = ?, updated_at = ? WHERE id = ?",
            (failures, locked_until, datetime.utcnow().isoformat(), int(user["id"])),
        )
        self.conn.commit()
        self.record_audit(
            actor="system",
            action="LOGIN_FAILED",
            target_type="user",
            target_id=int(user["id"]),
            target_name=user["username"],
            details=f"Failed login count is {failures}.",
            severity="critical" if locked_until else "warning",
            metadata={"locked_until": locked_until},
        )

    def create_session(self, user: sqlite3.Row, minutes: int = 60) -> str:
        session_id = secrets.token_urlsafe(32)
        now = datetime.utcnow()
        expires = now + timedelta(minutes=minutes)
        self.conn.execute(
            """
            INSERT INTO app_sessions (id, user_id, username, created_at, expires_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (session_id, int(user["id"]), user["username"], now.isoformat(), expires.isoformat(), now.isoformat()),
        )
        self.conn.commit()
        self.record_audit("system", "SESSION_CREATED", "user", int(user["id"]), user["username"], f"Session expires at {expires.isoformat()}.")
        return session_id

    def validate_session(self, session_id: str) -> Optional[sqlite3.Row]:
        row = self.conn.execute("SELECT * FROM app_sessions WHERE id = ?", (session_id,)).fetchone()
        if not row or row["revoked_at"]:
            return None
        if datetime.fromisoformat(row["expires_at"]) <= datetime.utcnow():
            return None
        self.conn.execute("UPDATE app_sessions SET last_seen_at = ? WHERE id = ?", (datetime.utcnow().isoformat(), session_id))
        self.conn.commit()
        return row

    def revoke_session(self, session_id: str) -> None:
        self.conn.execute("UPDATE app_sessions SET revoked_at = ? WHERE id = ?", (datetime.utcnow().isoformat(), session_id))
        self.conn.commit()

    def resolve_user_permissions(self, user_id: int) -> Dict[str, bool]:
        permissions: Dict[str, bool] = {}
        for role in self.db.get_user_roles(user_id):
            try:
                role_permissions = json.loads(role["permissions"] or "{}")
            except json.JSONDecodeError:
                role_permissions = {}
            if role_permissions.get("all"):
                return {"all": True}
            for permission, allowed in role_permissions.items():
                permissions[permission] = bool(allowed)
        return permissions

    def has_permission(self, user_id: int, permission: str) -> bool:
        permissions = self.resolve_user_permissions(user_id)
        return bool(permissions.get("all") or permissions.get(permission))

    def require_permission(self, user_id: int, permission: str) -> None:
        if not self.has_permission(user_id, permission):
            raise PermissionError(f"Permission required: {permission}")

    def _last_audit_hash(self) -> str:
        row = self.conn.execute(
            "SELECT record_hash FROM audit_log WHERE record_hash IS NOT NULL ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return row["record_hash"] if row and row["record_hash"] else "GENESIS"

    def _audit_hash_payload(
        self,
        *,
        previous_hash: str,
        timestamp: str,
        actor: str,
        action: str,
        target_type: Optional[str],
        target_id: Optional[int],
        target_name: Optional[str],
        details: Optional[str],
        severity: str,
        metadata: Optional[Dict[str, Any]],
    ) -> str:
        payload = {
            "version": self.HASH_VERSION,
            "previous_hash": previous_hash,
            "timestamp": timestamp,
            "actor": actor,
            "action": action,
            "target_type": target_type,
            "target_id": target_id,
            "target_name": target_name,
            "details": details,
            "severity": severity,
            "metadata": metadata or {},
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def record_audit(
        self,
        actor: str,
        action: str,
        target_type: Optional[str] = None,
        target_id: Optional[int] = None,
        target_name: Optional[str] = None,
        details: Optional[str] = None,
        severity: str = "info",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        previous_hash = self._last_audit_hash()
        timestamp = datetime.utcnow().isoformat()
        record_hash = self._audit_hash_payload(
            previous_hash=previous_hash,
            timestamp=timestamp,
            actor=actor,
            action=action,
            target_type=target_type,
            target_id=target_id,
            target_name=target_name,
            details=details,
            severity=severity,
            metadata=metadata,
        )
        self.conn.execute(
            """
            INSERT INTO audit_log
                (timestamp, actor, action, target_type, target_id, target_name, details, severity,
                 previous_hash, record_hash, integrity_version, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                actor,
                action,
                target_type,
                target_id,
                target_name,
                details,
                severity,
                previous_hash,
                record_hash,
                self.HASH_VERSION,
                json.dumps(metadata or {}, sort_keys=True),
            ),
        )
        self.conn.commit()
        return record_hash

    def backfill_audit_hashes(self) -> AuditIntegrityResult:
        previous_hash = "GENESIS"
        for row in self.conn.execute("SELECT * FROM audit_log ORDER BY id"):
            if row["record_hash"] and row["previous_hash"]:
                previous_hash = row["record_hash"]
                continue
            metadata = json.loads(row["metadata_json"] or "{}")
            record_hash = self._audit_hash_payload(
                previous_hash=previous_hash,
                timestamp=row["timestamp"],
                actor=row["actor"],
                action=row["action"],
                target_type=row["target_type"],
                target_id=row["target_id"],
                target_name=row["target_name"],
                details=row["details"],
                severity=row["severity"],
                metadata=metadata,
            )
            self.conn.execute(
                "UPDATE audit_log SET previous_hash = ?, record_hash = ?, integrity_version = ? WHERE id = ?",
                (previous_hash, record_hash, self.HASH_VERSION, int(row["id"])),
            )
            previous_hash = record_hash
        self.conn.commit()
        return self.verify_audit_chain()

    def verify_audit_chain(self) -> AuditIntegrityResult:
        problems: List[str] = []
        previous_hash = "GENESIS"
        checked = 0
        for row in self.conn.execute("SELECT * FROM audit_log ORDER BY id"):
            checked += 1
            if not row["record_hash"] or not row["previous_hash"]:
                problems.append(f"Audit row {row['id']} is missing integrity hashes.")
                continue

            if row["previous_hash"] != previous_hash:
                problems.append(f"Audit row {row['id']} previous hash does not match the prior row.")

            try:
                metadata = json.loads(row["metadata_json"] or "{}")
            except json.JSONDecodeError:
                metadata = {}

            expected = self._audit_hash_payload(
                previous_hash=row["previous_hash"],
                timestamp=row["timestamp"],
                actor=row["actor"],
                action=row["action"],
                target_type=row["target_type"],
                target_id=row["target_id"],
                target_name=row["target_name"],
                details=row["details"],
                severity=row["severity"],
                metadata=metadata,
            )
            if row["record_hash"] != expected:
                problems.append(f"Audit row {row['id']} hash verification failed.")

            previous_hash = row["record_hash"]

        return AuditIntegrityResult(ok=not problems, checked_records=checked, problems=problems)

    def export_backup(self, output_path: str | os.PathLike[str]) -> Dict[str, Any]:
        """Export a JSON backup of all application tables."""
        self.backfill_audit_hashes()
        tables = [
            "roles",
            "users",
            "user_roles",
            "access_requests",
            "audit_log",
            "password_policy",
            "access_reviews",
            "review_items",
            "app_sessions",
        ]
        integrity = self.verify_audit_chain()
        data: Dict[str, Any] = {
            "generated_at": datetime.utcnow().isoformat(),
            "format": "secureaccess-backup-v1",
            "audit_integrity": {
                "ok": integrity.ok,
                "checked_records": integrity.checked_records,
                "problems": integrity.problems,
            },
            "tables": {},
        }
        total_records = 0
        for table in tables:
            rows = [dict(row) for row in self.conn.execute(f"SELECT * FROM {table}")]
            data["tables"][table] = rows
            total_records += len(rows)

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = json.dumps(data, indent=2, sort_keys=True)
        path.write_text(raw, encoding="utf-8")
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        self.conn.execute(
            """
            INSERT INTO backup_manifest (created_at, path, sha256, record_count, audit_integrity_ok)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                datetime.utcnow().isoformat(),
                str(path),
                digest,
                total_records,
                1 if integrity.ok else 0,
            ),
        )
        self.conn.commit()
        self.record_audit(
            actor="system",
            action="BACKUP_EXPORTED",
            target_type="backup",
            target_name=path.name,
            details=f"Exported {total_records} records. sha256={digest}",
            severity="info",
        )
        return {"path": str(path), "sha256": digest, "record_count": total_records}
