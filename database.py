"""
SecureAccess - Database Layer
SQLite database for user access management
"""

import sqlite3
import os
import hashlib
import secrets
import json
import bcrypt
from datetime import datetime, timedelta
from pathlib import Path

# Allowed column names for dynamic INSERT/UPDATE queries (prevents SQL injection)
_ALLOWED_USER_COLS = {
    'username', 'display_name', 'email', 'department', 'title', 'status',
    'mfa_enabled', 'mfa_method', 'password_hash', 'password_changed_at',
    'password_expires_at', 'last_login', 'failed_login_count', 'locked_until',
    'updated_at', 'created_by', 'notes',
}
_ALLOWED_ROLE_COLS = {
    'name', 'description', 'permissions', 'risk_level', 'max_session_hours',
    'requires_mfa', 'updated_at',
}
_ALLOWED_POLICY_COLS = {
    'min_length', 'require_uppercase', 'require_lowercase', 'require_digits',
    'require_special', 'max_age_days', 'history_count', 'lockout_threshold',
    'lockout_duration_minutes', 'updated_at',
}


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except Exception:
        return False


def _validate_cols(cols: set, allowed: set, entity: str):
    """Raise ValueError if any column name is not in the allowed set."""
    unknown = cols - allowed
    if unknown:
        raise ValueError(f"Invalid {entity} column(s): {', '.join(sorted(unknown))}")


def get_db_path():
    """Get the database path in user's app data directory."""
    if os.name == 'nt':
        base = os.environ.get('LOCALAPPDATA', os.path.expanduser('~'))
    else:
        base = os.path.expanduser('~/.local/share')
    db_dir = os.path.join(base, 'SecureAccess')
    os.makedirs(db_dir, exist_ok=True)
    return os.path.join(db_dir, 'secureaccess.db')


class Database:
    def __init__(self, db_path=None):
        self.db_path = db_path or get_db_path()
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._create_tables()
        self._seed_defaults()

    def _create_tables(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                permissions TEXT DEFAULT '{}',
                risk_level TEXT DEFAULT 'low' CHECK(risk_level IN ('low','medium','high','critical')),
                max_session_hours INTEGER DEFAULT 8,
                requires_mfa INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                display_name TEXT NOT NULL,
                email TEXT,
                department TEXT,
                title TEXT,
                status TEXT DEFAULT 'active' CHECK(status IN ('active','inactive','locked','pending_review')),
                mfa_enabled INTEGER DEFAULT 0,
                mfa_method TEXT,
                password_hash TEXT,
                password_changed_at TEXT,
                password_expires_at TEXT,
                last_login TEXT,
                failed_login_count INTEGER DEFAULT 0,
                locked_until TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now')),
                created_by TEXT,
                notes TEXT
            );

            CREATE TABLE IF NOT EXISTS user_roles (
                user_id INTEGER NOT NULL,
                role_id INTEGER NOT NULL,
                granted_at TEXT DEFAULT (datetime('now')),
                granted_by TEXT,
                expires_at TEXT,
                justification TEXT,
                PRIMARY KEY (user_id, role_id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS access_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                role_id INTEGER NOT NULL,
                request_type TEXT DEFAULT 'grant' CHECK(request_type IN ('grant','revoke','modify')),
                status TEXT DEFAULT 'pending' CHECK(status IN ('pending','approved','denied','expired')),
                justification TEXT,
                requested_at TEXT DEFAULT (datetime('now')),
                reviewed_at TEXT,
                reviewed_by TEXT,
                review_notes TEXT,
                expires_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (role_id) REFERENCES roles(id)
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT DEFAULT (datetime('now')),
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target_type TEXT,
                target_id INTEGER,
                target_name TEXT,
                details TEXT,
                ip_address TEXT,
                severity TEXT DEFAULT 'info' CHECK(severity IN ('info','warning','critical'))
            );

            CREATE TABLE IF NOT EXISTS password_policy (
                id INTEGER PRIMARY KEY CHECK(id = 1),
                min_length INTEGER DEFAULT 12,
                require_uppercase INTEGER DEFAULT 1,
                require_lowercase INTEGER DEFAULT 1,
                require_digits INTEGER DEFAULT 1,
                require_special INTEGER DEFAULT 1,
                max_age_days INTEGER DEFAULT 90,
                history_count INTEGER DEFAULT 12,
                lockout_threshold INTEGER DEFAULT 5,
                lockout_duration_minutes INTEGER DEFAULT 30,
                updated_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS access_reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                status TEXT DEFAULT 'open' CHECK(status IN ('open','in_progress','completed','cancelled')),
                created_at TEXT DEFAULT (datetime('now')),
                due_date TEXT,
                completed_at TEXT,
                reviewer TEXT,
                notes TEXT
            );

            CREATE TABLE IF NOT EXISTS review_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                review_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                role_id INTEGER NOT NULL,
                decision TEXT CHECK(decision IN ('certify','revoke','modify', NULL)),
                decided_at TEXT,
                notes TEXT,
                FOREIGN KEY (review_id) REFERENCES access_reviews(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (role_id) REFERENCES roles(id)
            );
        """)
        self.conn.commit()

    def _seed_defaults(self):
        """Seed default data if tables are empty."""
        cursor = self.conn.execute("SELECT COUNT(*) FROM roles")
        if cursor.fetchone()[0] == 0:
            default_roles = [
                ('Administrator', 'Full system access', '{"all": true}', 'critical', 4, 1),
                ('Security Analyst', 'Security monitoring and incident response', '{"security": true, "read_logs": true}', 'high', 8, 1),
                ('Help Desk', 'Password resets and basic user support', '{"reset_password": true, "view_users": true}', 'medium', 8, 0),
                ('Auditor', 'Read-only access to all logs and reports', '{"read_all": true, "export": true}', 'high', 8, 1),
                ('Standard User', 'Basic application access', '{"read_own": true}', 'low', 8, 0),
                ('Privileged User', 'Elevated access for specific tasks', '{"read_all": true, "write_own": true}', 'medium', 6, 1),
                ('Service Account', 'Automated system processes', '{"api_access": true}', 'high', 24, 0),
            ]
            self.conn.executemany(
                "INSERT INTO roles (name, description, permissions, risk_level, max_session_hours, requires_mfa) VALUES (?,?,?,?,?,?)",
                default_roles
            )

        cursor = self.conn.execute("SELECT COUNT(*) FROM password_policy")
        if cursor.fetchone()[0] == 0:
            self.conn.execute("INSERT INTO password_policy (id) VALUES (1)")

        cursor = self.conn.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            sample_users = [
                ('admin', 'System Administrator', 'admin@company.com', 'IT Security', 'CISO', 'active', 1, 'authenticator'),
                ('jsmith', 'John Smith', 'jsmith@company.com', 'Engineering', 'Senior Developer', 'active', 1, 'authenticator'),
                ('mjones', 'Maria Jones', 'mjones@company.com', 'HR', 'HR Manager', 'active', 0, None),
                ('bwilson', 'Bob Wilson', 'bwilson@company.com', 'Finance', 'Financial Analyst', 'active', 1, 'sms'),
                ('alee', 'Alice Lee', 'alee@company.com', 'IT Security', 'Security Analyst', 'active', 1, 'authenticator'),
                ('tgarcia', 'Tom Garcia', 'tgarcia@company.com', 'Engineering', 'DevOps Engineer', 'active', 1, 'hardware_key'),
                ('kpatel', 'Kavita Patel', 'kpatel@company.com', 'Legal', 'Compliance Officer', 'active', 1, 'authenticator'),
                ('dkim', 'David Kim', 'dkim@company.com', 'Marketing', 'Marketing Specialist', 'inactive', 0, None),
                ('svc_backup', 'Backup Service', 'ops@company.com', 'IT', 'Service Account', 'active', 0, None),
                ('rchen', 'Rachel Chen', 'rchen@company.com', 'Engineering', 'Junior Developer', 'pending_review', 0, None),
            ]
            for u in sample_users:
                self.conn.execute(
                    "INSERT INTO users (username, display_name, email, department, title, status, mfa_enabled, mfa_method) VALUES (?,?,?,?,?,?,?,?)",
                    u
                )
            # Assign some roles
            role_assignments = [
                (1, 1, 'System setup'), (2, 5, 'Standard access'), (2, 6, 'Project needs'),
                (3, 5, 'Standard access'), (4, 5, 'Standard access'), (5, 2, 'Security team'),
                (5, 4, 'Audit duties'), (6, 5, 'Standard access'), (6, 6, 'Infrastructure work'),
                (7, 4, 'Compliance review'), (8, 5, 'Standard access'), (9, 7, 'Automated backups'),
                (10, 5, 'Onboarding'),
            ]
            for uid, rid, just in role_assignments:
                self.conn.execute(
                    "INSERT INTO user_roles (user_id, role_id, granted_by, justification) VALUES (?, ?, 'system', ?)",
                    (uid, rid, just)
                )
            # Sample audit entries
            audit_entries = [
                ('system', 'SYSTEM_INIT', 'system', None, 'System', 'Database initialized with default configuration', 'info'),
                ('admin', 'USER_LOGIN', 'user', 1, 'admin', 'Successful login', 'info'),
                ('admin', 'ROLE_GRANTED', 'user', 5, 'alee', 'Granted Security Analyst role', 'info'),
                ('admin', 'PASSWORD_POLICY_UPDATED', 'policy', 1, 'Password Policy', 'Min length changed to 14', 'warning'),
                ('admin', 'USER_LOCKED', 'user', 8, 'dkim', 'Account locked due to inactivity', 'warning'),
                ('system', 'ACCESS_REVIEW_CREATED', 'review', 1, 'Q1 2026 Review', 'Quarterly access review initiated', 'info'),
            ]
            for actor, action, ttype, tid, tname, details, severity in audit_entries:
                self.conn.execute(
                    "INSERT INTO audit_log (actor, action, target_type, target_id, target_name, details, severity) VALUES (?,?,?,?,?,?,?)",
                    (actor, action, ttype, tid, tname, details, severity)
                )

        self.conn.commit()

    # ── User CRUD ──
    def get_users(self, status_filter=None, search=None):
        query = "SELECT * FROM users WHERE 1=1"
        params = []
        if status_filter and status_filter != 'all':
            query += " AND status = ?"
            params.append(status_filter)
        if search:
            query += " AND (username LIKE ? OR display_name LIKE ? OR email LIKE ? OR department LIKE ?)"
            s = f"%{search}%"
            params.extend([s, s, s, s])
        query += " ORDER BY display_name"
        return self.conn.execute(query, params).fetchall()

    def get_user(self, user_id):
        return self.conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    def create_user(self, **kwargs):
        # Hash plaintext password if provided
        if 'password' in kwargs:
            kwargs['password_hash'] = hash_password(kwargs.pop('password'))
        _validate_cols(set(kwargs.keys()), _ALLOWED_USER_COLS, 'user')
        cols = ', '.join(kwargs.keys())
        placeholders = ', '.join(['?'] * len(kwargs))
        self.conn.execute(f"INSERT INTO users ({cols}) VALUES ({placeholders})", list(kwargs.values()))
        self.conn.commit()
        self.log_audit('admin', 'USER_CREATED', 'user', self.conn.execute("SELECT last_insert_rowid()").fetchone()[0],
                       kwargs.get('username', ''), f"User {kwargs.get('display_name')} created")

    def update_user(self, user_id, **kwargs):
        # Hash plaintext password if provided
        if 'password' in kwargs:
            kwargs['password_hash'] = hash_password(kwargs.pop('password'))
        kwargs['updated_at'] = datetime.now().isoformat()
        _validate_cols(set(kwargs.keys()), _ALLOWED_USER_COLS, 'user')
        sets = ', '.join(f"{k} = ?" for k in kwargs.keys())
        self.conn.execute(f"UPDATE users SET {sets} WHERE id = ?", list(kwargs.values()) + [user_id])
        self.conn.commit()

    def delete_user(self, user_id):
        user = self.get_user(user_id)
        if user:
            self.log_audit('admin', 'USER_DELETED', 'user', user_id, user['username'], f"User {user['display_name']} deleted")
        self.conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        self.conn.commit()

    # ── Role CRUD ──
    def get_roles(self):
        return self.conn.execute("SELECT * FROM roles ORDER BY name").fetchall()

    def get_role(self, role_id):
        return self.conn.execute("SELECT * FROM roles WHERE id = ?", (role_id,)).fetchone()

    def create_role(self, **kwargs):
        _validate_cols(set(kwargs.keys()), _ALLOWED_ROLE_COLS, 'role')
        cols = ', '.join(kwargs.keys())
        placeholders = ', '.join(['?'] * len(kwargs))
        self.conn.execute(f"INSERT INTO roles ({cols}) VALUES ({placeholders})", list(kwargs.values()))
        self.conn.commit()

    def update_role(self, role_id, **kwargs):
        kwargs['updated_at'] = datetime.now().isoformat()
        _validate_cols(set(kwargs.keys()), _ALLOWED_ROLE_COLS, 'role')
        sets = ', '.join(f"{k} = ?" for k in kwargs.keys())
        self.conn.execute(f"UPDATE roles SET {sets} WHERE id = ?", list(kwargs.values()) + [role_id])
        self.conn.commit()

    def delete_role(self, role_id):
        self.conn.execute("DELETE FROM roles WHERE id = ?", (role_id,))
        self.conn.commit()

    # ── User-Role assignments ──
    def get_user_roles(self, user_id):
        return self.conn.execute("""
            SELECT r.*, ur.granted_at, ur.granted_by, ur.expires_at, ur.justification
            FROM roles r JOIN user_roles ur ON r.id = ur.role_id
            WHERE ur.user_id = ? ORDER BY r.name
        """, (user_id,)).fetchall()

    def get_role_users(self, role_id):
        return self.conn.execute("""
            SELECT u.*, ur.granted_at, ur.granted_by, ur.expires_at
            FROM users u JOIN user_roles ur ON u.id = ur.user_id
            WHERE ur.role_id = ? ORDER BY u.display_name
        """, (role_id,)).fetchall()

    def assign_role(self, user_id, role_id, granted_by='admin', justification=''):
        self.conn.execute(
            "INSERT OR REPLACE INTO user_roles (user_id, role_id, granted_by, justification) VALUES (?,?,?,?)",
            (user_id, role_id, granted_by, justification)
        )
        self.conn.commit()
        user = self.get_user(user_id)
        role = self.get_role(role_id)
        self.log_audit(granted_by, 'ROLE_GRANTED', 'user', user_id,
                       user['username'] if user else '', f"Granted role: {role['name'] if role else role_id}")

    def revoke_role(self, user_id, role_id, revoked_by='admin'):
        self.conn.execute("DELETE FROM user_roles WHERE user_id = ? AND role_id = ?", (user_id, role_id))
        self.conn.commit()
        user = self.get_user(user_id)
        role = self.get_role(role_id)
        self.log_audit(revoked_by, 'ROLE_REVOKED', 'user', user_id,
                       user['username'] if user else '', f"Revoked role: {role['name'] if role else role_id}")

    # ── Access Requests ──
    def get_access_requests(self, status_filter=None):
        query = """
            SELECT ar.*, u.display_name as user_name, u.username, r.name as role_name
            FROM access_requests ar
            JOIN users u ON ar.user_id = u.id
            JOIN roles r ON ar.role_id = r.id
        """
        params = []
        if status_filter and status_filter != 'all':
            query += " WHERE ar.status = ?"
            params.append(status_filter)
        query += " ORDER BY ar.requested_at DESC"
        return self.conn.execute(query, params).fetchall()

    def create_access_request(self, user_id, role_id, request_type='grant', justification=''):
        self.conn.execute(
            "INSERT INTO access_requests (user_id, role_id, request_type, justification) VALUES (?,?,?,?)",
            (user_id, role_id, request_type, justification)
        )
        self.conn.commit()

    def review_access_request(self, request_id, status, reviewed_by, notes=''):
        self.conn.execute(
            "UPDATE access_requests SET status=?, reviewed_at=datetime('now'), reviewed_by=?, review_notes=? WHERE id=?",
            (status, reviewed_by, notes, request_id)
        )
        self.conn.commit()

    # ── Audit Log ──
    def log_audit(self, actor, action, target_type=None, target_id=None, target_name=None, details=None, severity='info'):
        self.conn.execute(
            "INSERT INTO audit_log (actor, action, target_type, target_id, target_name, details, severity) VALUES (?,?,?,?,?,?,?)",
            (actor, action, target_type, target_id, target_name, details, severity)
        )
        self.conn.commit()

    def get_audit_log(self, limit=100, severity_filter=None, search=None):
        query = "SELECT * FROM audit_log WHERE 1=1"
        params = []
        if severity_filter and severity_filter != 'all':
            query += " AND severity = ?"
            params.append(severity_filter)
        if search:
            query += " AND (actor LIKE ? OR action LIKE ? OR target_name LIKE ? OR details LIKE ?)"
            s = f"%{search}%"
            params.extend([s, s, s, s])
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        return self.conn.execute(query, params).fetchall()

    # ── Password Policy ──
    def get_password_policy(self):
        return self.conn.execute("SELECT * FROM password_policy WHERE id = 1").fetchone()

    def update_password_policy(self, **kwargs):
        kwargs['updated_at'] = datetime.now().isoformat()
        _validate_cols(set(kwargs.keys()), _ALLOWED_POLICY_COLS, 'password_policy')
        sets = ', '.join(f"{k} = ?" for k in kwargs.keys())
        self.conn.execute(f"UPDATE password_policy SET {sets} WHERE id = 1", list(kwargs.values()))
        self.conn.commit()
        self.log_audit('admin', 'PASSWORD_POLICY_UPDATED', 'policy', 1, 'Password Policy',
                       json.dumps(kwargs), 'warning')

    # ── Dashboard Stats ──
    def get_dashboard_stats(self):
        stats = {}
        stats['total_users'] = self.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        stats['active_users'] = self.conn.execute("SELECT COUNT(*) FROM users WHERE status='active'").fetchone()[0]
        stats['inactive_users'] = self.conn.execute("SELECT COUNT(*) FROM users WHERE status='inactive'").fetchone()[0]
        stats['locked_users'] = self.conn.execute("SELECT COUNT(*) FROM users WHERE status='locked'").fetchone()[0]
        stats['pending_review'] = self.conn.execute("SELECT COUNT(*) FROM users WHERE status='pending_review'").fetchone()[0]
        stats['total_roles'] = self.conn.execute("SELECT COUNT(*) FROM roles").fetchone()[0]
        stats['mfa_enabled'] = self.conn.execute("SELECT COUNT(*) FROM users WHERE mfa_enabled=1 AND status='active'").fetchone()[0]
        stats['mfa_disabled'] = stats['active_users'] - stats['mfa_enabled']
        stats['pending_requests'] = self.conn.execute("SELECT COUNT(*) FROM access_requests WHERE status='pending'").fetchone()[0]
        stats['critical_roles'] = self.conn.execute("SELECT COUNT(*) FROM roles WHERE risk_level='critical'").fetchone()[0]
        stats['high_risk_roles'] = self.conn.execute("SELECT COUNT(*) FROM roles WHERE risk_level='high'").fetchone()[0]
        stats['recent_audit_warnings'] = self.conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE severity IN ('warning','critical') AND timestamp > datetime('now', '-7 days')"
        ).fetchone()[0]
        stats['departments'] = self.conn.execute(
            "SELECT department, COUNT(*) as count FROM users WHERE status='active' GROUP BY department ORDER BY count DESC"
        ).fetchall()
        stats['role_distribution'] = self.conn.execute("""
            SELECT r.name, r.risk_level, COUNT(ur.user_id) as user_count
            FROM roles r LEFT JOIN user_roles ur ON r.id = ur.role_id
            GROUP BY r.id ORDER BY user_count DESC
        """).fetchall()
        return stats

    # ── Access Reviews ──
    def create_access_review(self, name, due_date=None, reviewer=None):
        self.conn.execute(
            "INSERT INTO access_reviews (name, due_date, reviewer) VALUES (?,?,?)",
            (name, due_date, reviewer)
        )
        review_id = self.conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        # Auto-populate with all current user-role assignments
        assignments = self.conn.execute("SELECT user_id, role_id FROM user_roles").fetchall()
        for a in assignments:
            self.conn.execute(
                "INSERT INTO review_items (review_id, user_id, role_id) VALUES (?,?,?)",
                (review_id, a['user_id'], a['role_id'])
            )
        self.conn.commit()
        self.log_audit('admin', 'ACCESS_REVIEW_CREATED', 'review', review_id, name,
                       f"Review created with {len(assignments)} items")
        return review_id

    def get_access_reviews(self):
        return self.conn.execute("SELECT * FROM access_reviews ORDER BY created_at DESC").fetchall()

    def get_review_items(self, review_id):
        return self.conn.execute("""
            SELECT ri.*, u.display_name as user_name, u.username, u.department,
                   r.name as role_name, r.risk_level
            FROM review_items ri
            JOIN users u ON ri.user_id = u.id
            JOIN roles r ON ri.role_id = r.id
            WHERE ri.review_id = ?
            ORDER BY r.risk_level DESC, u.display_name
        """, (review_id,)).fetchall()

    def close(self):
        self.conn.close()

