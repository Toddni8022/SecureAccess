# API Reference — SecureAccess

## Database API

The `Database` class (defined in `database.py`) provides the complete data access layer for SecureAccess. It wraps SQLite via the standard library `sqlite3` module.

### Instantiation

```python
from database import Database

# Default path (OS app data directory)
db = Database()

# Custom path (useful for testing)
db = Database(db_path="/path/to/custom.db")
```

On initialization, `Database`:
1. Opens (or creates) the SQLite file at `db_path`
2. Enables WAL journal mode and foreign key enforcement
3. Creates all tables if they do not exist
4. Seeds default roles, users, and password policy if empty

---

### `get_db_path() -> str`

Returns the platform-appropriate default database path:

- **Windows:** `%LOCALAPPDATA%\SecureAccess\secureaccess.db`
- **macOS / Linux:** `~/.local/share/SecureAccess/secureaccess.db`

The directory is created automatically if it does not exist.

---

### User Methods

#### `get_users(status_filter=None, search=None) -> list[sqlite3.Row]`

Returns a list of all users, optionally filtered.

| Parameter | Type | Description |
|-----------|------|-------------|
| `status_filter` | `str \| None` | Filter by `active`, `inactive`, `locked`, `pending_review` |
| `search` | `str \| None` | Case-insensitive search on username, display_name, email |

Each row contains: `id`, `username`, `display_name`, `email`, `department`, `title`, `status`, `mfa_enabled`, `mfa_method`, `last_login`, `created_at`, `updated_at`, `notes`.

---

#### `create_user(**kwargs) -> int`

Creates a new user and returns the new user's `id`.

| Keyword Argument | Type | Required | Description |
|-----------------|------|----------|-------------|
| `username` | `str` | Yes | Unique login name |
| `display_name` | `str` | Yes | Full name |
| `email` | `str` | Yes | Email address |
| `department` | `str` | No | Department name |
| `title` | `str` | No | Job title |
| `status` | `str` | No | `active` (default) |
| `mfa_enabled` | `int` | No | `0` or `1` |
| `mfa_method` | `str\|None` | No | `authenticator`, `sms`, `hardware_key`, `email` |
| `notes` | `str` | No | Free-form notes |

---

#### `update_user(user_id, **kwargs) -> None`

Updates fields for an existing user. Pass only the fields to change.

---

#### `delete_user(user_id) -> None`

Deletes a user by ID. Cascades to `user_roles`.

---

### Role Methods

#### `get_roles() -> list[sqlite3.Row]`

Returns all roles. Each row contains: `id`, `name`, `description`, `permissions`, `risk_level`, `max_session_hours`, `requires_mfa`, `created_at`, `updated_at`.

---

#### `create_role(**kwargs) -> int`

Creates a new role and returns its `id`.

| Keyword Argument | Type | Description |
|-----------------|------|-------------|
| `name` | `str` | Unique role name |
| `description` | `str` | Human-readable description |
| `permissions` | `str` | JSON-encoded permissions object |
| `risk_level` | `str` | `low`, `medium`, `high`, `critical` |
| `max_session_hours` | `int` | Maximum session length |
| `requires_mfa` | `int` | `0` or `1` |

---

#### `update_role(role_id, **kwargs) -> None`

Updates fields for an existing role.

---

#### `delete_role(role_id) -> None`

Deletes a role by ID. Cascades to `user_roles`.

---

### Access Request Methods

#### `get_access_requests(status_filter=None) -> list[sqlite3.Row]`

Returns access requests. Each row contains: `id`, `requester`, `target_user`, `role_name`, `request_type`, `status`, `justification`, `reviewer`, `review_notes`, `created_at`, `updated_at`.

---

#### `create_access_request(**kwargs) -> int`

Creates a new access request.

| Keyword Argument | Type | Description |
|-----------------|------|-------------|
| `requester` | `str` | Username of the requester |
| `target_user` | `str` | Username of the user being granted/revoked access |
| `role_name` | `str` | Name of the role |
| `request_type` | `str` | `grant` or `revoke` |
| `justification` | `str` | Business justification |

---

#### `update_access_request(request_id, **kwargs) -> None`

Updates an access request (e.g., to approve or deny).

---

### Audit Log Methods

#### `get_audit_log(limit=100, severity_filter=None, search=None) -> list[sqlite3.Row]`

Returns audit log entries, most recent first.

| Parameter | Type | Description |
|-----------|------|-------------|
| `limit` | `int` | Maximum number of entries to return |
| `severity_filter` | `str\|None` | Filter by `info`, `warning`, `critical` |
| `search` | `str\|None` | Full-text search across actor, action, target, details |

---

#### `log_action(actor, action, target, details='', severity='info', ip_address=None) -> None`

Appends an entry to the audit log.

---

### Password Policy Methods

#### `get_password_policy() -> sqlite3.Row | None`

Returns the active password policy row (id=1).

---

#### `update_password_policy(**kwargs) -> None`

Updates password policy fields. Supported fields: `min_length`, `require_uppercase`, `require_lowercase`, `require_digits`, `require_special`, `max_age_days`, `history_count`, `lockout_threshold`, `lockout_duration_minutes`.

---

## Connector API

All connectors inherit from `BaseConnector` (defined in `connectors.py`).

### Class Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `name` | `str` | Unique machine-readable identifier |
| `display_name` | `str` | Human-readable name |
| `icon` | `str` | Emoji icon |
| `description` | `str` | Short description |
| `config_fields` | `list[dict]` | Configuration field definitions for the UI |

### Constructor

```python
connector = ActiveDirectoryConnector(config={
    "server": "dc01.corp.example.com",
    "port": "389",
    "base_dn": "DC=corp,DC=example,DC=com",
})
```

### Methods

#### `test_connection() -> ProvisioningResult`

Tests connectivity to the target system. Returns a `ProvisioningResult` indicating success or failure.

---

#### `create_user(username, display_name, email, **kwargs) -> ProvisioningResult`

Provisions a new user in the target system.

---

#### `disable_user(username) -> ProvisioningResult`

Disables (suspends) a user account in the target system.

---

#### `enable_user(username) -> ProvisioningResult`

Re-enables a previously disabled user account.

---

#### `delete_user(username) -> ProvisioningResult`

Permanently removes a user from the target system.

---

#### `assign_group(username, group_name) -> ProvisioningResult`

Adds a user to a group or role in the target system.

---

#### `remove_group(username, group_name) -> ProvisioningResult`

Removes a user from a group or role.

---

#### `reset_password(username) -> ProvisioningResult`

Triggers a password reset for the user.

---

### `ProvisioningResult`

A dataclass returned by all connector operations.

```python
@dataclass
class ProvisioningResult:
    success: bool          # Whether the operation succeeded
    connector: str         # Connector name (e.g., "active_directory")
    action: str            # Action performed (e.g., "create_user")
    target_user: str       # Username targeted
    details: str           # Human-readable result details
    timestamp: str         # ISO 8601 timestamp (auto-set)
    error: str | None      # Error message if success=False
    remote_id: str | None  # Remote object ID if applicable
```

#### `to_dict() -> dict`

Serializes the result to a plain dictionary (useful for audit logging).

---

### `ConnectorManager`

Manages the lifecycle of all configured connectors.

```python
from database import Database
from connectors import ConnectorManager

db = Database()
mgr = ConnectorManager(db)
```

#### `provision_user(username, display_name, email, **kwargs) -> list[ProvisioningResult]`

Provisions a user across all enabled connectors. Returns a list of results, one per connector.

---

## Data Models

### User

Stored in the `users` SQLite table.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment primary key |
| username | TEXT UNIQUE | Login identifier |
| display_name | TEXT | Full display name |
| email | TEXT | Email address |
| department | TEXT | Department |
| title | TEXT | Job title |
| status | TEXT | `active`, `inactive`, `locked`, `pending_review` |
| mfa_enabled | INTEGER | 0 or 1 |
| mfa_method | TEXT | `authenticator`, `sms`, `hardware_key`, `email` |
| last_login | TEXT | ISO 8601 datetime |
| created_at | TEXT | ISO 8601 datetime |
| updated_at | TEXT | ISO 8601 datetime |
| notes | TEXT | Free-form notes |

### Role

Stored in the `roles` SQLite table.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment primary key |
| name | TEXT UNIQUE | Role name |
| description | TEXT | Description |
| permissions | TEXT | JSON-encoded permissions |
| risk_level | TEXT | `low`, `medium`, `high`, `critical` |
| max_session_hours | INTEGER | Maximum session duration |
| requires_mfa | INTEGER | 0 or 1 |
| created_at | TEXT | ISO 8601 datetime |
| updated_at | TEXT | ISO 8601 datetime |

### AccessRequest

Stored in the `access_requests` SQLite table.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| requester | TEXT | Username of requester |
| target_user | TEXT | Username of target |
| role_name | TEXT | Role being requested |
| request_type | TEXT | `grant` or `revoke` |
| status | TEXT | `pending`, `approved`, `denied` |
| justification | TEXT | Business justification |
| reviewer | TEXT | Username of reviewer |
| review_notes | TEXT | Reviewer comments |
| created_at | TEXT | ISO 8601 datetime |
| updated_at | TEXT | ISO 8601 datetime |

### AuditLog

Stored in the `audit_log` SQLite table.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| timestamp | TEXT | ISO 8601 UTC datetime |
| actor | TEXT | User who performed the action |
| action | TEXT | Action code (e.g., `create_user`) |
| target | TEXT | Affected entity |
| details | TEXT | JSON or plain-text context |
| severity | TEXT | `info`, `warning`, `critical` |
| ip_address | TEXT | Source IP address |

### PasswordPolicy

Stored in the `password_policy` SQLite table (single row, id=1).

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| min_length | INTEGER | 12 | Minimum password length |
| require_uppercase | INTEGER | 1 | Require uppercase letters |
| require_lowercase | INTEGER | 1 | Require lowercase letters |
| require_digits | INTEGER | 1 | Require digits |
| require_special | INTEGER | 1 | Require special characters |
| max_age_days | INTEGER | 90 | Days before password expires |
| history_count | INTEGER | 12 | Password history count |
| lockout_threshold | INTEGER | 5 | Failed attempts before lockout |
| lockout_duration_minutes | INTEGER | 30 | Lockout duration |
