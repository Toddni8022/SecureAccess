"""
SecureAccess - System Connectors
Integration modules for provisioning access to external systems.
Each connector handles user lifecycle and role management for its target platform.
"""

import json
import time
import random
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class ProvisioningResult:
    """Result of a provisioning operation."""
    success: bool
    connector: str
    action: str
    target_user: str
    details: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    error: Optional[str] = None
    remote_id: Optional[str] = None

    def to_dict(self):
        return asdict(self)


class BaseConnector:
    """Base class for all system connectors."""

    name = "base"
    display_name = "Base Connector"
    icon = "🔌"
    description = "Base connector"
    status = "disconnected"
    config_fields = []

    def __init__(self, config=None):
        self.config = config or {}
        self.connected = False
        self.last_sync = None
        self.provision_log = []

    def test_connection(self) -> ProvisioningResult:
        """Test connectivity to the target system."""
        raise NotImplementedError

    def connect(self) -> bool:
        """Establish connection."""
        result = self.test_connection()
        self.connected = result.success
        self.status = "connected" if result.success else "error"
        return result.success

    def disconnect(self):
        self.connected = False
        self.status = "disconnected"

    def create_user(self, username, display_name, email, **kwargs) -> ProvisioningResult:
        raise NotImplementedError

    def disable_user(self, username) -> ProvisioningResult:
        raise NotImplementedError

    def enable_user(self, username) -> ProvisioningResult:
        raise NotImplementedError

    def delete_user(self, username) -> ProvisioningResult:
        raise NotImplementedError

    def assign_group(self, username, group_name) -> ProvisioningResult:
        raise NotImplementedError

    def remove_group(self, username, group_name) -> ProvisioningResult:
        raise NotImplementedError

    def reset_password(self, username) -> ProvisioningResult:
        raise NotImplementedError

    def get_status_info(self) -> dict:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "icon": self.icon,
            "status": self.status,
            "connected": self.connected,
            "last_sync": self.last_sync,
            "config": {k: "***" if "password" in k.lower() or "secret" in k.lower() or "key" in k.lower()
                       else v for k, v in self.config.items()}
        }

    def _simulate_latency(self):
        """Simulate network latency for demo purposes."""
        time.sleep(random.uniform(0.1, 0.4))

    def _log(self, result: ProvisioningResult):
        self.provision_log.append(result)
        return result


# ══════════════════════════════════════════════
#  ACTIVE DIRECTORY / LDAP
# ══════════════════════════════════════════════
class ActiveDirectoryConnector(BaseConnector):
    name = "active_directory"
    display_name = "Active Directory / LDAP"
    icon = "🏢"
    description = "Microsoft Active Directory or OpenLDAP for centralized identity management"
    config_fields = [
        {"key": "server", "label": "Domain Controller", "placeholder": "dc01.corp.example.com", "type": "text"},
        {"key": "port", "label": "Port", "placeholder": "389 (LDAP) or 636 (LDAPS)", "type": "text"},
        {"key": "use_ssl", "label": "Use LDAPS (SSL)", "type": "checkbox"},
        {"key": "base_dn", "label": "Base DN", "placeholder": "DC=corp,DC=example,DC=com", "type": "text"},
        {"key": "bind_user", "label": "Bind User (DN)", "placeholder": "CN=svc_secureaccess,OU=Service Accounts,DC=corp,DC=example,DC=com", "type": "text"},
        {"key": "bind_password", "label": "Bind Password", "placeholder": "••••••••", "type": "password"},
        {"key": "user_ou", "label": "Users OU", "placeholder": "OU=Users,DC=corp,DC=example,DC=com", "type": "text"},
        {"key": "group_ou", "label": "Groups OU", "placeholder": "OU=Groups,DC=corp,DC=example,DC=com", "type": "text"},
    ]

    def test_connection(self):
        self._simulate_latency()
        server = self.config.get("server", "")
        if not server:
            return self._log(ProvisioningResult(False, self.name, "test_connection", "",
                             "No server configured", error="Missing server address"))
        port = self.config.get("port", "389")
        ssl = "LDAPS" if self.config.get("use_ssl") else "LDAP"
        return self._log(ProvisioningResult(True, self.name, "test_connection", "",
                         f"Connected to {server}:{port} via {ssl} | Base DN: {self.config.get('base_dn', 'N/A')}",
                         remote_id=f"ldap://{server}:{port}"))

    def create_user(self, username, display_name, email, **kwargs):
        self._simulate_latency()
        ou = self.config.get("user_ou", "OU=Users,DC=corp,DC=example,DC=com")
        dn = f"CN={display_name},{ou}"
        return self._log(ProvisioningResult(True, self.name, "create_user", username,
                         f"Created AD account | DN: {dn} | sAMAccountName: {username} | mail: {email} | "
                         f"userAccountControl: 512 (NORMAL_ACCOUNT) | pwdLastSet: 0 (must change)",
                         remote_id=dn))

    def disable_user(self, username):
        self._simulate_latency()
        return self._log(ProvisioningResult(True, self.name, "disable_user", username,
                         f"Disabled AD account | sAMAccountName: {username} | "
                         f"userAccountControl: 514 (ACCOUNTDISABLE) | Moved to OU=Disabled Users"))

    def enable_user(self, username):
        self._simulate_latency()
        return self._log(ProvisioningResult(True, self.name, "enable_user", username,
                         f"Enabled AD account | sAMAccountName: {username} | userAccountControl: 512"))

    def delete_user(self, username):
        self._simulate_latency()
        return self._log(ProvisioningResult(True, self.name, "delete_user", username,
                         f"Deleted AD account | sAMAccountName: {username} | Object removed from directory"))

    def assign_group(self, username, group_name):
        self._simulate_latency()
        group_ou = self.config.get("group_ou", "OU=Groups,DC=corp,DC=example,DC=com")
        return self._log(ProvisioningResult(True, self.name, "assign_group", username,
                         f"Added to AD group | Group: CN={group_name},{group_ou} | "
                         f"Member: {username} | Type: Security Group"))

    def remove_group(self, username, group_name):
        self._simulate_latency()
        return self._log(ProvisioningResult(True, self.name, "remove_group", username,
                         f"Removed from AD group | Group: {group_name} | Member: {username}"))

    def reset_password(self, username):
        self._simulate_latency()
        return self._log(ProvisioningResult(True, self.name, "reset_password", username,
                         f"Password reset | sAMAccountName: {username} | pwdLastSet: 0 | Must change at next login"))


# ══════════════════════════════════════════════
#  AZURE AD / ENTRA ID
# ══════════════════════════════════════════════
class AzureADConnector(BaseConnector):
    name = "azure_ad"
    display_name = "Microsoft Entra ID (Azure AD)"
    icon = "☁️"
    description = "Cloud identity and access management via Microsoft Graph API"
    config_fields = [
        {"key": "tenant_id", "label": "Tenant ID", "placeholder": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", "type": "text"},
        {"key": "client_id", "label": "Application (Client) ID", "placeholder": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", "type": "text"},
        {"key": "client_secret", "label": "Client Secret", "placeholder": "••••••••", "type": "password"},
        {"key": "domain", "label": "Domain", "placeholder": "corp.onmicrosoft.com", "type": "text"},
    ]

    def _graph_id(self):
        return f"{random.randint(10000000, 99999999)}-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}-{random.randint(100000000000, 999999999999)}"

    def test_connection(self):
        self._simulate_latency()
        tenant = self.config.get("tenant_id", "")
        if not tenant:
            return self._log(ProvisioningResult(False, self.name, "test_connection", "",
                             "No tenant ID configured", error="Missing tenant_id"))
        return self._log(ProvisioningResult(True, self.name, "test_connection", "",
                         f"Authenticated to Microsoft Graph API | Tenant: {tenant} | "
                         f"Permissions: User.ReadWrite.All, Group.ReadWrite.All, Directory.ReadWrite.All",
                         remote_id=f"https://graph.microsoft.com/v1.0/{tenant}"))

    def create_user(self, username, display_name, email, **kwargs):
        self._simulate_latency()
        domain = self.config.get("domain", "corp.onmicrosoft.com")
        obj_id = self._graph_id()
        return self._log(ProvisioningResult(True, self.name, "create_user", username,
                         f"POST /users | UPN: {username}@{domain} | displayName: {display_name} | "
                         f"mail: {email} | accountEnabled: true | objectId: {obj_id}",
                         remote_id=obj_id))

    def disable_user(self, username):
        self._simulate_latency()
        return self._log(ProvisioningResult(True, self.name, "disable_user", username,
                         f"PATCH /users/{username} | accountEnabled: false | signInBlocked: true"))

    def enable_user(self, username):
        self._simulate_latency()
        return self._log(ProvisioningResult(True, self.name, "enable_user", username,
                         f"PATCH /users/{username} | accountEnabled: true | signInBlocked: false"))

    def delete_user(self, username):
        self._simulate_latency()
        return self._log(ProvisioningResult(True, self.name, "delete_user", username,
                         f"DELETE /users/{username} | Moved to deletedItems (recoverable for 30 days)"))

    def assign_group(self, username, group_name):
        self._simulate_latency()
        return self._log(ProvisioningResult(True, self.name, "assign_group", username,
                         f"POST /groups/{{groupId}}/members/$ref | Group: {group_name} | Member: {username}"))

    def remove_group(self, username, group_name):
        self._simulate_latency()
        return self._log(ProvisioningResult(True, self.name, "remove_group", username,
                         f"DELETE /groups/{{groupId}}/members/{username}/$ref | Group: {group_name}"))

    def reset_password(self, username):
        self._simulate_latency()
        return self._log(ProvisioningResult(True, self.name, "reset_password", username,
                         f"POST /users/{username}/authentication/methods/password | forceChangePasswordNextSignIn: true"))


# ══════════════════════════════════════════════
#  AWS IAM
# ══════════════════════════════════════════════
class AWSIAMConnector(BaseConnector):
    name = "aws_iam"
    display_name = "AWS IAM"
    icon = "🔶"
    description = "Amazon Web Services Identity and Access Management"
    config_fields = [
        {"key": "access_key_id", "label": "Access Key ID", "placeholder": "AKIAIOSFODNN7EXAMPLE", "type": "text"},
        {"key": "secret_access_key", "label": "Secret Access Key", "placeholder": "••••••••", "type": "password"},
        {"key": "region", "label": "Region", "placeholder": "us-east-1", "type": "text"},
        {"key": "account_id", "label": "Account ID", "placeholder": "123456789012", "type": "text"},
    ]

    def test_connection(self):
        self._simulate_latency()
        account = self.config.get("account_id", "")
        region = self.config.get("region", "us-east-1")
        if not self.config.get("access_key_id"):
            return self._log(ProvisioningResult(False, self.name, "test_connection", "",
                             "No credentials configured", error="Missing access_key_id"))
        return self._log(ProvisioningResult(True, self.name, "test_connection", "",
                         f"sts:GetCallerIdentity OK | Account: {account} | Region: {region} | "
                         f"ARN: arn:aws:iam::{account}:user/secureaccess-svc",
                         remote_id=f"arn:aws:iam::{account}"))

    def create_user(self, username, display_name, email, **kwargs):
        self._simulate_latency()
        account = self.config.get("account_id", "123456789012")
        return self._log(ProvisioningResult(True, self.name, "create_user", username,
                         f"iam:CreateUser | UserName: {username} | Path: /secureaccess/ | "
                         f"ARN: arn:aws:iam::{account}:user/secureaccess/{username} | "
                         f"Tags: DisplayName={display_name}, Email={email}",
                         remote_id=f"arn:aws:iam::{account}:user/secureaccess/{username}"))

    def disable_user(self, username):
        self._simulate_latency()
        return self._log(ProvisioningResult(True, self.name, "disable_user", username,
                         f"iam:DeleteLoginProfile | iam:ListAccessKeys → deactivated 1 key | "
                         f"Console access: disabled | API access: suspended"))

    def enable_user(self, username):
        self._simulate_latency()
        return self._log(ProvisioningResult(True, self.name, "enable_user", username,
                         f"iam:CreateLoginProfile | iam:UpdateAccessKey → activated | "
                         f"Console access: enabled | Password reset required"))

    def delete_user(self, username):
        self._simulate_latency()
        return self._log(ProvisioningResult(True, self.name, "delete_user", username,
                         f"iam:DeleteUser | Detached 2 policies | Removed from 1 group | "
                         f"Deleted 1 access key | Deleted login profile"))

    def assign_group(self, username, group_name):
        self._simulate_latency()
        return self._log(ProvisioningResult(True, self.name, "assign_group", username,
                         f"iam:AddUserToGroup | Group: {group_name} | User: {username} | "
                         f"Attached policies inherited from group"))

    def remove_group(self, username, group_name):
        self._simulate_latency()
        return self._log(ProvisioningResult(True, self.name, "remove_group", username,
                         f"iam:RemoveUserFromGroup | Group: {group_name} | User: {username}"))


# ══════════════════════════════════════════════
#  LINUX / PAM
# ══════════════════════════════════════════════
class LinuxConnector(BaseConnector):
    name = "linux"
    display_name = "Linux (SSH/PAM)"
    icon = "🐧"
    description = "Linux server user management via SSH — useradd, usermod, PAM integration"
    config_fields = [
        {"key": "hostname", "label": "Hostname / IP", "placeholder": "192.168.1.100", "type": "text"},
        {"key": "port", "label": "SSH Port", "placeholder": "22", "type": "text"},
        {"key": "ssh_user", "label": "SSH User", "placeholder": "root", "type": "text"},
        {"key": "ssh_key_path", "label": "SSH Private Key Path", "placeholder": "/path/to/id_rsa", "type": "text"},
        {"key": "sudo", "label": "Use sudo", "type": "checkbox"},
    ]

    def test_connection(self):
        self._simulate_latency()
        host = self.config.get("hostname", "")
        if not host:
            return self._log(ProvisioningResult(False, self.name, "test_connection", "",
                             "No hostname configured", error="Missing hostname"))
        port = self.config.get("port", "22")
        user = self.config.get("ssh_user", "root")
        return self._log(ProvisioningResult(True, self.name, "test_connection", "",
                         f"SSH connected to {user}@{host}:{port} | OS: Ubuntu 24.04 LTS | "
                         f"Kernel: 6.8.0-45-generic | PAM: configured",
                         remote_id=f"ssh://{user}@{host}:{port}"))

    def create_user(self, username, display_name, email, **kwargs):
        self._simulate_latency()
        prefix = "sudo " if self.config.get("sudo") else ""
        return self._log(ProvisioningResult(True, self.name, "create_user", username,
                         f"{prefix}useradd -m -c '{display_name}' -s /bin/bash {username} | "
                         f"Home: /home/{username} | Shell: /bin/bash | "
                         f"UID: {random.randint(1001, 9999)} | Password: locked (must set)"))

    def disable_user(self, username):
        self._simulate_latency()
        prefix = "sudo " if self.config.get("sudo") else ""
        return self._log(ProvisioningResult(True, self.name, "disable_user", username,
                         f"{prefix}usermod -L -e 1 {username} | Account locked | "
                         f"Shell changed to /sbin/nologin | Active sessions killed"))

    def enable_user(self, username):
        self._simulate_latency()
        prefix = "sudo " if self.config.get("sudo") else ""
        return self._log(ProvisioningResult(True, self.name, "enable_user", username,
                         f"{prefix}usermod -U -e '' -s /bin/bash {username} | Account unlocked"))

    def delete_user(self, username):
        self._simulate_latency()
        prefix = "sudo " if self.config.get("sudo") else ""
        return self._log(ProvisioningResult(True, self.name, "delete_user", username,
                         f"{prefix}userdel -r {username} | Home directory removed | "
                         f"Mail spool removed | crontab removed"))

    def assign_group(self, username, group_name):
        self._simulate_latency()
        prefix = "sudo " if self.config.get("sudo") else ""
        return self._log(ProvisioningResult(True, self.name, "assign_group", username,
                         f"{prefix}usermod -aG {group_name} {username} | "
                         f"Groups: {username} {group_name}"))

    def remove_group(self, username, group_name):
        self._simulate_latency()
        prefix = "sudo " if self.config.get("sudo") else ""
        return self._log(ProvisioningResult(True, self.name, "remove_group", username,
                         f"{prefix}gpasswd -d {username} {group_name} | Removed from group"))

    def reset_password(self, username):
        self._simulate_latency()
        prefix = "sudo " if self.config.get("sudo") else ""
        return self._log(ProvisioningResult(True, self.name, "reset_password", username,
                         f"{prefix}passwd -e {username} | Password expired | Must change at next login"))


# ══════════════════════════════════════════════
#  OKTA SSO
# ══════════════════════════════════════════════
class OktaConnector(BaseConnector):
    name = "okta"
    display_name = "Okta SSO"
    icon = "🔐"
    description = "Okta Identity Platform — SSO, MFA, and lifecycle management"
    config_fields = [
        {"key": "domain", "label": "Okta Domain", "placeholder": "corp.okta.com", "type": "text"},
        {"key": "api_token", "label": "API Token", "placeholder": "00xxxxxxxxxxxxxxxxxxx", "type": "password"},
    ]

    def _okta_id(self):
        return f"00u{''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=16))}"

    def test_connection(self):
        self._simulate_latency()
        domain = self.config.get("domain", "")
        if not domain:
            return self._log(ProvisioningResult(False, self.name, "test_connection", "",
                             "No Okta domain configured", error="Missing domain"))
        return self._log(ProvisioningResult(True, self.name, "test_connection", "",
                         f"Okta API authenticated | Domain: https://{domain} | "
                         f"Scopes: okta.users.manage, okta.groups.manage, okta.apps.manage",
                         remote_id=f"https://{domain}"))

    def create_user(self, username, display_name, email, **kwargs):
        self._simulate_latency()
        okta_id = self._okta_id()
        domain = self.config.get("domain", "corp.okta.com")
        names = display_name.split(" ", 1)
        first = names[0]
        last = names[1] if len(names) > 1 else names[0]
        return self._log(ProvisioningResult(True, self.name, "create_user", username,
                         f"POST /api/v1/users | login: {email} | firstName: {first} | lastName: {last} | "
                         f"email: {email} | status: STAGED | Activation email sent | id: {okta_id}",
                         remote_id=okta_id))

    def disable_user(self, username):
        self._simulate_latency()
        return self._log(ProvisioningResult(True, self.name, "disable_user", username,
                         f"POST /api/v1/users/{username}/lifecycle/suspend | "
                         f"Status: ACTIVE → SUSPENDED | All sessions revoked"))

    def enable_user(self, username):
        self._simulate_latency()
        return self._log(ProvisioningResult(True, self.name, "enable_user", username,
                         f"POST /api/v1/users/{username}/lifecycle/unsuspend | "
                         f"Status: SUSPENDED → ACTIVE"))

    def delete_user(self, username):
        self._simulate_latency()
        return self._log(ProvisioningResult(True, self.name, "delete_user", username,
                         f"POST /api/v1/users/{username}/lifecycle/deactivate | "
                         f"DELETE /api/v1/users/{username} | Status: DEPROVISIONED → DELETED"))

    def assign_group(self, username, group_name):
        self._simulate_latency()
        return self._log(ProvisioningResult(True, self.name, "assign_group", username,
                         f"PUT /api/v1/groups/{{groupId}}/users/{username} | "
                         f"Group: {group_name} | App assignments inherited"))

    def remove_group(self, username, group_name):
        self._simulate_latency()
        return self._log(ProvisioningResult(True, self.name, "remove_group", username,
                         f"DELETE /api/v1/groups/{{groupId}}/users/{username} | Group: {group_name}"))


# ══════════════════════════════════════════════
#  DATABASE (MySQL/PostgreSQL)
# ══════════════════════════════════════════════
class DatabaseConnector(BaseConnector):
    name = "database"
    display_name = "Database (MySQL/PostgreSQL)"
    icon = "🗄️"
    description = "Database user and privilege management — MySQL, PostgreSQL, Oracle"
    config_fields = [
        {"key": "db_type", "label": "Database Type", "placeholder": "mysql | postgresql | oracle", "type": "text"},
        {"key": "host", "label": "Host", "placeholder": "db.corp.example.com", "type": "text"},
        {"key": "port", "label": "Port", "placeholder": "3306 (MySQL) or 5432 (PostgreSQL)", "type": "text"},
        {"key": "admin_user", "label": "Admin User", "placeholder": "secureaccess_admin", "type": "text"},
        {"key": "admin_password", "label": "Admin Password", "placeholder": "••••••••", "type": "password"},
        {"key": "database", "label": "Database", "placeholder": "production", "type": "text"},
    ]

    def test_connection(self):
        self._simulate_latency()
        host = self.config.get("host", "")
        db_type = self.config.get("db_type", "mysql").upper()
        if not host:
            return self._log(ProvisioningResult(False, self.name, "test_connection", "",
                             "No host configured", error="Missing host"))
        port = self.config.get("port", "3306")
        db = self.config.get("database", "production")
        return self._log(ProvisioningResult(True, self.name, "test_connection", "",
                         f"Connected to {db_type} | Host: {host}:{port} | Database: {db} | "
                         f"Server version: {'8.0.36' if 'mysql' in db_type.lower() else '16.2'} | SSL: enabled",
                         remote_id=f"{db_type.lower()}://{host}:{port}/{db}"))

    def create_user(self, username, display_name, email, **kwargs):
        self._simulate_latency()
        db_type = self.config.get("db_type", "mysql").lower()
        db = self.config.get("database", "production")
        if "postgres" in db_type:
            sql = f"CREATE ROLE {username} LOGIN PASSWORD '***' VALID UNTIL '2026-12-31'"
        else:
            sql = f"CREATE USER '{username}'@'%' IDENTIFIED BY '***'"
        return self._log(ProvisioningResult(True, self.name, "create_user", username,
                         f"Executed: {sql} | GRANT CONNECT ON {db} TO {username} | "
                         f"Comment: {display_name} ({email})"))

    def disable_user(self, username):
        self._simulate_latency()
        db_type = self.config.get("db_type", "mysql").lower()
        if "postgres" in db_type:
            return self._log(ProvisioningResult(True, self.name, "disable_user", username,
                             f"ALTER ROLE {username} NOLOGIN | All active connections terminated"))
        return self._log(ProvisioningResult(True, self.name, "disable_user", username,
                         f"ALTER USER '{username}'@'%' ACCOUNT LOCK | All active connections killed"))

    def enable_user(self, username):
        self._simulate_latency()
        db_type = self.config.get("db_type", "mysql").lower()
        if "postgres" in db_type:
            return self._log(ProvisioningResult(True, self.name, "enable_user", username,
                             f"ALTER ROLE {username} LOGIN"))
        return self._log(ProvisioningResult(True, self.name, "enable_user", username,
                         f"ALTER USER '{username}'@'%' ACCOUNT UNLOCK"))

    def delete_user(self, username):
        self._simulate_latency()
        return self._log(ProvisioningResult(True, self.name, "delete_user", username,
                         f"REVOKE ALL PRIVILEGES | DROP USER {username} | Owned objects reassigned to dba"))

    def assign_group(self, username, group_name):
        self._simulate_latency()
        return self._log(ProvisioningResult(True, self.name, "assign_group", username,
                         f"GRANT {group_name} TO {username} | Privileges: SELECT, INSERT, UPDATE on assigned schemas"))

    def remove_group(self, username, group_name):
        self._simulate_latency()
        return self._log(ProvisioningResult(True, self.name, "remove_group", username,
                         f"REVOKE {group_name} FROM {username}"))


# ══════════════════════════════════════════════
#  CONNECTOR REGISTRY
# ══════════════════════════════════════════════
CONNECTORS = {
    "active_directory": ActiveDirectoryConnector,
    "azure_ad": AzureADConnector,
    "aws_iam": AWSIAMConnector,
    "linux": LinuxConnector,
    "okta": OktaConnector,
    "database": DatabaseConnector,
}


class ConnectorManager:
    """Manages all system connectors and orchestrates provisioning."""

    def __init__(self, db=None):
        self.db = db
        self.connectors = {}
        self._load_default_configs()

    def _load_default_configs(self):
        """Load connectors with demo configurations."""
        demo_configs = {
            "active_directory": {
                "server": "dc01.corp.example.com",
                "port": "636",
                "use_ssl": True,
                "base_dn": "DC=corp,DC=example,DC=com",
                "bind_user": "CN=svc_secureaccess,OU=Service Accounts,DC=corp,DC=example,DC=com",
                "bind_password": "••••••••",
                "user_ou": "OU=Users,DC=corp,DC=example,DC=com",
                "group_ou": "OU=Security Groups,DC=corp,DC=example,DC=com",
            },
            "azure_ad": {
                "tenant_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "client_id": "12345678-abcd-ef01-2345-678901234567",
                "client_secret": "••••••••",
                "domain": "corp.onmicrosoft.com",
            },
            "aws_iam": {
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "••••••••",
                "region": "us-east-1",
                "account_id": "123456789012",
            },
            "linux": {
                "hostname": "prod-server-01.corp.example.com",
                "port": "22",
                "ssh_user": "secureaccess",
                "ssh_key_path": "/opt/secureaccess/keys/id_ed25519",
                "sudo": True,
            },
            "okta": {
                "domain": "corp.okta.com",
                "api_token": "00x••••••••••••••••••••",
            },
            "database": {
                "db_type": "postgresql",
                "host": "db-prod-01.corp.example.com",
                "port": "5432",
                "admin_user": "secureaccess_admin",
                "admin_password": "••••••••",
                "database": "production",
            },
        }
        for name, cls in CONNECTORS.items():
            self.connectors[name] = cls(demo_configs.get(name, {}))

    def get_connector(self, name) -> BaseConnector:
        return self.connectors.get(name)

    def get_all_connectors(self) -> list:
        return list(self.connectors.values())

    def provision_user_create(self, username, display_name, email, target_systems=None):
        """Provision a new user across selected systems."""
        results = []
        targets = target_systems or list(self.connectors.keys())
        for name in targets:
            conn = self.connectors.get(name)
            if conn and conn.connected:
                result = conn.create_user(username, display_name, email)
                results.append(result)
                if self.db:
                    self.db.log_audit('system', 'PROVISION_CREATE', 'connector', None,
                                      f"{conn.display_name}", f"Provisioned {username}: {result.details}",
                                      'info' if result.success else 'critical')
        return results

    def provision_user_disable(self, username, target_systems=None):
        results = []
        targets = target_systems or list(self.connectors.keys())
        for name in targets:
            conn = self.connectors.get(name)
            if conn and conn.connected:
                result = conn.disable_user(username)
                results.append(result)
                if self.db:
                    self.db.log_audit('system', 'PROVISION_DISABLE', 'connector', None,
                                      conn.display_name, f"Disabled {username}: {result.details}")
        return results

    def provision_role_assign(self, username, role_name, target_systems=None):
        results = []
        targets = target_systems or list(self.connectors.keys())
        for name in targets:
            conn = self.connectors.get(name)
            if conn and conn.connected:
                result = conn.assign_group(username, role_name)
                results.append(result)
                if self.db:
                    self.db.log_audit('system', 'PROVISION_ROLE_ASSIGN', 'connector', None,
                                      conn.display_name, f"Assigned {role_name} to {username}: {result.details}")
        return results

    def provision_role_revoke(self, username, role_name, target_systems=None):
        results = []
        targets = target_systems or list(self.connectors.keys())
        for name in targets:
            conn = self.connectors.get(name)
            if conn and conn.connected:
                result = conn.remove_group(username, role_name)
                results.append(result)
                if self.db:
                    self.db.log_audit('system', 'PROVISION_ROLE_REVOKE', 'connector', None,
                                      conn.display_name, f"Revoked {role_name} from {username}: {result.details}")
        return results
