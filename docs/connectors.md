# Connector Guide — SecureAccess

## Overview

SecureAccess integrates with external identity and access management systems through a modular **connector** architecture. Each connector implements the `BaseConnector` interface and handles user lifecycle operations (create, disable, enable, delete, group assignment, password reset) for its target platform.

Connectors are registered in the `CONNECTORS` dictionary in `connectors.py` and are managed at runtime by `ConnectorManager`.

---

## Available Connectors

### 🏢 Active Directory / LDAP

**Class:** `ActiveDirectoryConnector`  
**Protocol:** LDAP (port 389) / LDAPS (port 636)  
**Use case:** On-premise Microsoft Active Directory or OpenLDAP

#### Configuration

| Field | Key | Example | Description |
|-------|-----|---------|-------------|
| Domain Controller | `server` | `dc01.corp.example.com` | FQDN or IP of domain controller |
| Port | `port` | `389` or `636` | LDAP or LDAPS port |
| Use SSL | `use_ssl` | `true` | Enable LDAPS |
| Base DN | `base_dn` | `DC=corp,DC=example,DC=com` | Directory base |
| Bind User DN | `bind_user` | `CN=svc_secureaccess,OU=Service Accounts,...` | Service account DN |
| Bind Password | `bind_password` | `••••••••` | Service account password |
| Users OU | `user_ou` | `OU=Users,DC=corp,DC=example,DC=com` | Where users are created |
| Groups OU | `group_ou` | `OU=Groups,DC=corp,DC=example,DC=com` | Where groups are managed |

#### Operations

- **Test Connection** — Verifies LDAP bind with provided credentials
- **Create User** — Creates a new AD account with `userAccountControl: 512` (normal, enabled)
- **Disable User** — Sets `userAccountControl: 514` (disabled) and optionally moves to disabled OU
- **Enable User** — Restores `userAccountControl: 512`
- **Delete User** — Removes the user object from the directory
- **Assign Group** — Adds user as a member of a Security Group
- **Remove Group** — Removes user from a Security Group
- **Reset Password** — Sets `pwdLastSet: 0` (must change at next login)

---

### ☁️ Microsoft Entra ID (Azure AD)

**Class:** `AzureADConnector`  
**Protocol:** Microsoft Graph API (REST/OAuth2)  
**Use case:** Cloud-first Microsoft identity (Microsoft 365, Azure)

#### Configuration

| Field | Key | Example | Description |
|-------|-----|---------|-------------|
| Tenant ID | `tenant_id` | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` | Azure AD tenant GUID |
| Client ID | `client_id` | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` | App registration client ID |
| Client Secret | `client_secret` | `••••••••` | App registration secret |
| Domain | `domain` | `corp.onmicrosoft.com` | Azure AD domain |

#### Required API Permissions

Register an app in Azure AD with these **Application** (not delegated) permissions:
- `User.ReadWrite.All`
- `Group.ReadWrite.All`
- `Directory.ReadWrite.All`

#### Operations

- **Test Connection** — Authenticates via OAuth2 client credentials flow
- **Create User** — `POST /users` with UPN, displayName, and accountEnabled: true
- **Disable User** — `PATCH /users/{id}` with accountEnabled: false
- **Enable User** — `PATCH /users/{id}` with accountEnabled: true
- **Delete User** — `DELETE /users/{id}` (moves to deletedItems, recoverable for 30 days)
- **Assign Group** — `POST /groups/{groupId}/members/$ref`
- **Remove Group** — `DELETE /groups/{groupId}/members/{userId}/$ref`
- **Reset Password** — `POST /users/{id}/authentication/methods/password`

---

### 🔐 Okta

**Class:** `OktaConnector`  
**Protocol:** Okta Management API (REST)  
**Use case:** Universal identity platform, SSO federation

#### Configuration

| Field | Key | Example | Description |
|-------|-----|---------|-------------|
| Okta Domain | `domain` | `corp.okta.com` | Your Okta organization domain |
| API Token | `api_token` | `••••••••` | Okta API token (Admin scope) |

#### Operations

- **Test Connection** — `GET /api/v1/users/me`
- **Create User** — `POST /api/v1/users?activate=true`
- **Disable User** — `POST /api/v1/users/{id}/lifecycle/suspend`
- **Enable User** — `POST /api/v1/users/{id}/lifecycle/unsuspend`
- **Delete User** — `POST /api/v1/users/{id}/lifecycle/deactivate` then `DELETE /api/v1/users/{id}`
- **Assign Group** — `PUT /api/v1/groups/{groupId}/users/{userId}`
- **Remove Group** — `DELETE /api/v1/groups/{groupId}/users/{userId}`
- **Reset Password** — `POST /api/v1/users/{id}/lifecycle/reset_password`

---

### 🌐 Google Workspace

> **Note:** Google Workspace connector is planned for a future release. Use the Google Admin SDK Directory API with a service account and domain-wide delegation.

**Protocol:** Google Directory API (REST/OAuth2)  
**Use case:** G Suite / Google Workspace identity management

#### Planned Configuration

| Field | Key | Description |
|-------|-----|-------------|
| Admin Email | `admin_email` | Super admin email for impersonation |
| Service Account JSON | `service_account_json` | Path to service account key file |
| Domain | `domain` | Primary Google Workspace domain |

---

### 🟠 AWS IAM

**Class:** `AWSIAMConnector`  
**Protocol:** AWS SDK / IAM API  
**Use case:** AWS cloud access management, IAM users and groups

#### Configuration

| Field | Key | Example | Description |
|-------|-----|---------|-------------|
| Access Key ID | `access_key_id` | `AKIAIOSFODNN7EXAMPLE` | AWS access key |
| Secret Access Key | `secret_access_key` | `••••••••` | AWS secret key |
| Region | `region` | `us-east-1` | AWS region |
| Account ID | `account_id` | `123456789012` | AWS account ID |

#### Operations

- **Test Connection** — `sts:GetCallerIdentity`
- **Create User** — `iam:CreateUser` + `iam:CreateLoginProfile`
- **Disable User** — `iam:DeleteLoginProfile` + detach all policies
- **Delete User** — `iam:DeleteUser`
- **Assign Group** — `iam:AddUserToGroup`
- **Remove Group** — `iam:RemoveUserFromGroup`
- **Reset Password** — `iam:UpdateLoginProfile`

---

### 🐙 GitHub

> **Note:** GitHub connector is planned for a future release.

**Protocol:** GitHub REST API v3  
**Use case:** Manage GitHub organization membership and team access

#### Planned Configuration

| Field | Key | Description |
|-------|-----|-------------|
| Personal Access Token | `token` | GitHub PAT with `admin:org` scope |
| Organization | `org` | GitHub organization name |

---

### 💬 Slack

> **Note:** Slack connector is planned for a future release.

**Protocol:** Slack SCIM API  
**Use case:** Manage Slack workspace members

#### Planned Configuration

| Field | Key | Description |
|-------|-----|-------------|
| SCIM Token | `scim_token` | Slack SCIM API token (requires Slack Business+ plan) |
| Workspace | `workspace` | Slack workspace subdomain |

---

### 🎫 Jira Service Management

> **Note:** Jira connector is planned for a future release.

**Protocol:** Atlassian REST API v3  
**Use case:** Create/manage Jira user accounts and project access

#### Planned Configuration

| Field | Key | Description |
|-------|-----|-------------|
| Base URL | `base_url` | Jira instance URL (e.g., `https://corp.atlassian.net`) |
| Email | `email` | Admin email for API auth |
| API Token | `api_token` | Atlassian API token |

---

## How to Add a New Connector

1. **Subclass `BaseConnector`** in `connectors.py`:

```python
class MyServiceConnector(BaseConnector):
    name = "my_service"
    display_name = "My Service"
    icon = "🔧"
    description = "Integration with My Service for user provisioning"
    config_fields = [
        {"key": "api_url", "label": "API URL", "placeholder": "https://api.myservice.com", "type": "text"},
        {"key": "api_key", "label": "API Key", "placeholder": "••••••••", "type": "password"},
    ]

    def test_connection(self) -> ProvisioningResult:
        api_url = self.config.get("api_url", "")
        if not api_url:
            return self._log(ProvisioningResult(
                False, self.name, "test_connection", "", "No API URL configured",
                error="Missing api_url"
            ))
        # Perform actual connection test...
        return self._log(ProvisioningResult(
            True, self.name, "test_connection", "",
            f"Connected to {api_url}"
        ))

    def create_user(self, username, display_name, email, **kwargs) -> ProvisioningResult:
        # Implement user creation...
        return self._log(ProvisioningResult(
            True, self.name, "create_user", username,
            f"Created user {username} in My Service"
        ))

    def disable_user(self, username) -> ProvisioningResult:
        # Implement disable...
        ...

    def enable_user(self, username) -> ProvisioningResult:
        # Implement enable...
        ...

    def delete_user(self, username) -> ProvisioningResult:
        # Implement delete...
        ...

    def assign_group(self, username, group_name) -> ProvisioningResult:
        # Implement group assignment...
        ...

    def remove_group(self, username, group_name) -> ProvisioningResult:
        # Implement group removal...
        ...

    def reset_password(self, username) -> ProvisioningResult:
        # Implement password reset...
        ...
```

2. **Register the connector** in the `CONNECTORS` dict:

```python
CONNECTORS = {
    "active_directory": ActiveDirectoryConnector,
    "azure_ad": AzureADConnector,
    # ... existing connectors ...
    "my_service": MyServiceConnector,  # Add here
}
```

3. **Add tests** in `tests/test_connectors.py`.

4. **Add documentation** in `docs/connectors.md`.

---

## Connector Latency Simulation

In the current implementation, connectors simulate network latency using `_simulate_latency()` (a small random sleep) to provide realistic UX during development and demos. In production integrations, replace the simulation methods with actual API calls using appropriate HTTP clients (e.g., `requests`, `ldap3`, `boto3`).
