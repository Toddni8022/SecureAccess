# SecureAccess 90-second demo script

Use this script to record a quick portfolio demo with OBS, Loom, or Windows Game Bar.

## Setup

```bash
pip install -r requirements.txt
python -m unittest discover -s tests
python secure_launcher.py
```

Default demo login:

```text
admin / SecureAccess!ChangeMe1
```

## Demo flow

### 0:00 to 0:10: Problem statement

"SecureAccess is a desktop IAM workflow app for managing users, roles, access requests, access reviews, audit logs, compliance reports, and provisioning. I built it to model the kind of access governance work security and IT teams actually do."

### 0:10 to 0:25: Authenticated launch

Show `secure_launcher.py` and log in.

Say:

"The app now starts behind an authenticated launcher. Passwords are hashed, failed logins are tracked, and sessions are recorded."

### 0:25 to 0:40: Dashboard and users

Show the dashboard, MFA coverage, user status, and user management.

Say:

"The dashboard gives a quick security posture view. From here I can manage users, departments, titles, MFA status, and account states."

### 0:40 to 0:55: Roles and access governance

Show roles, risk levels, access requests, and access reviews.

Say:

"Roles have risk levels, MFA requirements, and permissions. Access requests and periodic reviews make this more than a CRUD app. It models the approval and certification workflow."

### 0:55 to 1:10: Audit integrity

Show `security_core.py` or mention the test output.

Say:

"Audit events are tamper-evident. Each record can be chained to the previous record with a SHA-256 hash, and the app can verify the chain."

### 1:10 to 1:25: Live Linux connector dry run

Run:

```bash
python live_linux_cli.py test
python live_linux_cli.py create-user jdoe "Jane Doe" jdoe@example.com
```

Say:

"The live Linux connector is dry-run by default. It shows the exact SSH commands it would run. Live mode requires explicit environment variables, so it is safer to test."

### 1:25 to 1:30: Close

Say:

"This is still a portfolio project, not a drop-in enterprise IAM product, but it demonstrates security architecture, IAM workflows, audit thinking, test coverage, and live connector design."
