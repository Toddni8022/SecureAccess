"""
SecureAccess Live Linux Connector

A production-oriented Linux SSH connector with safe defaults.

Design goals:
- dry-run by default
- explicit live mode required before mutating a host
- strict username/group validation
- command quoting with shlex
- injectable SSH client factory for tests
- no secrets hardcoded in source

Example dry run:
    python live_linux_cli.py test
    python live_linux_cli.py create-user jdoe "Jane Doe" jdoe@example.com

Example live mode:
    set SECUREACCESS_LINUX_HOST=192.168.56.10
    set SECUREACCESS_LINUX_USER=secureaccess
    set SECUREACCESS_LINUX_KEY=C:\\Users\\Todd\\.ssh\\id_ed25519
    set SECUREACCESS_LINUX_DRY_RUN=0
    python live_linux_cli.py test
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Callable, Iterable, List, Optional, Tuple

SAFE_NAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


@dataclass
class LiveProvisioningResult:
    success: bool
    connector: str
    action: str
    target_user: str
    details: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    error: Optional[str] = None
    commands: List[str] = field(default_factory=list)
    dry_run: bool = True

    def to_dict(self):
        return asdict(self)


class LinuxSSHConnector:
    """Live Linux connector using Paramiko SSH with dry-run safety."""

    name = "linux_ssh_live"
    display_name = "Linux SSH Live Connector"

    def __init__(self, config: Optional[dict] = None, client_factory: Optional[Callable] = None):
        self.config = config or self.from_env()
        self.client_factory = client_factory
        self.connected = False
        self.client = None
        self.provision_log: List[LiveProvisioningResult] = []

    @staticmethod
    def from_env() -> dict:
        return {
            "hostname": os.environ.get("SECUREACCESS_LINUX_HOST", ""),
            "port": int(os.environ.get("SECUREACCESS_LINUX_PORT", "22")),
            "username": os.environ.get("SECUREACCESS_LINUX_USER", ""),
            "key_filename": os.environ.get("SECUREACCESS_LINUX_KEY", ""),
            "password": os.environ.get("SECUREACCESS_LINUX_PASSWORD", ""),
            "sudo": os.environ.get("SECUREACCESS_LINUX_SUDO", "1") != "0",
            "dry_run": os.environ.get("SECUREACCESS_LINUX_DRY_RUN", "1") != "0",
            "timeout": int(os.environ.get("SECUREACCESS_LINUX_TIMEOUT", "10")),
        }

    @property
    def dry_run(self) -> bool:
        return bool(self.config.get("dry_run", True))

    def _log(self, result: LiveProvisioningResult) -> LiveProvisioningResult:
        self.provision_log.append(result)
        return result

    def _validate_safe_name(self, value: str, field_name: str = "name") -> None:
        if not SAFE_NAME_RE.match(value or ""):
            raise ValueError(f"Unsafe {field_name}: {value!r}. Use lowercase Linux-safe names only.")

    def _sudo(self, command: str) -> str:
        return f"sudo {command}" if self.config.get("sudo", True) else command

    def _quote(self, value: str) -> str:
        return shlex.quote(value)

    def _make_client(self):
        if self.client_factory:
            return self.client_factory()

        try:
            import paramiko  # type: ignore
        except ImportError as exc:
            raise RuntimeError("paramiko is required for live SSH mode. Install requirements.txt.") from exc

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        return client

    def _connect_if_needed(self):
        if self.dry_run:
            return None
        if self.client:
            return self.client

        hostname = self.config.get("hostname")
        username = self.config.get("username")
        if not hostname or not username:
            raise ValueError("hostname and username are required for live mode.")

        client = self._make_client()
        connect_kwargs = {
            "hostname": hostname,
            "port": int(self.config.get("port", 22)),
            "username": username,
            "timeout": int(self.config.get("timeout", 10)),
            "look_for_keys": True,
            "allow_agent": True,
        }
        key_filename = self.config.get("key_filename")
        password = self.config.get("password")
        if key_filename:
            connect_kwargs["key_filename"] = key_filename
        if password:
            connect_kwargs["password"] = password

        client.connect(**connect_kwargs)
        self.client = client
        self.connected = True
        return client

    def close(self) -> None:
        if self.client:
            self.client.close()
        self.client = None
        self.connected = False

    def _execute(self, commands: Iterable[str]) -> Tuple[bool, str, Optional[str]]:
        command_list = list(commands)
        if self.dry_run:
            return True, "DRY RUN: " + " && ".join(command_list), None

        client = self._connect_if_needed()
        combined_output: List[str] = []
        for command in command_list:
            _stdin, stdout, stderr = client.exec_command(command, timeout=int(self.config.get("timeout", 10)))
            exit_code = stdout.channel.recv_exit_status()
            out = stdout.read().decode("utf-8", errors="replace").strip()
            err = stderr.read().decode("utf-8", errors="replace").strip()
            if out:
                combined_output.append(out)
            if err:
                combined_output.append(err)
            if exit_code != 0:
                return False, "\n".join(combined_output), f"Command failed with exit code {exit_code}: {command}"
        return True, "\n".join(combined_output) or "Command completed.", None

    def test_connection(self) -> LiveProvisioningResult:
        commands = ["id", "uname -a"]
        try:
            ok, details, error = self._execute(commands)
            return self._log(LiveProvisioningResult(ok, self.name, "test_connection", "", details, error=error, commands=commands, dry_run=self.dry_run))
        except Exception as exc:
            return self._log(LiveProvisioningResult(False, self.name, "test_connection", "", str(exc), error=str(exc), commands=commands, dry_run=self.dry_run))

    def create_user(self, username: str, display_name: str, email: str = "") -> LiveProvisioningResult:
        self._validate_safe_name(username, "username")
        gecos = f"{display_name} <{email}>" if email else display_name
        quoted_user = self._quote(username)
        quoted_gecos = self._quote(gecos)
        commands = [
            f"id -u {quoted_user} >/dev/null 2>&1 || {self._sudo(f'useradd -m -s /bin/bash -c {quoted_gecos} {quoted_user}')}",
            self._sudo(f"passwd -l {quoted_user}"),
        ]
        return self._run_user_action("create_user", username, commands)

    def disable_user(self, username: str) -> LiveProvisioningResult:
        self._validate_safe_name(username, "username")
        quoted_user = self._quote(username)
        commands = [self._sudo(f"usermod -L -e 1 -s /usr/sbin/nologin {quoted_user}"), f"pkill -KILL -u {quoted_user} || true"]
        return self._run_user_action("disable_user", username, commands)

    def enable_user(self, username: str) -> LiveProvisioningResult:
        self._validate_safe_name(username, "username")
        quoted_user = self._quote(username)
        commands = [self._sudo(f"usermod -U -e '' -s /bin/bash {quoted_user}")]
        return self._run_user_action("enable_user", username, commands)

    def delete_user(self, username: str) -> LiveProvisioningResult:
        self._validate_safe_name(username, "username")
        commands = [self._sudo(f"userdel -r {self._quote(username)}")]
        return self._run_user_action("delete_user", username, commands)

    def assign_group(self, username: str, group_name: str) -> LiveProvisioningResult:
        self._validate_safe_name(username, "username")
        self._validate_safe_name(group_name, "group")
        quoted_user = self._quote(username)
        quoted_group = self._quote(group_name)
        commands = [
            f"getent group {quoted_group} >/dev/null || {self._sudo(f'groupadd {quoted_group}')}",
            self._sudo(f"usermod -aG {quoted_group} {quoted_user}"),
        ]
        return self._run_user_action("assign_group", username, commands)

    def remove_group(self, username: str, group_name: str) -> LiveProvisioningResult:
        self._validate_safe_name(username, "username")
        self._validate_safe_name(group_name, "group")
        commands = [self._sudo(f"gpasswd -d {self._quote(username)} {self._quote(group_name)}")]
        return self._run_user_action("remove_group", username, commands)

    def reset_password(self, username: str) -> LiveProvisioningResult:
        self._validate_safe_name(username, "username")
        commands = [self._sudo(f"passwd -e {self._quote(username)}")]
        return self._run_user_action("reset_password", username, commands)

    def _run_user_action(self, action: str, username: str, commands: List[str]) -> LiveProvisioningResult:
        try:
            ok, details, error = self._execute(commands)
            return self._log(LiveProvisioningResult(ok, self.name, action, username, details, error=error, commands=commands, dry_run=self.dry_run))
        except Exception as exc:
            return self._log(LiveProvisioningResult(False, self.name, action, username, str(exc), error=str(exc), commands=commands, dry_run=self.dry_run))
