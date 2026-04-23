"""
Command-line runner for the SecureAccess live Linux SSH connector.

Dry-run is enabled by default, so commands are printed instead of executed.
Set SECUREACCESS_LINUX_DRY_RUN=0 only against a sandbox host you control.
"""

from __future__ import annotations

import argparse
import json
import sys

from live_linux_connector import LinuxSSHConnector


def print_result(result) -> int:
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.success else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="SecureAccess Linux SSH live connector CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("test", help="Test SSH connectivity or show dry-run test commands")

    create = sub.add_parser("create-user", help="Create a Linux user")
    create.add_argument("username")
    create.add_argument("display_name")
    create.add_argument("email", nargs="?", default="")

    disable = sub.add_parser("disable-user", help="Disable a Linux user")
    disable.add_argument("username")

    enable = sub.add_parser("enable-user", help="Enable a Linux user")
    enable.add_argument("username")

    delete = sub.add_parser("delete-user", help="Delete a Linux user")
    delete.add_argument("username")

    assign = sub.add_parser("assign-group", help="Assign a user to a group")
    assign.add_argument("username")
    assign.add_argument("group")

    remove = sub.add_parser("remove-group", help="Remove a user from a group")
    remove.add_argument("username")
    remove.add_argument("group")

    reset = sub.add_parser("reset-password", help="Expire a user's password")
    reset.add_argument("username")

    args = parser.parse_args(argv)
    connector = LinuxSSHConnector()

    try:
        if args.command == "test":
            return print_result(connector.test_connection())
        if args.command == "create-user":
            return print_result(connector.create_user(args.username, args.display_name, args.email))
        if args.command == "disable-user":
            return print_result(connector.disable_user(args.username))
        if args.command == "enable-user":
            return print_result(connector.enable_user(args.username))
        if args.command == "delete-user":
            return print_result(connector.delete_user(args.username))
        if args.command == "assign-group":
            return print_result(connector.assign_group(args.username, args.group))
        if args.command == "remove-group":
            return print_result(connector.remove_group(args.username, args.group))
        if args.command == "reset-password":
            return print_result(connector.reset_password(args.username))
    finally:
        connector.close()

    parser.error(f"Unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
