"""Tests for the database layer."""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import Database


class TestDatabase:
    """Tests for Database class."""

    def test_database_initializes(self, temp_db):
        """Database should initialize with default roles and users."""
        cursor = temp_db.conn.execute("SELECT COUNT(*) FROM roles")
        count = cursor.fetchone()[0]
        assert count > 0, "Default roles should be seeded"

    def test_default_roles_seeded(self, temp_db):
        """Default roles should include Administrator, Security Analyst, etc."""
        cursor = temp_db.conn.execute("SELECT name FROM roles ORDER BY id")
        roles = [row[0] for row in cursor.fetchall()]
        assert "Administrator" in roles
        assert "Security Analyst" in roles
        assert "Standard User" in roles

    def test_default_users_seeded(self, temp_db):
        """Default users should be seeded."""
        cursor = temp_db.conn.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        assert count > 0

    def test_password_policy_seeded(self, temp_db):
        """Password policy should be seeded with defaults."""
        cursor = temp_db.conn.execute("SELECT * FROM password_policy WHERE id = 1")
        row = cursor.fetchone()
        assert row is not None

    def test_get_users(self, temp_db):
        """get_users should return a list of users."""
        users = temp_db.get_users()
        assert isinstance(users, list)
        assert len(users) > 0

    def test_get_roles(self, temp_db):
        """get_roles should return a list of roles."""
        roles = temp_db.get_roles()
        assert isinstance(roles, list)
        assert len(roles) > 0

    def test_create_user(self, temp_db):
        """Should be able to create a new user."""
        initial_count_cursor = temp_db.conn.execute("SELECT COUNT(*) FROM users")
        initial_count = initial_count_cursor.fetchone()[0]

        temp_db.create_user(
            username="testuser",
            display_name="Test User",
            email="test@example.com",
            department="IT",
            title="Tester",
            status="active",
            mfa_enabled=0,
            mfa_method=None,
            notes="Test user"
        )

        cursor = temp_db.conn.execute("SELECT COUNT(*) FROM users")
        new_count = cursor.fetchone()[0]
        assert new_count == initial_count + 1

    def test_get_audit_log(self, temp_db):
        """get_audit_log should return a list."""
        logs = temp_db.get_audit_log()
        assert isinstance(logs, list)

    def test_get_password_policy(self, temp_db):
        """get_password_policy should return policy data."""
        policy = temp_db.get_password_policy()
        assert policy is not None

    def test_foreign_keys_enabled(self, temp_db):
        """Foreign keys should be enforced."""
        cursor = temp_db.conn.execute("PRAGMA foreign_keys")
        fk_enabled = cursor.fetchone()[0]
        assert fk_enabled == 1
