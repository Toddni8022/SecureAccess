"""Tests for authentication utilities."""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.secure_access.auth.password import hash_password, verify_password, PasswordPolicy


class TestPasswordHashing:
    """Tests for password hashing functions."""

    def test_hash_returns_tuple(self):
        hashed, salt = hash_password("MyP@ssw0rd!")
        assert isinstance(hashed, str)
        assert isinstance(salt, str)

    def test_hash_is_deterministic_with_same_salt(self):
        hashed1, salt = hash_password("MyP@ssw0rd!", salt="testsalt")
        hashed2, _ = hash_password("MyP@ssw0rd!", salt="testsalt")
        assert hashed1 == hashed2

    def test_different_salts_produce_different_hashes(self):
        hashed1, _ = hash_password("MyP@ssw0rd!", salt="salt1")
        hashed2, _ = hash_password("MyP@ssw0rd!", salt="salt2")
        assert hashed1 != hashed2

    def test_verify_correct_password(self):
        password = "MyP@ssw0rd!"
        hashed, salt = hash_password(password)
        assert verify_password(password, hashed, salt) is True

    def test_verify_wrong_password(self):
        hashed, salt = hash_password("CorrectPassword1!")
        assert verify_password("WrongPassword1!", hashed, salt) is False


class TestPasswordPolicy:
    """Tests for PasswordPolicy validation."""

    def test_valid_password_passes(self):
        policy = PasswordPolicy()
        violations = policy.validate("SecureP@ss1!")
        assert violations == []

    def test_too_short_fails(self):
        policy = PasswordPolicy(min_length=12)
        violations = policy.validate("Short1!")
        assert any("12" in v for v in violations)

    def test_no_uppercase_fails(self):
        policy = PasswordPolicy()
        violations = policy.validate("nouppercase1!")
        assert any("uppercase" in v.lower() for v in violations)

    def test_no_lowercase_fails(self):
        policy = PasswordPolicy()
        violations = policy.validate("NOLOWERCASE1!")
        assert any("lowercase" in v.lower() for v in violations)

    def test_no_digit_fails(self):
        policy = PasswordPolicy()
        violations = policy.validate("NoDigitsHere!")
        assert any("digit" in v.lower() for v in violations)

    def test_no_special_fails(self):
        policy = PasswordPolicy()
        violations = policy.validate("NoSpecialChar1")
        assert any("special" in v.lower() for v in violations)

    def test_custom_min_length(self):
        policy = PasswordPolicy(min_length=6)
        violations = policy.validate("Ab1!")
        assert any("6" in v for v in violations)

    def test_policy_no_requirements(self):
        policy = PasswordPolicy(
            min_length=1,
            require_uppercase=False,
            require_lowercase=False,
            require_digits=False,
            require_special=False,
        )
        violations = policy.validate("a")
        assert violations == []
