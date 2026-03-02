"""
Password hashing and policy enforcement utilities.
"""
import hashlib
import secrets
import re
from dataclasses import dataclass


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """Hash a password with a salt using SHA-256.

    NOTE: SHA-256 is used here for demonstration purposes to maintain
    compatibility with the existing database layer. For production deployments,
    replace this with bcrypt, argon2, or scrypt. See SECURITY.md for details.
    """
    if salt is None:
        salt = secrets.token_hex(32)
    hashed = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
    return hashed, salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Verify a password against a stored hash."""
    computed, _ = hash_password(password, salt)
    return computed == stored_hash


@dataclass
class PasswordPolicy:
    """Password policy configuration."""
    min_length: int = 12
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digits: bool = True
    require_special: bool = True
    max_age_days: int = 90
    history_count: int = 12
    lockout_threshold: int = 5
    lockout_duration_minutes: int = 30

    def validate(self, password: str) -> list[str]:
        """
        Validate a password against the policy.
        Returns a list of violation messages (empty if valid).
        """
        violations = []
        if len(password) < self.min_length:
            violations.append(f"Password must be at least {self.min_length} characters long.")
        if self.require_uppercase and not re.search(r"[A-Z]", password):
            violations.append("Password must contain at least one uppercase letter.")
        if self.require_lowercase and not re.search(r"[a-z]", password):
            violations.append("Password must contain at least one lowercase letter.")
        if self.require_digits and not re.search(r"\d", password):
            violations.append("Password must contain at least one digit.")
        if self.require_special and not re.search(r"[^a-zA-Z0-9]", password):
            violations.append("Password must contain at least one special character.")
        return violations
