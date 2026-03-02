"""User data models."""
from enum import Enum


class UserStatus(str, Enum):
    """User account status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    LOCKED = "locked"
    PENDING_REVIEW = "pending_review"


class MFAMethod(str, Enum):
    """MFA methods supported."""
    AUTHENTICATOR = "authenticator"
    SMS = "sms"
    HARDWARE_KEY = "hardware_key"
    EMAIL = "email"
