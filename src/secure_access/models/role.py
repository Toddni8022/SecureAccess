"""Role data models."""
from enum import Enum


class RiskLevel(str, Enum):
    """Risk level classification for roles."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
