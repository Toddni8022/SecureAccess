"""Date and time utility functions."""
from datetime import datetime, timezone


def format_datetime(dt_str: str | None, fmt: str = "%Y-%m-%d %H:%M") -> str:
    """Format a datetime string for display."""
    if not dt_str:
        return "Never"
    try:
        dt = datetime.fromisoformat(dt_str)
        return dt.strftime(fmt)
    except (ValueError, TypeError):
        return dt_str or "Never"


def days_until(dt_str: str | None) -> int | None:
    """Calculate days until a future datetime."""
    if not dt_str:
        return None
    try:
        dt = datetime.fromisoformat(dt_str)
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        delta = dt - now
        return delta.days
    except (ValueError, TypeError):
        return None
