"""CSV export utilities."""
import csv
import os
from typing import Any


def export_to_csv(filepath: str, headers: list[str], rows: list[list[Any]]) -> bool:
    """
    Export data to a CSV file.

    Args:
        filepath: Path to the output CSV file.
        headers: List of column header names.
        rows: List of row data (each row is a list of values).

    Returns:
        True if export succeeded, False otherwise.
    """
    try:
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)
        return True
    except OSError:
        return False
