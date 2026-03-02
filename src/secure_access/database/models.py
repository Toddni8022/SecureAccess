"""
Database models — re-exported from root database module for package compatibility.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from database import Database, get_db_path  # noqa: E402, F401

__all__ = ["Database", "get_db_path"]
