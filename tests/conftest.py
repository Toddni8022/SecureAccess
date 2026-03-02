"""Shared pytest fixtures for SecureAccess tests."""
import pytest
import tempfile
import os
import sys

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def temp_db(tmp_path):
    """Create a temporary database for testing."""
    from database import Database
    db_path = str(tmp_path / "test_secureaccess.db")
    db = Database(db_path=db_path)
    yield db
    db.conn.close()
