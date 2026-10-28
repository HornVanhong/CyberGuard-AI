"""Pytest fixtures and test utilities for CyberGuard AI."""

import os
import tempfile
import pytest
from pathlib import Path


@pytest.fixture
def temp_dir():
    """Provides an isolated temporary directory for test file generation."""
    with tempfile.TemporaryDirectory() as td:
        yield Path(td)


@pytest.fixture
def test_db_path(temp_dir):
    """Provides a temporary SQLite database path."""
    return temp_dir / "test_cyberguard.db"
