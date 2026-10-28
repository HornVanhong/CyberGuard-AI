"""Database package."""
from app.database.models import ScanRecord
from app.database.repository import ScanRepository

__all__ = ["ScanRecord", "ScanRepository"]
