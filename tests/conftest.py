"""Shared pytest helpers for Feature 0.1 tests."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

LAB1_ROOT = Path(__file__).resolve().parents[1]
if str(LAB1_ROOT) not in sys.path:
    sys.path.insert(0, str(LAB1_ROOT))

from src.storage.repository import MetadataRepository
from src.storage.repository import UserRepository


@pytest.fixture
def valid_passphrase() -> str:
    return "Str0ng!Passphrase123"


@pytest.fixture
def another_valid_passphrase() -> str:
    return "An0ther!Passphrase456"


@pytest.fixture
def metadata_path(tmp_path: Path) -> Path:
    return tmp_path / "vault_metadata.json"


@pytest.fixture
def metadata_repository(metadata_path: Path) -> MetadataRepository:
    return MetadataRepository(metadata_path)


@pytest.fixture
def user_repository(tmp_path: Path) -> UserRepository:
    """An isolated runtime account store for authentication tests."""
    return UserRepository(tmp_path / "users.json")


@pytest.fixture
def fixed_clock():
    """A mutable deterministic UTC clock for session and lockout tests."""
    class Clock:
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)

        def __call__(self) -> datetime:
            return self.now

    return Clock()
