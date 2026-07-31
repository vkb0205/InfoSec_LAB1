"""User-store persistence safety tests."""
import json
import os
import sys

import pytest

from src.errors import INVALID_INPUT, InvalidInputError
from src.storage.repository import UserRepository


def account(email="user@example.com"):
    return {"email": email, "password_hash": "$argon2id$example", "failed_attempts": 0, "locked_until": None}


def test_absent_store_is_empty_and_create_is_atomic(tmp_path):
    path = tmp_path / "users.json"
    repository = UserRepository(path)
    assert repository.read()["users"] == {}
    repository.create_account(account())
    stored = json.loads(path.read_text())
    assert stored["users"]["user@example.com"] == account()
    assert "sessions" not in stored
    assert not list(tmp_path.glob("*.tmp"))
    if os.name == "posix":
        assert os.stat(path).st_mode & 0o077 == 0


def test_malformed_store_fails_safely(tmp_path):
    path = tmp_path / "users.json"
    path.write_text('{"schema_version": 2, "users": {}}')
    with pytest.raises(InvalidInputError) as error:
        UserRepository(path).read()
    assert error.value.code == INVALID_INPUT
