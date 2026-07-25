"""Create-only metadata repository behavior tests."""

from __future__ import annotations

import pytest

from src.core.vault import Vault
from src.errors import ALREADY_INITIALIZED, AlreadyInitializedError


def test_repeat_initialization_is_create_only_and_preserves_bytes(metadata_repository, metadata_path, valid_passphrase, another_valid_passphrase) -> None:
    vault = Vault(metadata_repository)
    vault.initialize(valid_passphrase)
    original_bytes = metadata_path.read_bytes()

    with pytest.raises(AlreadyInitializedError) as exc_info:
        vault.initialize(another_valid_passphrase)

    assert exc_info.value.code == ALREADY_INITIALIZED
    assert metadata_path.read_bytes() == original_bytes


def test_publish_collision_reports_already_initialized_and_keeps_existing_bytes(metadata_repository, metadata_path, valid_passphrase) -> None:
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.write_bytes(b'{"existing": true}')
    original_bytes = metadata_path.read_bytes()

    with pytest.raises(AlreadyInitializedError) as exc_info:
        Vault(metadata_repository).initialize(valid_passphrase)

    assert exc_info.value.code == ALREADY_INITIALIZED
    assert metadata_path.read_bytes() == original_bytes
    assert not list(metadata_path.parent.glob("*.tmp"))
