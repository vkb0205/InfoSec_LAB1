"""Vault unlock tests."""

from __future__ import annotations

import pytest

from src.core.vault import Vault
from src.errors import VAULT_LOCKED, VaultLockedError


def test_fresh_vault_over_metadata_starts_locked_and_has_no_dek(metadata_repository, valid_passphrase) -> None:
    Vault(metadata_repository).initialize(valid_passphrase)

    restarted = Vault(metadata_repository)

    assert restarted.is_initialized() is True
    assert restarted.is_locked() is True
    with pytest.raises(VaultLockedError) as exc_info:
        restarted.get_dek()
    assert exc_info.value.code == VAULT_LOCKED


def test_correct_unlock_exposes_32_byte_dek_in_memory_without_changing_metadata(metadata_repository, metadata_path, valid_passphrase) -> None:
    Vault(metadata_repository).initialize(valid_passphrase)
    original_bytes = metadata_path.read_bytes()
    restarted = Vault(metadata_repository)

    restarted.unlock(valid_passphrase)

    assert restarted.is_locked() is False
    dek = restarted.get_dek()
    assert isinstance(dek, bytes)
    assert len(dek) == 32
    assert metadata_path.read_bytes() == original_bytes
