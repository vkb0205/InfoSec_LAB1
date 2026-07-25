"""Vault initialization contract tests."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from src.crypto_utils import (
    DEFAULT_ARGON2_HASH_LEN,
    DEFAULT_ARGON2_MEMORY_COST_KIB,
    DEFAULT_ARGON2_PARALLELISM,
    DEFAULT_ARGON2_TIME_COST,
    SCHEMA_VERSION,
)
from src.core.vault import Vault
from src.errors import INVALID_INPUT, VAULT_LOCKED, InvalidInputError, VaultLockedError


def _metadata(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_initialization_metadata_contract_and_locked_state(metadata_repository, metadata_path, valid_passphrase) -> None:
    vault = Vault(metadata_repository)

    vault.initialize(valid_passphrase)

    assert metadata_path.exists()
    metadata = _metadata(metadata_path)
    assert metadata["schema_version"] == SCHEMA_VERSION
    assert metadata["kdf"] == {
        "algorithm": "argon2id",
        "salt_b64": metadata["kdf"]["salt_b64"],
        "memory_cost_kib": DEFAULT_ARGON2_MEMORY_COST_KIB,
        "time_cost": DEFAULT_ARGON2_TIME_COST,
        "parallelism": DEFAULT_ARGON2_PARALLELISM,
        "hash_len": DEFAULT_ARGON2_HASH_LEN,
    }
    assert metadata["aead"]["algorithm"] == "aes-256-gcm"
    assert len(base64.b64decode(metadata["kdf"]["salt_b64"], validate=True)) == 16
    assert len(base64.b64decode(metadata["aead"]["nonce_b64"], validate=True)) == 12
    assert len(base64.b64decode(metadata["aead"]["ciphertext_and_tag_b64"], validate=True)) == 48
    assert vault.is_initialized() is True
    assert vault.is_locked() is True
    with pytest.raises(VaultLockedError) as exc_info:
        vault.get_dek()
    assert exc_info.value.code == VAULT_LOCKED


def test_initialization_persists_no_plaintext_secrets_or_extra_keys(metadata_repository, metadata_path, valid_passphrase) -> None:
    Vault(metadata_repository).initialize(valid_passphrase)

    raw = metadata_path.read_bytes()
    metadata = _metadata(metadata_path)

    assert valid_passphrase.encode() not in raw
    assert b"plaintext" not in raw.lower()
    assert b"passphrase" not in raw.lower()
    assert b"derived" not in raw.lower()
    assert set(metadata) == {"schema_version", "kdf", "aead"}
    assert set(metadata["kdf"]) == {
        "algorithm",
        "salt_b64",
        "memory_cost_kib",
        "time_cost",
        "parallelism",
        "hash_len",
    }
    assert set(metadata["aead"]) == {"algorithm", "nonce_b64", "ciphertext_and_tag_b64"}


@pytest.mark.parametrize(
    "weak_passphrase",
    [
        "short1!A",
        "alllowercasepassword1!",
        "ALLUPPERCASEPASSWORD1!",
        "NoDigitsPassphrase!",
        "NoSymbolPassphrase1",
    ],
)
def test_weak_passphrase_rejected_without_metadata_or_temp_residue(metadata_repository, metadata_path, weak_passphrase) -> None:
    with pytest.raises(InvalidInputError) as exc_info:
        Vault(metadata_repository).initialize(weak_passphrase)

    assert exc_info.value.code == INVALID_INPUT
    assert not metadata_path.exists()
    assert list(metadata_path.parent.glob("*")) == []


def test_same_passphrase_two_initializations_use_fresh_entropy(tmp_path, valid_passphrase) -> None:
    from src.storage.repository import MetadataRepository

    path_one = tmp_path / "one" / "vault_metadata.json"
    path_two = tmp_path / "two" / "vault_metadata.json"

    Vault(MetadataRepository(path_one)).initialize(valid_passphrase)
    Vault(MetadataRepository(path_two)).initialize(valid_passphrase)

    first = _metadata(path_one)
    second = _metadata(path_two)
    assert first["kdf"]["salt_b64"] != second["kdf"]["salt_b64"]
    assert first["aead"]["nonce_b64"] != second["aead"]["nonce_b64"]
    assert first["aead"]["ciphertext_and_tag_b64"] != second["aead"]["ciphertext_and_tag_b64"]
