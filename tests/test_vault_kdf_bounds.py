"""KDF parameter bound rejection tests."""

from __future__ import annotations

import json

import pytest

from src.core.vault import Vault
from src.errors import UNLOCK_FAILED, UnlockFailedError


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("memory_cost_kib", 8191),
        ("memory_cost_kib", 1048577),
        ("time_cost", 0),
        ("time_cost", 11),
        ("parallelism", 0),
        ("parallelism", 17),
        ("hash_len", 15),
        ("hash_len", 65),
    ],
)
def test_kdf_parameter_bounds_fail_generically(metadata_repository, metadata_path, valid_passphrase, field, value) -> None:
    Vault(metadata_repository).initialize(valid_passphrase)
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["kdf"][field] = value
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    vault = Vault(metadata_repository)
    with pytest.raises(UnlockFailedError) as exc_info:
        vault.unlock(valid_passphrase)

    assert exc_info.value.code == UNLOCK_FAILED
    assert vault.is_locked() is True


def test_kdf_salt_size_bounds_fail_generically(metadata_repository, metadata_path, valid_passphrase) -> None:
    import base64

    Vault(metadata_repository).initialize(valid_passphrase)
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["kdf"]["salt_b64"] = base64.b64encode(b"too-short").decode("ascii")
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    vault = Vault(metadata_repository)
    with pytest.raises(UnlockFailedError) as exc_info:
        vault.unlock(valid_passphrase)

    assert exc_info.value.code == UNLOCK_FAILED
    assert vault.is_locked() is True
