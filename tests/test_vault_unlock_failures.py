"""Generic vault unlock failure tests."""

from __future__ import annotations

import base64
import json

import pytest

from src.core.vault import Vault
from src.errors import UNLOCK_FAILED, UnlockFailedError


def _write(metadata_path, payload: dict) -> None:
    metadata_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")


def _initialized_metadata(metadata_repository, metadata_path, valid_passphrase) -> dict:
    Vault(metadata_repository).initialize(valid_passphrase)
    return json.loads(metadata_path.read_text(encoding="utf-8"))


def _assert_unlock_failed(repo, passphrase: str) -> None:
    vault = Vault(repo)
    with pytest.raises(UnlockFailedError) as exc_info:
        vault.unlock(passphrase)
    assert exc_info.value.code == UNLOCK_FAILED
    assert str(exc_info.value) == UNLOCK_FAILED
    assert vault.is_locked() is True


def test_wrong_passphrase_fails_generically(metadata_repository, valid_passphrase, another_valid_passphrase) -> None:
    Vault(metadata_repository).initialize(valid_passphrase)
    _assert_unlock_failed(metadata_repository, another_valid_passphrase)


def test_malformed_json_fails_generically(metadata_repository, metadata_path, valid_passphrase) -> None:
    metadata_path.write_text("{not json", encoding="utf-8")
    _assert_unlock_failed(metadata_repository, valid_passphrase)


@pytest.mark.parametrize(
    "mutator",
    [
        lambda m: {**m, "schema_version": 999},
        lambda m: {**m, "extra": True},
        lambda m: {**m, "kdf": {**m["kdf"], "salt_b64": "not@@base64"}},
        lambda m: {**m, "aead": {**m["aead"], "nonce_b64": base64.b64encode(b"bad").decode("ascii")}},
        lambda m: {**m, "aead": {**m["aead"], "ciphertext_and_tag_b64": base64.b64encode(b"short").decode("ascii")}},
        lambda m: {
            **m,
            "aead": {
                **m["aead"],
                "ciphertext_and_tag_b64": base64.b64encode(
                    bytes([base64.b64decode(m["aead"]["ciphertext_and_tag_b64"], validate=True)[0] ^ 1])
                    + base64.b64decode(m["aead"]["ciphertext_and_tag_b64"], validate=True)[1:]
                ).decode("ascii"),
            },
        },
    ],
)
def test_metadata_and_ciphertext_failures_are_generic(metadata_repository, metadata_path, valid_passphrase, mutator) -> None:
    metadata = _initialized_metadata(metadata_repository, metadata_path, valid_passphrase)
    _write(metadata_path, mutator(metadata))

    _assert_unlock_failed(metadata_repository, valid_passphrase)
