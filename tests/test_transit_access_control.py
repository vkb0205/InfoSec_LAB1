"""Feature 2.3 Transit named-key access control."""

import json

import pytest

from src.errors import PERMISSION_DENIED, PermissionDeniedError
from src.storage.repository import TransitKeyRepository
from src.transit.service import TransitService


class Vault:
    def __init__(self):
        self.dek = b"d" * 32
        self.dek_accesses = 0

    def is_locked(self):
        return False

    def get_dek(self):
        self.dek_accesses += 1
        return self.dek


def test_cross_owner_encrypt_and_decrypt_are_denied_before_cryptography_and_logged(tmp_path):
    vault = Vault()
    identities = {"alice-token": "alice@example.com", "bob-token": "bob@example.com"}
    log_path = tmp_path / "access_denied.jsonl"
    transit = TransitService(
        vault,
        auth_validator=identities.__getitem__,
        repository=TransitKeyRepository(tmp_path / "transit_keys.json"),
        access_log_path=log_path,
    )
    transit.create_key("bob-token", "bob-key")
    ciphertext = transit.encrypt("bob-token", "bob-key", "")
    accesses_before_denials = vault.dek_accesses

    for operation in (
        lambda: transit.encrypt("alice-token", "bob-key", ""),
        lambda: transit.decrypt("alice-token", ciphertext),
    ):
        with pytest.raises(PermissionDeniedError) as error:
            operation()
        assert error.value.code == PERMISSION_DENIED

    assert vault.dek_accesses == accesses_before_denials
    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert entries == [
        {
            "event": "TRANSIT_PERMISSION_DENIED",
            "key_name": "bob-key",
            "requester_email": "alice@example.com",
        },
        {
            "event": "TRANSIT_PERMISSION_DENIED",
            "key_name": "bob-key",
            "requester_email": "alice@example.com",
        },
    ]


def test_missing_and_foreign_keys_have_the_same_public_error(tmp_path):
    identities = {"alice-token": "alice@example.com", "bob-token": "bob@example.com"}
    transit = TransitService(
        Vault(),
        auth_validator=identities.__getitem__,
        repository=TransitKeyRepository(tmp_path / "transit_keys.json"),
        access_log_path=tmp_path / "access_denied.jsonl",
    )
    transit.create_key("bob-token", "foreign")

    for key_name in ("foreign", "missing"):
        with pytest.raises(PermissionDeniedError) as error:
            transit.encrypt("alice-token", key_name, "")
        assert error.value.code == PERMISSION_DENIED
