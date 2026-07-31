"""Feature 2.1 named AES key management."""

import base64
import json

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.errors import DuplicateKeyError, KeyNotFoundError
from src.storage.repository import TransitKeyRepository
from src.transit.service import KEY_USAGE, TransitService


class UnlockedVault:
    dek = b"d" * 32

    def is_locked(self):
        return False

    def get_dek(self):
        return self.dek


def service(tmp_path):
    identities = {"alice-token": "alice@example.com", "bob-token": "bob@example.com"}
    repository = TransitKeyRepository(tmp_path / "transit_keys.json")
    return (
        TransitService(
            UnlockedVault(),
            auth_validator=identities.__getitem__,
            repository=repository,
        ),
        repository,
    )


def test_create_wraps_key_and_api_never_returns_material(tmp_path):
    transit, repository = service(tmp_path)

    result = transit.create_key("alice-token", "payments")
    listed = transit.list_keys("alice-token")
    record = repository.read()["keys"][0]

    assert result == {"key_name": "payments", "key_usage": KEY_USAGE}
    assert listed == [{"key_name": "payments", "key_usage": KEY_USAGE}]
    assert "key_material" not in json.dumps(result) + json.dumps(listed)

    envelope = base64.b64decode(record["encrypted_key_material_b64"], validate=True)
    aad = transit._key_aad("alice@example.com", "payments")
    assert len(AESGCM(UnlockedVault.dek).decrypt(envelope[:12], envelope[12:], aad)) == 32
    assert UnlockedVault.dek not in repository.key_path.read_bytes()


def test_keys_are_owner_scoped_and_duplicates_are_rejected(tmp_path):
    transit, repository = service(tmp_path)
    transit.create_key("alice-token", "shared-name")
    original = repository.key_path.read_bytes()

    with pytest.raises(DuplicateKeyError):
        transit.create_key("alice-token", "shared-name")
    assert repository.key_path.read_bytes() == original

    transit.create_key("bob-token", "shared-name")
    assert transit.list_keys("alice-token") == [{"key_name": "shared-name", "key_usage": KEY_USAGE}]
    assert transit.list_keys("bob-token") == [{"key_name": "shared-name", "key_usage": KEY_USAGE}]


def test_revoke_permanently_removes_only_the_owners_key(tmp_path):
    transit, repository = service(tmp_path)
    transit.create_key("alice-token", "shared-name")
    transit.create_key("bob-token", "shared-name")

    assert transit.revoke_key("alice-token", "shared-name") == {
        "key_name": "shared-name",
        "revoked": True,
    }
    assert transit.list_keys("alice-token") == []
    assert len(repository.read()["keys"]) == 1

    with pytest.raises(KeyNotFoundError):
        transit.revoke_key("alice-token", "shared-name")
