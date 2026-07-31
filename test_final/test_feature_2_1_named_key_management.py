"""Final acceptance tests for Feature 2.1: Transit named-key management."""

from __future__ import annotations

import base64
import json
from pathlib import Path
import sys

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.errors import (
    DuplicateKeyError,
    InvalidInputError,
    KeyNotFoundError,
    UnauthenticatedError,
    VaultLockedError,
)
from src.storage.repository import TransitKeyRepository
from src.transit.service import KEY_USAGE, TransitService


IDENTITIES = {
    "alice-token": "alice@example.com",
    "bob-token": "bob@example.com",
}


class VaultStub:
    def __init__(self, *, locked: bool = False) -> None:
        self.locked = locked
        self.dek = bytes([0xA5]) * 32
        self.dek_accesses = 0

    def is_locked(self) -> bool:
        return self.locked

    def get_dek(self) -> bytes:
        self.dek_accesses += 1
        if self.locked:
            raise AssertionError("a locked vault must not expose its DEK")
        return self.dek


def authenticate(token: str) -> str:
    try:
        return IDENTITIES[token]
    except (KeyError, TypeError) as exc:
        raise UnauthenticatedError() from exc


def make_service(tmp_path):
    vault = VaultStub()
    repository = TransitKeyRepository(tmp_path / "transit_keys.json")
    service = TransitService(
        vault,
        auth_validator=authenticate,
        repository=repository,
        access_log_path=tmp_path / "access_denied.jsonl",
    )
    return service, repository, vault


def unwrap_key(service: TransitService, vault: VaultStub, record: dict) -> tuple[bytes, bytes]:
    envelope = base64.b64decode(
        record["encrypted_key_material_b64"],
        validate=True,
    )
    plaintext_key = AESGCM(vault.dek).decrypt(
        envelope[:12],
        envelope[12:],
        service._key_aad(
            record["owner_email"],
            record["key_name"],
            record["key_usage"],
        ),
    )
    return envelope[:12], plaintext_key


@pytest.mark.parametrize(
    ("method_name", "arguments"),
    [
        ("create_key", ("invalid-token", "payments")),
        ("list_keys", ("invalid-token",)),
        ("revoke_key", ("invalid-token", "payments")),
    ],
)
def test_locked_vault_rejects_every_key_management_operation_before_authentication(
    tmp_path,
    method_name,
    arguments,
):
    auth_calls = []
    vault = VaultStub(locked=True)
    service = TransitService(
        vault,
        auth_validator=lambda token: auth_calls.append(token),
        repository=TransitKeyRepository(tmp_path / "keys.json"),
    )

    with pytest.raises(VaultLockedError):
        getattr(service, method_name)(*arguments)

    assert auth_calls == []
    assert vault.dek_accesses == 0
    assert not (tmp_path / "keys.json").exists()


@pytest.mark.parametrize(
    ("method_name", "arguments"),
    [
        ("create_key", (None, "payments")),
        ("list_keys", ("missing-token",)),
        ("revoke_key", ("missing-token", "payments")),
    ],
)
def test_key_management_requires_a_valid_session_before_storage_or_crypto(
    tmp_path,
    method_name,
    arguments,
):
    service, repository, vault = make_service(tmp_path)

    with pytest.raises(UnauthenticatedError):
        getattr(service, method_name)(*arguments)

    assert vault.dek_accesses == 0
    assert not repository.key_path.exists()


def test_created_aes_256_key_is_owner_bound_and_encrypted_at_rest(tmp_path):
    service, repository, vault = make_service(tmp_path)

    result = service.create_key("alice-token", "payments")
    persisted = repository.read()
    record = persisted["keys"][0]
    nonce, plaintext_key = unwrap_key(service, vault, record)
    disk_bytes = repository.key_path.read_bytes()

    assert result == {"key_name": "payments", "key_usage": KEY_USAGE}
    assert persisted["schema_version"] == 1
    assert set(record) == {
        "key_name",
        "owner_email",
        "key_usage",
        "encrypted_key_material_b64",
    }
    assert record["owner_email"] == "alice@example.com"
    assert record["key_usage"] == "ENCRYPT_DECRYPT"
    assert len(nonce) == 12
    assert len(plaintext_key) == 32
    assert plaintext_key not in disk_bytes
    assert base64.b64encode(plaintext_key) not in disk_bytes
    assert vault.dek not in disk_bytes
    assert base64.b64encode(vault.dek) not in disk_bytes


def test_key_metadata_is_authenticated_as_associated_data(tmp_path):
    service, repository, vault = make_service(tmp_path)
    service.create_key("alice-token", "payments")
    record = repository.read()["keys"][0]
    envelope = base64.b64decode(
        record["encrypted_key_material_b64"],
        validate=True,
    )

    for wrong_aad in (
        service._key_aad("bob@example.com", "payments", KEY_USAGE),
        service._key_aad("alice@example.com", "renamed", KEY_USAGE),
        service._key_aad("alice@example.com", "payments", "SIGN_VERIFY"),
    ):
        with pytest.raises(InvalidTag):
            AESGCM(vault.dek).decrypt(
                envelope[:12],
                envelope[12:],
                wrong_aad,
            )


def test_each_created_key_uses_fresh_nonce_and_key_material(tmp_path):
    service, repository, vault = make_service(tmp_path)
    service.create_key("alice-token", "first")
    service.create_key("alice-token", "second")
    records = repository.read()["keys"]

    first_nonce, first_key = unwrap_key(service, vault, records[0])
    second_nonce, second_key = unwrap_key(service, vault, records[1])

    assert first_nonce != second_nonce
    assert first_key != second_key


def test_list_is_sorted_owner_scoped_persistent_and_never_leaks_key_material(tmp_path):
    service, repository, vault = make_service(tmp_path)
    service.create_key("alice-token", "z-last")
    service.create_key("alice-token", "a-first")
    service.create_key("bob-token", "bob-only")

    restarted = TransitService(
        vault,
        auth_validator=authenticate,
        repository=TransitKeyRepository(repository.key_path),
        access_log_path=tmp_path / "access_denied.jsonl",
    )
    alice_list = restarted.list_keys("alice-token")
    bob_list = restarted.list_keys("bob-token")
    public_payload = json.dumps(alice_list + bob_list, sort_keys=True)

    assert alice_list == [
        {"key_name": "a-first", "key_usage": KEY_USAGE},
        {"key_name": "z-last", "key_usage": KEY_USAGE},
    ]
    assert bob_list == [{"key_name": "bob-only", "key_usage": KEY_USAGE}]
    assert "owner_email" not in public_payload
    assert "encrypted" not in public_payload
    assert "material" not in public_payload
    for record in repository.read()["keys"]:
        assert record["encrypted_key_material_b64"] not in public_payload


def test_duplicate_name_is_rejected_without_overwrite_but_names_are_per_owner(
    tmp_path,
):
    service, repository, _ = make_service(tmp_path)
    service.create_key("alice-token", "shared")
    bytes_before_duplicate = repository.key_path.read_bytes()

    with pytest.raises(DuplicateKeyError):
        service.create_key("alice-token", "shared")

    assert repository.key_path.read_bytes() == bytes_before_duplicate
    service.create_key("bob-token", "shared")
    records = repository.read()["keys"]
    assert {(item["owner_email"], item["key_name"]) for item in records} == {
        ("alice@example.com", "shared"),
        ("bob@example.com", "shared"),
    }


def test_revoke_is_permanent_and_cannot_remove_another_owners_same_named_key(
    tmp_path,
):
    service, repository, _ = make_service(tmp_path)
    service.create_key("alice-token", "shared")
    service.create_key("bob-token", "shared")
    service.create_key("bob-token", "bob-only")

    assert service.revoke_key("alice-token", "shared") == {
        "key_name": "shared",
        "revoked": True,
    }
    assert service.list_keys("alice-token") == []
    assert service.list_keys("bob-token") == [
        {"key_name": "bob-only", "key_usage": KEY_USAGE},
        {"key_name": "shared", "key_usage": KEY_USAGE},
    ]
    assert {
        (item["owner_email"], item["key_name"])
        for item in repository.read()["keys"]
    } == {
        ("bob@example.com", "shared"),
        ("bob@example.com", "bob-only"),
    }

    with pytest.raises(KeyNotFoundError):
        service.revoke_key("alice-token", "shared")
    with pytest.raises(KeyNotFoundError):
        service.revoke_key("alice-token", "bob-only")


@pytest.mark.parametrize(
    "invalid_name",
    [None, 7, "", " leading", "trailing ", "contains:colon"],
)
def test_create_and_revoke_reject_invalid_key_names(tmp_path, invalid_name):
    service, repository, _ = make_service(tmp_path)

    with pytest.raises(InvalidInputError):
        service.create_key("alice-token", invalid_name)
    with pytest.raises(InvalidInputError):
        service.revoke_key("alice-token", invalid_name)

    assert not repository.key_path.exists()
