"""Advanced Feature 4: versioned Transit encryption-key rotation."""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.errors import (
    DecryptionFailedError,
    InvalidCiphertextError,
    InvalidInputError,
    InvalidKeyUsageError,
    PermissionDeniedError,
    UnauthenticatedError,
)
from src.storage.repository import TransitKeyRepository
from src.transit.service import (
    KEY_USAGE,
    SIGNING_ALGORITHM,
    TransitService,
)


class Vault:
    def __init__(self, locked=False):
        self.locked = locked
        self.dek = b"d" * 32
        self.dek_accesses = 0

    def is_locked(self):
        return self.locked

    def get_dek(self):
        self.dek_accesses += 1
        return self.dek


IDENTITIES = {
    "alice-token": "alice@example.com",
    "bob-token": "bob@example.com",
}


def authenticate(token):
    try:
        return IDENTITIES[token]
    except (KeyError, TypeError) as exc:
        raise UnauthenticatedError() from exc


def b64(value):
    return base64.b64encode(value).decode("ascii")


def make_service(tmp_path, vault=None):
    vault = vault or Vault()
    repository = TransitKeyRepository(tmp_path / "transit_keys.json")
    return (
        TransitService(
            vault,
            auth_validator=authenticate,
            repository=repository,
            access_log_path=tmp_path / "access_denied.jsonl",
        ),
        repository,
        vault,
    )


def test_rotation_preserves_every_ciphertext_version_across_restart(tmp_path):
    service, repository, vault = make_service(tmp_path)
    service.create_key("alice-token", "payments")
    version_one = service.encrypt(
        "alice-token",
        "payments",
        b64(b"before rotation"),
    )
    assert version_one.startswith("vault:payments:")
    assert ":v1:" not in version_one

    assert service.rotate_key("alice-token", "payments") == {
        "key_name": "payments",
        "key_usage": KEY_USAGE,
        "latest_version": 2,
    }
    version_two = service.encrypt(
        "alice-token",
        "payments",
        b64(b"after first rotation"),
    )
    assert version_two.startswith("vault:payments:v2:")

    service.rotate_key("alice-token", "payments")
    version_three = service.encrypt(
        "alice-token",
        "payments",
        b64(b"after second rotation"),
    )
    assert version_three.startswith("vault:payments:v3:")
    assert service.list_key_versions("alice-token", "payments") == {
        "key_name": "payments",
        "latest_version": 3,
        "versions": [1, 2, 3],
    }
    assert service.list_keys("alice-token") == [{
        "key_name": "payments",
        "key_usage": KEY_USAGE,
    }]

    restarted = TransitService(
        Vault(),
        auth_validator=authenticate,
        repository=repository,
        access_log_path=tmp_path / "restarted-denied.jsonl",
    )
    assert restarted.decrypt("alice-token", version_one) == b64(b"before rotation")
    assert restarted.decrypt("alice-token", version_two) == b64(
        b"after first rotation"
    )
    assert restarted.decrypt("alice-token", version_three) == b64(
        b"after second rotation"
    )

    record = repository.get_key("alice@example.com", "payments")
    assert record["latest_version"] == 3
    assert [item["version"] for item in record["versions"]] == [1, 2, 3]
    plaintext_keys = []
    for version in record["versions"]:
        envelope = base64.b64decode(
            version["encrypted_key_material_b64"],
            validate=True,
        )
        aad = service._key_aad(
            "alice@example.com",
            "payments",
            key_version=(
                version["version"]
                if version["version"] > 1
                else None
            ),
        )
        plaintext_keys.append(
            AESGCM(vault.dek).decrypt(envelope[:12], envelope[12:], aad)
        )
    assert all(len(key) == 32 for key in plaintext_keys)
    assert len(set(plaintext_keys)) == 3


def test_unrotated_key_reports_version_one_without_storage_migration(tmp_path):
    service, repository, _ = make_service(tmp_path)
    service.create_key("alice-token", "legacy")
    before = repository.key_path.read_bytes()

    assert service.list_key_versions("alice-token", "legacy") == {
        "key_name": "legacy",
        "latest_version": 1,
        "versions": [1],
    }
    assert repository.key_path.read_bytes() == before
    assert set(repository.get_key("alice@example.com", "legacy")) == {
        "key_name",
        "owner_email",
        "key_usage",
        "encrypted_key_material_b64",
    }


def test_ciphertext_version_tampering_and_invalid_versions_are_rejected(tmp_path):
    service, _, vault = make_service(tmp_path)
    service.create_key("alice-token", "payments")
    service.rotate_key("alice-token", "payments")
    version_two = service.encrypt("alice-token", "payments", b64(b"sensitive"))
    _, key_name, _, payload = version_two.split(":")

    with pytest.raises(DecryptionFailedError):
        service.decrypt(
            "alice-token",
            f"vault:{key_name}:v1:{payload}",
        )

    accesses_before_missing_version = vault.dek_accesses
    with pytest.raises(InvalidCiphertextError):
        service.decrypt(
            "alice-token",
            f"vault:{key_name}:v99:{payload}",
        )
    assert vault.dek_accesses == accesses_before_missing_version

    for invalid in (
        f"vault:{key_name}:v0:{payload}",
        f"vault:{key_name}:v01:{payload}",
        f"vault:{key_name}:v-1:{payload}",
        f"vault:{key_name}:vx:{payload}",
        f"vault:{key_name}:v:{payload}",
        f"vault:{key_name}:v2:{payload}:extra",
    ):
        with pytest.raises(InvalidCiphertextError):
            service.decrypt("alice-token", invalid)


def test_acl_grants_span_versions_but_rotation_stays_owner_only(tmp_path):
    service, _, vault = make_service(tmp_path)
    service.create_key("alice-token", "shared")
    old_ciphertext = service.encrypt(
        "alice-token",
        "shared",
        b64(b"old"),
    )
    service.grant_key_access(
        "alice-token",
        "shared",
        "bob@example.com",
        ["ENCRYPT", "DECRYPT"],
    )

    accesses_before_denials = vault.dek_accesses
    with pytest.raises(PermissionDeniedError):
        service.rotate_key(
            "bob-token",
            "shared",
            key_owner_email="alice@example.com",
        )
    with pytest.raises(PermissionDeniedError):
        service.list_key_versions(
            "bob-token",
            "shared",
            key_owner_email="alice@example.com",
        )
    assert vault.dek_accesses == accesses_before_denials

    service.rotate_key("alice-token", "shared")
    new_ciphertext = service.encrypt(
        "bob-token",
        "shared",
        b64(b"new"),
        key_owner_email="alice@example.com",
    )
    assert new_ciphertext.startswith(
        "vault:alice@example.com/shared:v2:"
    )
    assert service.decrypt(
        "bob-token",
        old_ciphertext,
        key_owner_email="alice@example.com",
    ) == b64(b"old")
    assert service.decrypt("bob-token", new_ciphertext) == b64(b"new")


def test_signing_keys_cannot_rotate_and_revoke_removes_every_version(tmp_path):
    service, repository, _ = make_service(tmp_path)
    service.create_signing_key(
        "alice-token",
        "signer",
        SIGNING_ALGORITHM,
    )
    signing_record = repository.key_path.read_bytes()
    with pytest.raises(InvalidKeyUsageError):
        service.rotate_key("alice-token", "signer")
    with pytest.raises(InvalidKeyUsageError):
        service.list_key_versions("alice-token", "signer")
    assert repository.key_path.read_bytes() == signing_record

    service.create_key("alice-token", "temporary")
    old_ciphertext = service.encrypt("alice-token", "temporary", b64(b"old"))
    service.rotate_key("alice-token", "temporary")
    new_ciphertext = service.encrypt("alice-token", "temporary", b64(b"new"))
    service.revoke_key("alice-token", "temporary")
    for ciphertext in (old_ciphertext, new_ciphertext):
        with pytest.raises(PermissionDeniedError):
            service.decrypt("alice-token", ciphertext)


@pytest.mark.parametrize(
    "mutator",
    [
        lambda record: {**record, "latest_version": 3},
        lambda record: {
            **record,
            "versions": [
                record["versions"][0],
                {**record["versions"][1], "version": 3},
            ],
        },
        lambda record: {
            **record,
            "versions": [
                {**record["versions"][0], "version": True},
                record["versions"][1],
            ],
        },
        lambda record: {
            **record,
            "versions": [
                record["versions"][0],
                {
                    **record["versions"][1],
                    "encrypted_key_material_b64": b64(b"short"),
                },
            ],
        },
    ],
)
def test_malformed_version_history_fails_repository_validation(
    tmp_path,
    mutator,
):
    service, repository, _ = make_service(tmp_path)
    service.create_key("alice-token", "payments")
    service.rotate_key("alice-token", "payments")
    document = repository.read()
    document["keys"][0] = mutator(document["keys"][0])
    repository.key_path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(InvalidInputError):
        repository.read()


def test_rotation_authenticates_before_repository_or_dek_access(tmp_path):
    service, repository, vault = make_service(tmp_path)
    service.create_key("alice-token", "payments")
    original = repository.key_path.read_bytes()
    accesses_before = vault.dek_accesses

    for operation in (
        lambda: service.rotate_key("invalid-token", "payments"),
        lambda: service.list_key_versions("invalid-token", "payments"),
    ):
        with pytest.raises(UnauthenticatedError):
            operation()
    assert repository.key_path.read_bytes() == original
    assert vault.dek_accesses == accesses_before
