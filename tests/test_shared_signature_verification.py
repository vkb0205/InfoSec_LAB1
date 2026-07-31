"""Advanced Feature 6: explicit non-owner signature verification grants."""

from __future__ import annotations

import base64

import pytest

from src.errors import (
    InvalidInputError,
    PermissionDeniedError,
    UnauthenticatedError,
)
from src.policy import PolicyRepository, TRANSIT_KEY
from src.storage.repository import TransitKeyRepository
from src.transit.service import SIGNING_ALGORITHM, TransitService


IDENTITIES = {
    "alice-token": "alice@example.com",
    "bob-token": "bob@example.com",
    "carol-token": "carol@example.com",
}


def authenticate(token):
    try:
        return IDENTITIES[token]
    except (KeyError, TypeError) as exc:
        raise UnauthenticatedError() from exc


def b64(value):
    return base64.b64encode(value).decode("ascii")


class Vault:
    def __init__(self):
        self.dek = b"d" * 32
        self.dek_accesses = 0

    def is_locked(self):
        return False

    def get_dek(self):
        self.dek_accesses += 1
        return self.dek


def make_service(tmp_path, vault=None):
    vault = vault or Vault()
    repository = TransitKeyRepository(tmp_path / "transit_keys.json")
    return (
        TransitService(
            vault,
            auth_validator=authenticate,
            repository=repository,
            access_log_path=tmp_path / "access_denied.jsonl",
            audit_log_path=tmp_path / "audit.jsonl",
        ),
        repository,
        vault,
    )


def test_explicit_verify_grant_uses_public_key_without_dek_access(tmp_path):
    service, _, vault = make_service(tmp_path)
    service.create_signing_key(
        "alice-token",
        "release-signer",
        SIGNING_ALGORITHM,
    )
    signature = service.sign(
        "alice-token",
        "release-signer",
        b64(b"release manifest"),
        "RAW",
    )["signature_b64"]

    assert service.grant_verify_access(
        "alice-token",
        "release-signer",
        "Bob@Example.com",
    ) == {
        "key_name": "release-signer",
        "owner_email": "alice@example.com",
        "grantee_email": "bob@example.com",
        "permissions": ["VERIFY"],
    }
    accesses_before_verification = vault.dek_accesses

    expected = {
        "key_name": "release-signer",
        "signature_valid": True,
        "signing_algorithm": SIGNING_ALGORITHM,
    }
    assert service.verify(
        "bob-token",
        "release-signer",
        b64(b"release manifest"),
        "RAW",
        signature,
        key_owner_email="alice@example.com",
    ) == expected
    assert service.verify(
        "bob-token",
        "alice@example.com/release-signer",
        b64(b"release manifest"),
        "RAW",
        signature,
    ) == expected
    assert vault.dek_accesses == accesses_before_verification
    assert service.list_shared_keys("bob-token") == [{
        "key_name": "release-signer",
        "owner_email": "alice@example.com",
        "key_usage": "SIGN_VERIFY",
        "permissions": ["VERIFY"],
    }]


def test_verify_grant_does_not_open_sign_or_access_for_other_users(tmp_path):
    service, _, vault = make_service(tmp_path)
    service.create_signing_key("alice-token", "signer", SIGNING_ALGORITHM)
    signature = service.sign(
        "alice-token",
        "signer",
        b64(b"message"),
        "RAW",
    )["signature_b64"]
    service.grant_verify_access(
        "alice-token",
        "signer",
        "bob@example.com",
    )
    accesses_before_denials = vault.dek_accesses

    with pytest.raises(PermissionDeniedError):
        service.sign(
            "bob-token",
            "signer",
            b64(b"message"),
            "RAW",
            key_owner_email="alice@example.com",
        )
    with pytest.raises(PermissionDeniedError):
        service.verify(
            "carol-token",
            "signer",
            b64(b"message"),
            "RAW",
            signature,
            key_owner_email="alice@example.com",
        )
    assert vault.dek_accesses == accesses_before_denials

    assert service.verify(
        "bob-token",
        "signer",
        b64(b"modified"),
        "RAW",
        signature,
        key_owner_email="alice@example.com",
    )["signature_valid"] is False


def test_verify_grant_persists_and_revocation_immediately_denies(tmp_path):
    service, repository, vault = make_service(tmp_path)
    service.create_signing_key("alice-token", "signer", SIGNING_ALGORITHM)
    signature = service.sign(
        "alice-token",
        "signer",
        b64(b"persistent policy"),
        "RAW",
    )["signature_b64"]
    service.grant_verify_access(
        "alice-token",
        "signer",
        "bob@example.com",
    )

    restarted = TransitService(
        vault,
        auth_validator=authenticate,
        repository=repository,
        access_log_path=tmp_path / "restarted-denied.jsonl",
        audit_log_path=tmp_path / "audit.jsonl",
    )
    assert restarted.verify(
        "bob-token",
        "signer",
        b64(b"persistent policy"),
        "RAW",
        signature,
        key_owner_email="alice@example.com",
    )["signature_valid"] is True

    assert restarted.revoke_verify_access(
        "alice-token",
        "signer",
        "bob@example.com",
    )["permissions"] == []
    with pytest.raises(PermissionDeniedError):
        restarted.verify(
            "bob-token",
            "signer",
            b64(b"persistent policy"),
            "RAW",
            signature,
            key_owner_email="alice@example.com",
        )
    assert PolicyRepository(tmp_path / "policies.json").get_acl(
        TRANSIT_KEY,
        "alice@example.com",
        "signer",
    ) == {}
    assert restarted.list_shared_keys("bob-token") == []


def test_only_owner_can_manage_verify_grants_and_authentication_is_first(
    tmp_path,
):
    service, repository, vault = make_service(tmp_path)
    service.create_signing_key("alice-token", "signer", SIGNING_ALGORITHM)
    original_keys = repository.key_path.read_bytes()
    accesses_before = vault.dek_accesses

    for operation in (
        lambda: service.grant_verify_access(
            "invalid-token",
            "signer",
            "bob@example.com",
        ),
        lambda: service.revoke_verify_access(
            "invalid-token",
            "signer",
            "bob@example.com",
        ),
    ):
        with pytest.raises(UnauthenticatedError):
            operation()

    with pytest.raises(PermissionDeniedError):
        service.grant_verify_access(
            "bob-token",
            "signer",
            "carol@example.com",
            key_owner_email="alice@example.com",
        )
    assert repository.key_path.read_bytes() == original_keys
    assert vault.dek_accesses == accesses_before

    service.create_key("alice-token", "encryption-key")
    keys_after_creation = repository.key_path.read_bytes()
    accesses_after_creation = vault.dek_accesses
    with pytest.raises(InvalidInputError):
        service.grant_verify_access(
            "alice-token",
            "encryption-key",
            "bob@example.com",
        )

    assert repository.key_path.read_bytes() == keys_after_creation
    assert vault.dek_accesses == accesses_after_creation
