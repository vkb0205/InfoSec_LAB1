"""Feature 2.4 Ed25519 signing and verification."""

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.errors import (
    InvalidInputError,
    InvalidKeyUsageError,
    InvalidSigningAlgorithmError,
    PermissionDeniedError,
)
from src.storage.repository import TransitKeyRepository
from src.transit.service import SIGNING_ALGORITHM, SIGNING_KEY_USAGE, TransitService


class Vault:
    def __init__(self):
        self.dek = b"d" * 32
        self.dek_accesses = 0

    def is_locked(self):
        return False

    def get_dek(self):
        self.dek_accesses += 1
        return self.dek


def make_service(tmp_path):
    vault = Vault()
    identities = {"alice-token": "alice@example.com", "bob-token": "bob@example.com"}
    repository = TransitKeyRepository(tmp_path / "transit_keys.json")
    transit = TransitService(
        vault,
        auth_validator=identities.__getitem__,
        repository=repository,
        access_log_path=tmp_path / "access_denied.jsonl",
    )
    return transit, repository, vault


def b64(value):
    return base64.b64encode(value).decode()


def test_signing_key_private_material_is_wrapped_and_never_returned(tmp_path):
    transit, repository, vault = make_service(tmp_path)

    created = transit.create_signing_key("alice-token", "signing-key", "ED25519")
    listed = transit.list_keys("alice-token")
    record = repository.get_key("alice@example.com", "signing-key")

    assert created == {
        "key_name": "signing-key",
        "key_usage": SIGNING_KEY_USAGE,
        "signing_algorithm": SIGNING_ALGORITHM,
    }
    assert listed == [{"key_name": "signing-key", "key_usage": SIGNING_KEY_USAGE}]
    assert "private" not in json.dumps(created) + json.dumps(listed)

    envelope = base64.b64decode(record["encrypted_private_key_b64"], validate=True)
    aad = transit._key_aad(
        "alice@example.com",
        "signing-key",
        SIGNING_KEY_USAGE,
        SIGNING_ALGORITHM,
    )
    private_bytes = AESGCM(vault.dek).decrypt(envelope[:12], envelope[12:], aad)
    assert len(private_bytes) == 32
    assert private_bytes not in repository.key_path.read_bytes()


def test_raw_and_digest_sign_verify_round_trip(tmp_path):
    transit, _, vault = make_service(tmp_path)
    transit.create_signing_key("alice-token", "signing-key", SIGNING_ALGORITHM)
    message = b"message to authenticate"
    digest = hashlib.sha256(message).digest()

    raw_signature = transit.sign("alice-token", "signing-key", b64(message), "RAW")
    digest_signature = transit.sign("alice-token", "signing-key", b64(digest), "DIGEST")
    accesses_before_verify = vault.dek_accesses

    assert raw_signature == digest_signature
    assert transit.verify(
        "alice-token",
        "signing-key",
        b64(message),
        "RAW",
        raw_signature["signature_b64"],
    ) == {
        "key_name": "signing-key",
        "signature_valid": True,
        "signing_algorithm": SIGNING_ALGORITHM,
    }
    assert transit.verify(
        "alice-token",
        "signing-key",
        b64(digest),
        "DIGEST",
        digest_signature["signature_b64"],
    )["signature_valid"] is True
    assert vault.dek_accesses == accesses_before_verify


def test_tampered_message_cross_key_and_malformed_signature_are_invalid(tmp_path):
    transit, _, _ = make_service(tmp_path)
    transit.create_signing_key("alice-token", "first", SIGNING_ALGORITHM)
    transit.create_signing_key("alice-token", "second", SIGNING_ALGORITHM)
    signature = transit.sign("alice-token", "first", b64(b"original"), "RAW")["signature_b64"]

    assert transit.verify("alice-token", "first", b64(b"changed"), "RAW", signature)["signature_valid"] is False
    assert transit.verify("alice-token", "second", b64(b"original"), "RAW", signature)["signature_valid"] is False
    assert transit.verify("alice-token", "first", b64(b"original"), "RAW", "not-base64!")["signature_valid"] is False
    assert transit.verify("alice-token", "first", b64(b"original"), "RAW", b64(b"short"))["signature_valid"] is False
    assert transit.verify("alice-token", "first", b64(b"original"), "RAW")["signature_valid"] is False


def test_invalid_digest_algorithm_and_key_usage_are_rejected(tmp_path):
    transit, _, _ = make_service(tmp_path)
    with pytest.raises(InvalidSigningAlgorithmError):
        transit.create_signing_key("alice-token", "missing-algorithm")
    with pytest.raises(InvalidSigningAlgorithmError):
        transit.create_signing_key("alice-token", "unsupported", "RSA")

    transit.create_signing_key("alice-token", "signing-key", SIGNING_ALGORITHM)
    with pytest.raises(InvalidInputError):
        transit.sign("alice-token", "signing-key", b64(b"message"))
    with pytest.raises(InvalidInputError):
        transit.sign("alice-token", "signing-key", b64(b"message"), "UNKNOWN")
    with pytest.raises(InvalidInputError):
        transit.verify("alice-token", "signing-key", b64(b"message"), "UNKNOWN")
    with pytest.raises(InvalidInputError):
        transit.sign("alice-token", "signing-key", b64(b"not-32-bytes"), "DIGEST")
    signature = transit.sign("alice-token", "signing-key", b64(b"message"), "RAW")["signature_b64"]
    with pytest.raises(InvalidInputError):
        transit.verify(
            "alice-token",
            "signing-key",
            b64(b"message"),
            signature_b64=signature,
        )
    with pytest.raises(InvalidInputError):
        transit.verify(
            "alice-token",
            "signing-key",
            b64(b"not-32-bytes"),
            "DIGEST",
            signature,
        )
    with pytest.raises(InvalidSigningAlgorithmError):
        transit.verify(
            "alice-token",
            "signing-key",
            b64(b"message"),
            "RAW",
            signature,
            signing_algorithm="RSA",
        )
    with pytest.raises(InvalidKeyUsageError):
        transit.encrypt("alice-token", "signing-key", "")
    with pytest.raises(InvalidKeyUsageError):
        transit.decrypt("alice-token", f"vault:signing-key:{b64(bytes(28))}")

    transit.create_key("alice-token", "encryption-key")
    with pytest.raises(InvalidKeyUsageError):
        transit.sign("alice-token", "encryption-key", b64(b"message"), "RAW")
    with pytest.raises(InvalidKeyUsageError):
        transit.verify("alice-token", "encryption-key", b64(b"message"), "RAW", signature)


def test_revoked_signing_key_cannot_sign_or_verify(tmp_path):
    transit, _, _ = make_service(tmp_path)
    transit.create_signing_key("alice-token", "signing-key", SIGNING_ALGORITHM)
    signature = transit.sign("alice-token", "signing-key", b64(b"message"), "RAW")["signature_b64"]
    transit.revoke_key("alice-token", "signing-key")

    with pytest.raises(PermissionDeniedError):
        transit.sign("alice-token", "signing-key", b64(b"message"), "RAW")
    with pytest.raises(PermissionDeniedError):
        transit.verify("alice-token", "signing-key", b64(b"message"), "RAW", signature)


def test_only_owner_can_sign_or_verify_and_denials_do_not_access_dek(tmp_path):
    transit, _, vault = make_service(tmp_path)
    transit.create_signing_key("bob-token", "bob-signing-key", SIGNING_ALGORITHM)
    signature = transit.sign("bob-token", "bob-signing-key", b64(b"message"), "RAW")["signature_b64"]
    accesses_before_denials = vault.dek_accesses

    with pytest.raises(PermissionDeniedError):
        transit.sign("alice-token", "bob-signing-key", b64(b"message"), "RAW")
    with pytest.raises(PermissionDeniedError):
        transit.verify("alice-token", "bob-signing-key", b64(b"message"), "RAW", signature)

    assert vault.dek_accesses == accesses_before_denials
    entries = [
        json.loads(line)
        for line in (tmp_path / "access_denied.jsonl").read_text().splitlines()
    ]
    assert [entry["requester_email"] for entry in entries] == [
        "alice@example.com",
        "alice@example.com",
    ]
