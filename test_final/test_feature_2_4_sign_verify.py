"""Final acceptance tests for Feature 2.4: Transit sign/verify."""

from __future__ import annotations

import base64
import hashlib
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
    DecryptionFailedError,
    DuplicateKeyError,
    InvalidInputError,
    InvalidKeyUsageError,
    InvalidSigningAlgorithmError,
    PermissionDeniedError,
    UnauthenticatedError,
    VaultLockedError,
)
from src.storage.repository import TransitKeyRepository
from src.transit.service import (
    SIGNING_ALGORITHM,
    SIGNING_KEY_USAGE,
    TransitService,
)


IDENTITIES = {
    "alice-token": "alice@example.com",
    "bob-token": "bob@example.com",
}


class VaultStub:
    def __init__(self, *, locked: bool = False) -> None:
        self.locked = locked
        self.dek = b"\x7C" * 32
        self.dek_accesses = 0

    def is_locked(self) -> bool:
        return self.locked

    def get_dek(self) -> bytes:
        self.dek_accesses += 1
        if self.locked:
            raise AssertionError("locked vault DEK access")
        return self.dek


def authenticate(token: str) -> str:
    try:
        return IDENTITIES[token]
    except (KeyError, TypeError) as exc:
        raise UnauthenticatedError() from exc


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def make_service(tmp_path):
    vault = VaultStub()
    repository = TransitKeyRepository(tmp_path / "transit_keys.json")
    log_path = tmp_path / "access_denied.jsonl"
    service = TransitService(
        vault,
        auth_validator=authenticate,
        repository=repository,
        access_log_path=log_path,
    )
    return service, repository, vault, log_path


@pytest.mark.parametrize(
    ("method_name", "arguments"),
    [
        (
            "create_signing_key",
            ("invalid-token", "signer", SIGNING_ALGORITHM),
        ),
        ("sign", ("invalid-token", "signer", b64(b"message"), "RAW")),
        (
            "verify",
            ("invalid-token", "signer", b64(b"message"), "RAW", b64(b"x")),
        ),
    ],
)
def test_locked_vault_rejects_all_signing_operations_before_authentication(
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


@pytest.mark.parametrize(
    ("method_name", "arguments"),
    [
        ("create_signing_key", (None, "bad:name", "RSA")),
        ("sign", ("expired-token", "bad:name", "not-base64!", "UNKNOWN")),
        (
            "verify",
            (
                "invalid-token",
                "bad:name",
                "not-base64!",
                "UNKNOWN",
                "not-base64!",
            ),
        ),
    ],
)
def test_signing_apis_authenticate_before_input_key_or_signature_processing(
    tmp_path,
    method_name,
    arguments,
):
    service, repository, vault, log_path = make_service(tmp_path)

    with pytest.raises(UnauthenticatedError):
        getattr(service, method_name)(*arguments)

    assert vault.dek_accesses == 0
    assert not repository.key_path.exists()
    assert not log_path.exists()


def test_signing_key_contract_private_key_encryption_and_api_non_disclosure(
    tmp_path,
):
    service, repository, vault, _ = make_service(tmp_path)

    created = service.create_signing_key(
        "alice-token",
        "signer",
        SIGNING_ALGORITHM,
    )
    listed = service.list_keys("alice-token")
    record = repository.get_key("alice@example.com", "signer")
    envelope = base64.b64decode(
        record["encrypted_private_key_b64"],
        validate=True,
    )
    aad = service._key_aad(
        "alice@example.com",
        "signer",
        SIGNING_KEY_USAGE,
        SIGNING_ALGORITHM,
    )
    private_key_bytes = AESGCM(vault.dek).decrypt(
        envelope[:12],
        envelope[12:],
        aad,
    )
    disk_bytes = repository.key_path.read_bytes()
    public_payload = json.dumps([created, listed], sort_keys=True)

    assert created == {
        "key_name": "signer",
        "key_usage": SIGNING_KEY_USAGE,
        "signing_algorithm": SIGNING_ALGORITHM,
    }
    assert listed == [{"key_name": "signer", "key_usage": SIGNING_KEY_USAGE}]
    assert set(record) == {
        "key_name",
        "owner_email",
        "key_usage",
        "signing_algorithm",
        "encrypted_private_key_b64",
        "public_key_b64",
    }
    assert len(envelope[:12]) == 12
    assert len(private_key_bytes) == 32
    assert len(base64.b64decode(record["public_key_b64"], validate=True)) == 32
    assert private_key_bytes not in disk_bytes
    assert base64.b64encode(private_key_bytes) not in disk_bytes
    assert record["encrypted_private_key_b64"] not in public_payload
    assert record["public_key_b64"] not in public_payload
    assert "private" not in public_payload
    assert "public" not in public_payload


def test_signing_private_key_metadata_is_authenticated(tmp_path):
    service, repository, vault, _ = make_service(tmp_path)
    service.create_signing_key("alice-token", "signer", SIGNING_ALGORITHM)
    record = repository.get_key("alice@example.com", "signer")
    envelope = base64.b64decode(
        record["encrypted_private_key_b64"],
        validate=True,
    )

    wrong_aads = [
        service._key_aad(
            "bob@example.com",
            "signer",
            SIGNING_KEY_USAGE,
            SIGNING_ALGORITHM,
        ),
        service._key_aad(
            "alice@example.com",
            "other",
            SIGNING_KEY_USAGE,
            SIGNING_ALGORITHM,
        ),
        service._key_aad(
            "alice@example.com",
            "signer",
            "ENCRYPT_DECRYPT",
            SIGNING_ALGORITHM,
        ),
    ]
    for wrong_aad in wrong_aads:
        with pytest.raises(InvalidTag):
            AESGCM(vault.dek).decrypt(
                envelope[:12],
                envelope[12:],
                wrong_aad,
            )


@pytest.mark.parametrize(
    "message",
    [
        b"",
        b"message to authenticate",
        bytes(range(256)),
    ],
)
def test_raw_and_digest_sign_verify_round_trip_with_structured_results(
    tmp_path,
    message,
):
    service, _, vault, _ = make_service(tmp_path)
    service.create_signing_key("alice-token", "signer", SIGNING_ALGORITHM)
    digest = hashlib.sha256(message).digest()

    raw_result = service.sign(
        "alice-token",
        "signer",
        b64(message),
        "RAW",
    )
    digest_result = service.sign(
        "alice-token",
        "signer",
        b64(digest),
        "DIGEST",
    )
    accesses_before_verify = vault.dek_accesses

    assert raw_result == digest_result
    assert set(raw_result) == {
        "signature_b64",
        "key_name",
        "signing_algorithm",
    }
    assert len(base64.b64decode(raw_result["signature_b64"], validate=True)) == 64
    assert service.verify(
        "alice-token",
        "signer",
        b64(message),
        "RAW",
        raw_result["signature_b64"],
    ) == {
        "key_name": "signer",
        "signature_valid": True,
        "signing_algorithm": SIGNING_ALGORITHM,
    }
    assert service.verify(
        "alice-token",
        "signer",
        b64(digest),
        "DIGEST",
        digest_result["signature_b64"],
    )["signature_valid"] is True
    assert vault.dek_accesses == accesses_before_verify


def test_tampered_message_and_cross_key_signature_are_always_invalid(tmp_path):
    service, _, _, _ = make_service(tmp_path)
    service.create_signing_key("alice-token", "first", SIGNING_ALGORITHM)
    service.create_signing_key("alice-token", "second", SIGNING_ALGORITHM)
    original = bytearray(b"original message")
    signature = service.sign(
        "alice-token",
        "first",
        b64(bytes(original)),
        "RAW",
    )["signature_b64"]

    for index in range(len(original)):
        tampered = original.copy()
        tampered[index] ^= 0x01
        assert service.verify(
            "alice-token",
            "first",
            b64(bytes(tampered)),
            "RAW",
            signature,
        )["signature_valid"] is False

    assert service.verify(
        "alice-token",
        "second",
        b64(bytes(original)),
        "RAW",
        signature,
    )["signature_valid"] is False


@pytest.mark.parametrize(
    "signature",
    [
        None,
        "",
        "not-base64!",
        b64(b"short"),
        b64(bytes(63)),
        b64(bytes(65)),
    ],
)
def test_malformed_or_wrong_length_signature_returns_structured_false(
    tmp_path,
    signature,
):
    service, _, _, _ = make_service(tmp_path)
    service.create_signing_key("alice-token", "signer", SIGNING_ALGORITHM)

    result = service.verify(
        "alice-token",
        "signer",
        b64(b"message"),
        "RAW",
        signature,
    )

    assert result == {
        "key_name": "signer",
        "signature_valid": False,
        "signing_algorithm": SIGNING_ALGORITHM,
    }


@pytest.mark.parametrize("digest_length", [0, 1, 31, 33, 64])
def test_digest_input_must_be_exactly_sha256_length(tmp_path, digest_length):
    service, _, _, _ = make_service(tmp_path)
    service.create_signing_key("alice-token", "signer", SIGNING_ALGORITHM)
    encoded = b64(bytes(digest_length))

    with pytest.raises(InvalidInputError):
        service.sign("alice-token", "signer", encoded, "DIGEST")
    with pytest.raises(InvalidInputError):
        service.verify(
            "alice-token",
            "signer",
            encoded,
            "DIGEST",
            b64(bytes(64)),
        )


@pytest.mark.parametrize("message_type", [None, "", "raw", "UNKNOWN"])
def test_message_type_is_mandatory_and_strict(tmp_path, message_type):
    service, _, _, _ = make_service(tmp_path)
    service.create_signing_key("alice-token", "signer", SIGNING_ALGORITHM)

    with pytest.raises(InvalidInputError):
        service.sign(
            "alice-token",
            "signer",
            b64(b"message"),
            message_type,
        )
    with pytest.raises(InvalidInputError):
        service.verify(
            "alice-token",
            "signer",
            b64(b"message"),
            message_type,
            b64(bytes(64)),
        )


def test_invalid_or_mismatched_signing_algorithm_is_rejected(tmp_path):
    service, _, _, _ = make_service(tmp_path)

    for invalid_algorithm in (None, "", "RSA", "ed25519"):
        with pytest.raises(InvalidSigningAlgorithmError):
            service.create_signing_key(
                "alice-token",
                f"key-{invalid_algorithm}",
                invalid_algorithm,
            )

    service.create_signing_key("alice-token", "signer", SIGNING_ALGORITHM)
    signature = service.sign(
        "alice-token",
        "signer",
        b64(b"message"),
        "RAW",
    )["signature_b64"]
    with pytest.raises(InvalidSigningAlgorithmError):
        service.verify(
            "alice-token",
            "signer",
            b64(b"message"),
            "RAW",
            signature,
            signing_algorithm="RSA",
        )


def test_encryption_key_usage_is_rejected_for_sign_and_verify(tmp_path):
    service, _, _, _ = make_service(tmp_path)
    service.create_key("alice-token", "encryption-key")

    with pytest.raises(InvalidKeyUsageError):
        service.sign(
            "alice-token",
            "encryption-key",
            b64(b"message"),
            "RAW",
        )
    with pytest.raises(InvalidKeyUsageError):
        service.verify(
            "alice-token",
            "encryption-key",
            b64(b"message"),
            "RAW",
            b64(bytes(64)),
        )


def test_key_name_collision_is_rejected_across_key_usages(tmp_path):
    service, repository, _, _ = make_service(tmp_path)
    service.create_key("alice-token", "shared-name")
    original = repository.key_path.read_bytes()

    with pytest.raises(DuplicateKeyError):
        service.create_signing_key(
            "alice-token",
            "shared-name",
            SIGNING_ALGORITHM,
        )

    assert repository.key_path.read_bytes() == original


def test_missing_and_revoked_signing_key_refuse_sign_and_verify(tmp_path):
    service, _, _, _ = make_service(tmp_path)
    service.create_signing_key("alice-token", "signer", SIGNING_ALGORITHM)
    signature = service.sign(
        "alice-token",
        "signer",
        b64(b"message"),
        "RAW",
    )["signature_b64"]
    service.revoke_key("alice-token", "signer")

    operations = [
        lambda: service.sign(
            "alice-token",
            "missing",
            b64(b"message"),
            "RAW",
        ),
        lambda: service.verify(
            "alice-token",
            "missing",
            b64(b"message"),
            "RAW",
            signature,
        ),
        lambda: service.sign(
            "alice-token",
            "signer",
            b64(b"message"),
            "RAW",
        ),
        lambda: service.verify(
            "alice-token",
            "signer",
            b64(b"message"),
            "RAW",
            signature,
        ),
    ]
    for operation in operations:
        with pytest.raises(PermissionDeniedError):
            operation()


def test_only_owner_can_sign_or_verify_and_denial_precedes_crypto(tmp_path):
    service, _, vault, log_path = make_service(tmp_path)
    service.create_signing_key("bob-token", "bob-signer", SIGNING_ALGORITHM)
    signature = service.sign(
        "bob-token",
        "bob-signer",
        b64(b"message"),
        "RAW",
    )["signature_b64"]
    accesses_before_denials = vault.dek_accesses

    with pytest.raises(PermissionDeniedError):
        service.sign(
            "alice-token",
            "bob-signer",
            b64(b"message"),
            "RAW",
        )
    with pytest.raises(PermissionDeniedError):
        service.verify(
            "alice-token",
            "bob-signer",
            b64(b"message"),
            "RAW",
            signature,
        )

    assert vault.dek_accesses == accesses_before_denials
    entries = [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
    ]
    assert entries == [
        {
            "event": "TRANSIT_PERMISSION_DENIED",
            "key_name": "bob-signer",
            "requester_email": "alice@example.com",
        },
        {
            "event": "TRANSIT_PERMISSION_DENIED",
            "key_name": "bob-signer",
            "requester_email": "alice@example.com",
        },
    ]


def test_tampered_wrapped_private_key_fails_signing_without_key_exposure(
    tmp_path,
):
    service, repository, _, _ = make_service(tmp_path)
    service.create_signing_key("alice-token", "signer", SIGNING_ALGORITHM)
    document = repository.read()
    envelope = bytearray(
        base64.b64decode(
            document["keys"][0]["encrypted_private_key_b64"],
            validate=True,
        )
    )
    envelope[-1] ^= 0x01
    document["keys"][0]["encrypted_private_key_b64"] = b64(bytes(envelope))
    repository.key_path.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    with pytest.raises(DecryptionFailedError):
        service.sign(
            "alice-token",
            "signer",
            b64(b"message"),
            "RAW",
        )
