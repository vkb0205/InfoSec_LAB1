"""Final acceptance tests for Feature 2.2: Transit encrypt/decrypt."""

from __future__ import annotations

import base64
import json
from pathlib import Path
import sys

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.errors import (
    DecryptionFailedError,
    InvalidCiphertextError,
    InvalidInputError,
    InvalidKeyUsageError,
    PermissionDeniedError,
    UnauthenticatedError,
    VaultLockedError,
)
from src.storage.repository import TransitKeyRepository
from src.transit.service import TransitService


IDENTITIES = {
    "alice-token": "alice@example.com",
    "bob-token": "bob@example.com",
}


class VaultStub:
    def __init__(self, *, locked: bool = False) -> None:
        self.locked = locked
        self.dek = bytes(range(32))
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
    service = TransitService(
        vault,
        auth_validator=authenticate,
        repository=repository,
        access_log_path=tmp_path / "access_denied.jsonl",
    )
    return service, repository, vault


@pytest.mark.parametrize(
    ("method_name", "arguments"),
    [
        ("encrypt", ("invalid-token", "payments", b64(b"secret"))),
        ("decrypt", ("invalid-token", "vault:payments:AAAA")),
    ],
)
def test_locked_vault_has_precedence_over_authentication_and_parsing(
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
        ("encrypt", ("invalid-token", "invalid:key", "not-base64!")),
        ("decrypt", (None, "not-even-an-envelope")),
    ],
)
def test_invalid_session_is_rejected_before_input_parsing_or_key_lookup(
    tmp_path,
    method_name,
    arguments,
):
    service, repository, vault = make_service(tmp_path)

    with pytest.raises(UnauthenticatedError):
        getattr(service, method_name)(*arguments)

    assert vault.dek_accesses == 0
    assert not repository.key_path.exists()


@pytest.mark.parametrize(
    "plaintext",
    [
        pytest.param(b"plain UTF-8 text", id="text"),
        pytest.param(
            json.dumps(
                {
                    "enabled": True,
                    "count": 3,
                    "nested": {"roles": ["a", "b"]},
                },
                separators=(",", ":"),
            ).encode(),
            id="json",
        ),
        pytest.param(bytes(range(256)), id="all-byte-values"),
        pytest.param(b"", id="empty"),
        pytest.param(bytes(range(256)) * 256, id="large-binary"),
    ],
)
def test_round_trip_is_exact_for_text_json_binary_empty_and_large_data(
    tmp_path,
    plaintext,
):
    service, _, _ = make_service(tmp_path)
    service.create_key("alice-token", "application")
    encoded = b64(plaintext)

    ciphertext = service.encrypt("alice-token", "application", encoded)
    decrypted = service.decrypt("alice-token", ciphertext)

    assert isinstance(ciphertext, str)
    assert ciphertext.startswith("vault:application:")
    assert decrypted == encoded
    assert base64.b64decode(decrypted, validate=True) == plaintext


def test_ciphertext_is_self_describing_and_has_nonce_ciphertext_and_tag(tmp_path):
    service, _, _ = make_service(tmp_path)
    service.create_key("alice-token", "payments")
    plaintext = b"card-data"

    ciphertext = service.encrypt("alice-token", "payments", b64(plaintext))
    prefix, key_name, encoded_envelope = ciphertext.split(":", 2)
    envelope = base64.b64decode(encoded_envelope, validate=True)

    assert prefix == "vault"
    assert key_name == "payments"
    assert len(envelope[:12]) == 12
    assert len(envelope) == 12 + len(plaintext) + 16
    assert service.decrypt("alice-token", ciphertext) == b64(plaintext)


def test_repeated_encryption_uses_a_fresh_nonce_and_ciphertext(tmp_path):
    service, _, _ = make_service(tmp_path)
    service.create_key("alice-token", "payments")
    plaintext = b64(b"identical plaintext")

    ciphertexts = [
        service.encrypt("alice-token", "payments", plaintext)
        for _ in range(5)
    ]
    envelopes = [
        base64.b64decode(item.split(":", 2)[2], validate=True)
        for item in ciphertexts
    ]

    assert len(set(ciphertexts)) == len(ciphertexts)
    assert len({item[:12] for item in envelopes}) == len(envelopes)


@pytest.mark.parametrize(
    ("component", "index"),
    [
        ("nonce", 0),
        ("ciphertext", 12),
        ("tag", -1),
    ],
)
def test_single_byte_tampering_of_every_envelope_component_is_rejected(
    tmp_path,
    component,
    index,
):
    service, _, _ = make_service(tmp_path)
    service.create_key("alice-token", "payments")
    ciphertext = service.encrypt("alice-token", "payments", b64(b"sensitive"))
    prefix, key_name, encoded_envelope = ciphertext.split(":", 2)
    tampered = bytearray(base64.b64decode(encoded_envelope, validate=True))
    tampered[index] ^= 0x01

    with pytest.raises(DecryptionFailedError):
        service.decrypt(
            "alice-token",
            f"{prefix}:{key_name}:{b64(bytes(tampered))}",
        )


def test_changing_embedded_key_name_cannot_rebind_a_ciphertext(tmp_path):
    service, _, _ = make_service(tmp_path)
    service.create_key("alice-token", "first")
    service.create_key("alice-token", "second")
    ciphertext = service.encrypt("alice-token", "first", b64(b"sensitive"))
    _, _, payload = ciphertext.split(":", 2)

    with pytest.raises(DecryptionFailedError):
        service.decrypt("alice-token", f"vault:second:{payload}")


@pytest.mark.parametrize(
    "ciphertext",
    [
        None,
        b"vault:key:AAAA",
        "",
        "vault",
        "vault:key",
        "wrong:key:AAAA",
        "vault::AAAA",
        "vault: leading:AAAA",
        "vault:trailing :AAAA",
        "vault:key:not-base64!",
        "vault:key:YWJj\n",
        f"vault:key:{b64(b'too-short')}",
    ],
)
def test_malformed_or_truncated_ciphertext_is_rejected_clearly(
    tmp_path,
    ciphertext,
):
    service, _, _ = make_service(tmp_path)

    with pytest.raises(InvalidCiphertextError):
        service.decrypt("alice-token", ciphertext)


@pytest.mark.parametrize(
    "invalid_plaintext",
    [None, b"YWJj", 3, "not-base64!", "YWJj\n", "===="],
)
def test_encrypt_rejects_non_string_or_noncanonical_base64(
    tmp_path,
    invalid_plaintext,
):
    service, _, _ = make_service(tmp_path)
    service.create_key("alice-token", "payments")

    with pytest.raises(InvalidInputError):
        service.encrypt("alice-token", "payments", invalid_plaintext)


def test_missing_and_revoked_keys_refuse_both_encrypt_and_decrypt(tmp_path):
    service, _, _ = make_service(tmp_path)
    service.create_key("alice-token", "payments")
    ciphertext = service.encrypt("alice-token", "payments", b64(b"data"))
    service.revoke_key("alice-token", "payments")

    operations = [
        lambda: service.encrypt("alice-token", "missing", b64(b"data")),
        lambda: service.decrypt(
            "alice-token",
            f"vault:missing:{ciphertext.split(':', 2)[2]}",
        ),
        lambda: service.encrypt("alice-token", "payments", b64(b"data")),
        lambda: service.decrypt("alice-token", ciphertext),
    ]
    for operation in operations:
        with pytest.raises(PermissionDeniedError):
            operation()


def test_signing_key_usage_is_rejected_before_dek_access_for_both_apis():
    class NoCryptoVault:
        def is_locked(self):
            return False

        def get_dek(self):
            raise AssertionError("wrong key usage must precede DEK access")

    class SigningKeyRepository:
        def get_key(self, owner_email, key_name):
            return {
                "key_name": key_name,
                "owner_email": owner_email,
                "key_usage": "SIGN_VERIFY",
                "signing_algorithm": "ED25519",
                "encrypted_private_key_b64": b64(bytes(60)),
                "public_key_b64": b64(bytes(32)),
            }

    service = TransitService(
        NoCryptoVault(),
        auth_validator=lambda token: "alice@example.com",
        repository=SigningKeyRepository(),
    )

    with pytest.raises(InvalidKeyUsageError):
        service.encrypt("token", "signing-key", b64(b"data"))
    with pytest.raises(InvalidKeyUsageError):
        service.decrypt("token", f"vault:signing-key:{b64(bytes(28))}")


def test_tampered_wrapped_named_key_refuses_encrypt_and_decrypt(tmp_path):
    service, repository, _ = make_service(tmp_path)
    service.create_key("alice-token", "payments")
    ciphertext = service.encrypt("alice-token", "payments", b64(b"data"))

    document = repository.read()
    envelope = bytearray(
        base64.b64decode(
            document["keys"][0]["encrypted_key_material_b64"],
            validate=True,
        )
    )
    envelope[-1] ^= 0x01
    document["keys"][0]["encrypted_key_material_b64"] = b64(bytes(envelope))
    repository.key_path.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    with pytest.raises(DecryptionFailedError):
        service.encrypt("alice-token", "payments", b64(b"data"))
    with pytest.raises(DecryptionFailedError):
        service.decrypt("alice-token", ciphertext)
