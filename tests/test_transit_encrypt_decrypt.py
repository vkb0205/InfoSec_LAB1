"""Feature 2.2 Transit encryption and decryption."""

import base64

import pytest

from src.errors import (
    DecryptionFailedError,
    InvalidCiphertextError,
    InvalidInputError,
    InvalidKeyUsageError,
    KeyNotFoundError,
)
from src.storage.repository import TransitKeyRepository
from src.transit.service import TransitService


class UnlockedVault:
    def __init__(self):
        self.dek = b"d" * 32

    def is_locked(self):
        return False

    def get_dek(self):
        return self.dek


def make_service(tmp_path):
    identities = {"alice-token": "alice@example.com", "bob-token": "bob@example.com"}
    return TransitService(
        UnlockedVault(),
        auth_validator=identities.__getitem__,
        repository=TransitKeyRepository(tmp_path / "transit_keys.json"),
    )


@pytest.mark.parametrize(
    "plaintext",
    [
        b"hello",
        b'{"enabled":true,"count":3}',
        bytes(range(256)),
        b"",
    ],
)
def test_encrypt_decrypt_round_trip_for_text_json_and_binary(tmp_path, plaintext):
    transit = make_service(tmp_path)
    transit.create_key("alice-token", "application")
    encoded = base64.b64encode(plaintext).decode()

    ciphertext = transit.encrypt("alice-token", "application", encoded)

    assert ciphertext.startswith("vault:application:")
    assert transit.decrypt("alice-token", ciphertext) == encoded


def test_encrypt_uses_fresh_nonce_and_tampering_is_rejected(tmp_path):
    transit = make_service(tmp_path)
    transit.create_key("alice-token", "application")
    encoded = base64.b64encode(b"same plaintext").decode()

    first = transit.encrypt("alice-token", "application", encoded)
    second = transit.encrypt("alice-token", "application", encoded)
    assert first != second

    prefix, payload = first.rsplit(":", 1)
    envelope = bytearray(base64.b64decode(payload))
    envelope[-1] ^= 1
    tampered = f"{prefix}:{base64.b64encode(envelope).decode()}"
    with pytest.raises(DecryptionFailedError):
        transit.decrypt("alice-token", tampered)


@pytest.mark.parametrize(
    "ciphertext",
    [
        None,
        "",
        "wrong:key:value",
        "vault::AAAA",
        "vault:key:not-base64!",
        f"vault:key:{base64.b64encode(b'short').decode()}",
    ],
)
def test_malformed_or_truncated_ciphertext_is_rejected(tmp_path, ciphertext):
    transit = make_service(tmp_path)
    with pytest.raises(InvalidCiphertextError):
        transit.decrypt("alice-token", ciphertext)


def test_invalid_plaintext_base64_and_revoked_keys_are_rejected(tmp_path):
    transit = make_service(tmp_path)
    transit.create_key("alice-token", "application")
    with pytest.raises(InvalidInputError):
        transit.encrypt("alice-token", "application", "not-base64!")

    ciphertext = transit.encrypt("alice-token", "application", "")
    transit.revoke_key("alice-token", "application")
    with pytest.raises(KeyNotFoundError):
        transit.encrypt("alice-token", "application", "")
    with pytest.raises(KeyNotFoundError):
        transit.decrypt("alice-token", ciphertext)


def test_another_owner_cannot_use_the_named_key(tmp_path):
    transit = make_service(tmp_path)
    transit.create_key("alice-token", "application")
    ciphertext = transit.encrypt("alice-token", "application", "")

    with pytest.raises(KeyNotFoundError):
        transit.encrypt("bob-token", "application", "")
    with pytest.raises(KeyNotFoundError):
        transit.decrypt("bob-token", ciphertext)


def test_signing_key_usage_is_rejected_before_key_decryption():
    class Vault:
        def is_locked(self):
            return False

        def get_dek(self):
            raise AssertionError("wrong key usage must be rejected before cryptography")

    class SigningKeyRepository:
        def get_key(self, owner_email, key_name):
            return {
                "key_name": key_name,
                "owner_email": owner_email,
                "key_usage": "SIGN_VERIFY",
                "encrypted_key_material_b64": "unused",
            }

    transit = TransitService(
        Vault(),
        auth_validator=lambda token: "alice@example.com",
        repository=SigningKeyRepository(),
    )
    with pytest.raises(InvalidKeyUsageError):
        transit.encrypt("token", "signing-key", "")
