"""Person 1 Day 4 tests for safe in-memory DEK operations."""

from __future__ import annotations

import base64
import json
import tempfile
import unittest
from dataclasses import replace

from src.core.vault import Vault
from src.crypto_utils import (
    AES_256_KEY_BYTES,
    AES_GCM_NONCE_BYTES,
    ARGON2_SALT_BYTES,
    AesGcmEnvelope,
    Argon2idParameters,
)
from src.errors import (
    INTEGRITY_ERROR,
    INVALID_INPUT,
    VAULT_LOCKED,
    MiniVaultError,
)
from src.storage.repository import JsonRepository


MASTER_PASSPHRASE = "Day-Four-Master-9!"
FAST_TEST_KDF = Argon2idParameters(
    time_cost=1,
    memory_cost_kib=8_192,
    parallelism=1,
)
KNOWN_DEK = b"D" * AES_256_KEY_BYTES
KV_ASSOCIATED_DATA = b"mini-vault:kv:v1:secret/alice@example.com/db"


class SequenceRandom:
    def __init__(self, *values: bytes) -> None:
        self._values = iter(values)

    def __call__(self, length: int) -> bytes:
        value = next(self._values)
        if len(value) != length:
            raise AssertionError("Unexpected random byte request.")
        return value


class DekCryptoDay4Tests(unittest.TestCase):
    def _vault(
        self,
        directory: str,
        *,
        random_bytes=None,
    ) -> Vault:
        arguments = {
            "repository": JsonRepository(directory),
            "kdf_parameters": FAST_TEST_KDF,
        }
        if random_bytes is not None:
            arguments["random_bytes"] = random_bytes
        return Vault(**arguments)

    def test_dek_operations_fail_while_locked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault = self._vault(directory)
            envelope = AesGcmEnvelope(
                nonce=b"N" * AES_GCM_NONCE_BYTES,
                ciphertext=b"ciphertext",
                tag=b"T" * 16,
            )

            for operation in (
                lambda: vault.encrypt_with_dek(
                    b"secret",
                    associated_data=KV_ASSOCIATED_DATA,
                ),
                lambda: vault.decrypt_with_dek(
                    envelope,
                    associated_data=KV_ASSOCIATED_DATA,
                ),
            ):
                with self.subTest(operation=operation):
                    with self.assertRaises(MiniVaultError) as raised:
                        operation()
                    self.assertEqual(raised.exception.code, VAULT_LOCKED)

    def test_encrypt_decrypt_round_trip_uses_storage_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault = self._vault(directory)
            vault.initialize(MASTER_PASSPHRASE)
            plaintext = b'{"username":"alice","password":"correct horse"}'

            envelope = vault.encrypt_with_dek(
                plaintext,
                associated_data=KV_ASSOCIATED_DATA,
            )
            stored_fields = envelope.to_base64_fields()
            restored_envelope = AesGcmEnvelope.from_base64_fields(stored_fields)
            decrypted = vault.decrypt_with_dek(
                restored_envelope,
                associated_data=KV_ASSOCIATED_DATA,
            )

            self.assertEqual(decrypted, plaintext)
            self.assertEqual(restored_envelope, envelope)
            self.assertEqual(AesGcmEnvelope.unpack(envelope.pack()), envelope)
            self.assertEqual(
                set(stored_fields),
                {"nonce_b64", "ciphertext_b64", "tag_b64"},
            )
            self.assertNotIn(
                plaintext.decode("utf-8"),
                json.dumps(stored_fields),
            )

    def test_each_encryption_uses_a_fresh_nonce(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            random_source = SequenceRandom(
                b"S" * ARGON2_SALT_BYTES,
                KNOWN_DEK,
                b"W" * AES_GCM_NONCE_BYTES,
                b"A" * AES_GCM_NONCE_BYTES,
                b"B" * AES_GCM_NONCE_BYTES,
            )
            vault = self._vault(directory, random_bytes=random_source)
            vault.initialize(MASTER_PASSPHRASE)

            first = vault.encrypt_with_dek(
                b"same plaintext",
                associated_data=KV_ASSOCIATED_DATA,
            )
            second = vault.encrypt_with_dek(
                b"same plaintext",
                associated_data=KV_ASSOCIATED_DATA,
            )

            self.assertNotEqual(first.nonce, second.nonce)
            self.assertNotEqual(first.ciphertext, second.ciphertext)
            self.assertEqual(first.nonce, b"A" * AES_GCM_NONCE_BYTES)
            self.assertEqual(second.nonce, b"B" * AES_GCM_NONCE_BYTES)

    def test_faulty_random_source_cannot_reuse_a_live_dek_nonce(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repeated_nonce = b"A" * AES_GCM_NONCE_BYTES
            random_source = SequenceRandom(
                b"S" * ARGON2_SALT_BYTES,
                KNOWN_DEK,
                b"W" * AES_GCM_NONCE_BYTES,
                repeated_nonce,
                *([repeated_nonce] * 8),
            )
            vault = self._vault(directory, random_bytes=random_source)
            vault.initialize(MASTER_PASSPHRASE)
            vault.encrypt_with_dek(
                b"first",
                associated_data=KV_ASSOCIATED_DATA,
            )

            with self.assertRaises(RuntimeError):
                vault.encrypt_with_dek(
                    b"second",
                    associated_data=KV_ASSOCIATED_DATA,
                )

    def test_tampered_ciphertext_or_tag_returns_no_plaintext(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault = self._vault(directory)
            vault.initialize(MASTER_PASSPHRASE)
            envelope = vault.encrypt_with_dek(
                b"sensitive value",
                associated_data=KV_ASSOCIATED_DATA,
            )
            tampered_ciphertext = bytearray(envelope.ciphertext)
            tampered_ciphertext[0] ^= 1
            tampered_tag = bytearray(envelope.tag)
            tampered_tag[-1] ^= 1

            for tampered in (
                replace(envelope, ciphertext=bytes(tampered_ciphertext)),
                replace(envelope, tag=bytes(tampered_tag)),
            ):
                with self.subTest(tampered=tampered):
                    with self.assertRaises(MiniVaultError) as raised:
                        vault.decrypt_with_dek(
                            tampered,
                            associated_data=KV_ASSOCIATED_DATA,
                        )
                    self.assertEqual(raised.exception.code, INTEGRITY_ERROR)

    def test_associated_data_binds_ciphertext_to_its_resource(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault = self._vault(directory)
            vault.initialize(MASTER_PASSPHRASE)
            envelope = vault.encrypt_with_dek(
                b"sensitive value",
                associated_data=KV_ASSOCIATED_DATA,
            )

            with self.assertRaises(MiniVaultError) as raised:
                vault.decrypt_with_dek(
                    envelope,
                    associated_data=b"mini-vault:kv:v1:secret/bob@example.com/db",
                )

            self.assertEqual(raised.exception.code, INTEGRITY_ERROR)

    def test_public_operations_never_return_the_raw_dek(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            random_source = SequenceRandom(
                b"S" * ARGON2_SALT_BYTES,
                KNOWN_DEK,
                b"W" * AES_GCM_NONCE_BYTES,
                b"A" * AES_GCM_NONCE_BYTES,
            )
            vault = self._vault(directory, random_bytes=random_source)
            vault.initialize(MASTER_PASSPHRASE)
            envelope = vault.encrypt_with_dek(
                b"payload",
                associated_data=KV_ASSOCIATED_DATA,
            )

            serialized = json.dumps(envelope.to_base64_fields())
            self.assertFalse(hasattr(vault, "get_dek"))
            self.assertNotIn(base64.b64encode(KNOWN_DEK).decode(), serialized)
            self.assertNotEqual(envelope.pack(), KNOWN_DEK)

    def test_lock_best_effort_zeroes_the_in_memory_dek(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault = self._vault(directory)
            vault.initialize(MASTER_PASSPHRASE)
            dek_reference = vault._dek
            self.assertIsNotNone(dek_reference)

            response = vault.lock()

            self.assertEqual(response["status"], "locked")
            self.assertTrue(all(value == 0 for value in dek_reference))
            with self.assertRaises(MiniVaultError) as raised:
                vault.encrypt_with_dek(
                    b"secret",
                    associated_data=KV_ASSOCIATED_DATA,
                )
            self.assertEqual(raised.exception.code, VAULT_LOCKED)

    def test_crypto_boundary_rejects_wrong_types_and_malformed_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault = self._vault(directory)
            vault.initialize(MASTER_PASSPHRASE)

            for operation in (
                lambda: vault.encrypt_with_dek(
                    "not bytes",
                    associated_data=KV_ASSOCIATED_DATA,
                ),
                lambda: vault.decrypt_with_dek(
                    b"not an envelope",
                    associated_data=KV_ASSOCIATED_DATA,
                ),
            ):
                with self.assertRaises(MiniVaultError) as raised:
                    operation()
                self.assertEqual(raised.exception.code, INVALID_INPUT)

            with self.assertRaises(ValueError):
                AesGcmEnvelope.from_base64_fields(
                    {
                        "nonce_b64": "not-valid-base64!",
                        "ciphertext_b64": "",
                        "tag_b64": "",
                    }
                )


if __name__ == "__main__":
    unittest.main()
