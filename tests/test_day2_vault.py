"""Security tests for Person 1 Day 2 vault initialization and unlock."""

from __future__ import annotations

import base64
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from main import main
from src.core.vault import GENERIC_UNLOCK_MESSAGE, Vault
from src.crypto_utils import (
    AES_256_KEY_BYTES,
    AES_GCM_NONCE_BYTES,
    AES_GCM_TAG_BYTES,
    ARGON2_SALT_BYTES,
    Argon2idParameters,
)
from src.errors import (
    ALREADY_INITIALIZED,
    INVALID_INPUT,
    UNLOCK_FAILED,
    VAULT_LOCKED,
    MiniVaultError,
)
from src.storage.repository import VAULT_METADATA_FILE, JsonRepository


STRONG_PASSPHRASE = "Correct-Horse-9!"
WRONG_PASSPHRASE = "Incorrect-Horse-8!"
FAST_TEST_KDF = Argon2idParameters(
    time_cost=1,
    memory_cost_kib=8_192,
    parallelism=1,
)


class DeterministicRandom:
    """Provide known values so tests can prove the DEK is not persisted."""

    def __init__(self) -> None:
        self.values = iter(
            (
                b"S" * ARGON2_SALT_BYTES,
                b"D" * AES_256_KEY_BYTES,
                b"N" * AES_GCM_NONCE_BYTES,
            )
        )

    def __call__(self, length: int) -> bytes:
        value = next(self.values)
        if len(value) != length:
            raise AssertionError("Unexpected random byte request.")
        return value


class VaultDay2Tests(unittest.TestCase):
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

    def test_weak_master_passphrase_is_rejected_before_storage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault = self._vault(directory)
            with self.assertRaises(MiniVaultError) as raised:
                vault.initialize("too-weak")

            self.assertEqual(raised.exception.code, INVALID_INPUT)
            self.assertFalse(Path(directory, VAULT_METADATA_FILE).exists())

    def test_initialization_stores_only_encrypted_dek_and_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            known_dek = b"D" * AES_256_KEY_BYTES
            vault = self._vault(
                directory,
                random_bytes=DeterministicRandom(),
            )
            response = vault.initialize(STRONG_PASSPHRASE)

            metadata_path = Path(directory, VAULT_METADATA_FILE)
            raw_storage = metadata_path.read_text(encoding="utf-8")
            metadata = json.loads(raw_storage)
            encrypted_blob = base64.b64decode(
                metadata["encrypted_dek_b64"],
                validate=True,
            )

            self.assertEqual(response["status"], "unlocked")
            self.assertEqual(metadata["kdf"], "argon2id")
            self.assertEqual(metadata["status"], "locked")
            self.assertNotIn(STRONG_PASSPHRASE, raw_storage)
            self.assertNotIn(base64.b64encode(known_dek).decode(), raw_storage)
            self.assertNotIn("plaintext_dek", metadata)
            self.assertNotIn("dek", metadata)
            self.assertEqual(
                len(encrypted_blob),
                AES_GCM_NONCE_BYTES + AES_256_KEY_BYTES + AES_GCM_TAG_BYTES,
            )

    def test_new_instance_always_starts_locked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            initialized_vault = self._vault(directory)
            initialized_vault.initialize(STRONG_PASSPHRASE)
            self.assertFalse(initialized_vault.is_locked)

            restarted_vault = self._vault(directory)
            self.assertTrue(restarted_vault.is_locked)
            with self.assertRaises(MiniVaultError) as raised:
                restarted_vault.require_unlocked()
            self.assertEqual(raised.exception.code, VAULT_LOCKED)

    def test_correct_master_passphrase_unlocks_after_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self._vault(directory).initialize(STRONG_PASSPHRASE)
            restarted_vault = self._vault(directory)

            response = restarted_vault.unlock(STRONG_PASSPHRASE)
            persisted_metadata = JsonRepository(directory).load(
                VAULT_METADATA_FILE
            )

            self.assertEqual(response["status"], "unlocked")
            self.assertFalse(restarted_vault.is_locked)
            self.assertEqual(persisted_metadata["status"], "locked")
            restarted_vault.require_unlocked()

    def test_wrong_master_passphrase_fails_generically_and_stays_locked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self._vault(directory).initialize(STRONG_PASSPHRASE)
            restarted_vault = self._vault(directory)

            with self.assertRaises(MiniVaultError) as raised:
                restarted_vault.unlock(WRONG_PASSPHRASE)

            self.assertEqual(raised.exception.code, UNLOCK_FAILED)
            self.assertEqual(raised.exception.message, GENERIC_UNLOCK_MESSAGE)
            self.assertTrue(restarted_vault.is_locked)

    def test_tampered_encrypted_dek_uses_same_generic_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self._vault(directory).initialize(STRONG_PASSPHRASE)
            repository = JsonRepository(directory)
            metadata = repository.load(VAULT_METADATA_FILE)
            encrypted_blob = bytearray(
                base64.b64decode(metadata["encrypted_dek_b64"], validate=True)
            )
            encrypted_blob[-1] ^= 1
            metadata["encrypted_dek_b64"] = base64.b64encode(
                encrypted_blob
            ).decode("ascii")
            repository.save(VAULT_METADATA_FILE, metadata)

            restarted_vault = self._vault(directory)
            with self.assertRaises(MiniVaultError) as raised:
                restarted_vault.unlock(STRONG_PASSPHRASE)

            self.assertEqual(raised.exception.code, UNLOCK_FAILED)
            self.assertEqual(raised.exception.message, GENERIC_UNLOCK_MESSAGE)
            self.assertTrue(restarted_vault.is_locked)

    def test_tampered_kdf_cost_is_rejected_before_resource_use(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self._vault(directory).initialize(STRONG_PASSPHRASE)
            repository = JsonRepository(directory)
            metadata = repository.load(VAULT_METADATA_FILE)
            metadata["kdf_parameters"]["memory_cost_kib"] = 999_999_999
            repository.save(VAULT_METADATA_FILE, metadata)

            with self.assertRaises(MiniVaultError) as raised:
                self._vault(directory).unlock(STRONG_PASSPHRASE)

            self.assertEqual(raised.exception.code, UNLOCK_FAILED)
            self.assertEqual(raised.exception.message, GENERIC_UNLOCK_MESSAGE)

    def test_independent_vaults_use_fresh_salts_and_nonces(self) -> None:
        with (
            tempfile.TemporaryDirectory() as first_directory,
            tempfile.TemporaryDirectory() as second_directory,
        ):
            self._vault(first_directory).initialize(STRONG_PASSPHRASE)
            self._vault(second_directory).initialize(STRONG_PASSPHRASE)
            first = JsonRepository(first_directory).load(VAULT_METADATA_FILE)
            second = JsonRepository(second_directory).load(VAULT_METADATA_FILE)

            self.assertNotEqual(
                first["kdf_salt_b64"],
                second["kdf_salt_b64"],
            )
            self.assertNotEqual(
                first["encrypted_dek_b64"],
                second["encrypted_dek_b64"],
            )

    def test_reinitialization_is_rejected_without_replacing_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault = self._vault(directory)
            vault.initialize(STRONG_PASSPHRASE)
            metadata_before = Path(
                directory,
                VAULT_METADATA_FILE,
            ).read_bytes()

            with self.assertRaises(MiniVaultError) as raised:
                self._vault(directory).initialize(WRONG_PASSPHRASE)

            self.assertEqual(raised.exception.code, ALREADY_INITIALIZED)
            self.assertEqual(
                Path(directory, VAULT_METADATA_FILE).read_bytes(),
                metadata_before,
            )
            self._vault(directory).unlock(STRONG_PASSPHRASE)


class VaultCliDay2Tests(unittest.TestCase):
    def test_cli_init_prompts_instead_of_accepting_passphrase_argument(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault = Vault(
                JsonRepository(directory),
                kdf_parameters=FAST_TEST_KDF,
            )
            output = io.StringIO()
            with (
                patch(
                    "main.getpass.getpass",
                    side_effect=[STRONG_PASSPHRASE, STRONG_PASSPHRASE],
                ),
                redirect_stdout(output),
            ):
                exit_code = main(["init"], vault=vault)

            response = json.loads(output.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(response["status"], "unlocked")
            self.assertNotIn(STRONG_PASSPHRASE, output.getvalue())

    def test_cli_wrong_unlock_returns_only_generic_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self._vault_for_cli(directory).initialize(STRONG_PASSPHRASE)
            restarted_vault = self._vault_for_cli(directory)
            errors = io.StringIO()

            with (
                patch("main.getpass.getpass", return_value=WRONG_PASSPHRASE),
                redirect_stderr(errors),
            ):
                exit_code = main(["unlock"], vault=restarted_vault)

            response = json.loads(errors.getvalue())
            self.assertEqual(exit_code, 1)
            self.assertEqual(response["error_code"], UNLOCK_FAILED)
            self.assertEqual(response["message"], GENERIC_UNLOCK_MESSAGE)
            self.assertEqual(set(response), {"error_code", "message"})

    @staticmethod
    def _vault_for_cli(directory: str) -> Vault:
        return Vault(
            JsonRepository(directory),
            kdf_parameters=FAST_TEST_KDF,
        )


if __name__ == "__main__":
    unittest.main()
