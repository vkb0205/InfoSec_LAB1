"""Person 1 Day 7 end-to-end tests for the public CLI workflow."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from argon2 import PasswordHasher
from argon2.low_level import Type

from main import main
from src.auth.service import AuthService
from src.core.vault import Vault
from src.crypto_utils import Argon2idParameters
from src.storage.repository import (
    SESSIONS_FILE,
    USERS_FILE,
    VAULT_METADATA_FILE,
    JsonRepository,
)


MASTER_PASSPHRASE = "Day-Seven-Master-7!"
USER_PASSPHRASE = "Day-Seven-User-7!"
EMAIL = "alice@example.com"
FAST_KDF = Argon2idParameters(
    time_cost=1,
    memory_cost_kib=8_192,
    parallelism=1,
)
FAST_PASSWORD_HASHER = PasswordHasher(
    time_cost=1,
    memory_cost=8_192,
    parallelism=1,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)
FIXED_TIME = datetime(2026, 7, 25, 16, 0, tzinfo=timezone.utc)


class Person1Day7EndToEndTests(unittest.TestCase):
    """Exercise CLI, services, cryptography, and JSON persistence together."""

    def _services(self, directory: str) -> tuple[Vault, AuthService]:
        repository = JsonRepository(directory)
        return (
            Vault(repository, kdf_parameters=FAST_KDF),
            AuthService(
                repository,
                password_hasher=FAST_PASSWORD_HASHER,
                clock=lambda: FIXED_TIME,
            ),
        )

    def _run_cli(
        self,
        directory: str,
        arguments: list[str],
        *,
        prompts: list[str] | None = None,
    ) -> tuple[int, dict[str, object], str, str]:
        """Run one command with newly constructed process-local services."""

        vault, auth = self._services(directory)
        standard_output = io.StringIO()
        standard_error = io.StringIO()
        with (
            patch(
                "main.getpass.getpass",
                side_effect=prompts if prompts is not None else [],
            ),
            redirect_stdout(standard_output),
            redirect_stderr(standard_error),
        ):
            exit_code = main(arguments, vault=vault, auth=auth)

        output_text = standard_output.getvalue()
        response = json.loads(output_text) if output_text else {}
        return exit_code, response, output_text, standard_error.getvalue()

    def test_vault_and_authentication_cli_flow_survives_restarts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            init_code, initialized, init_output, init_error = self._run_cli(
                directory,
                ["init"],
                prompts=[MASTER_PASSPHRASE, MASTER_PASSPHRASE],
            )
            self.assertEqual(init_code, 0)
            self.assertEqual(
                initialized,
                {"initialized": True, "status": "unlocked"},
            )
            self.assertEqual(init_error, "")

            # A new CLI process receives no plaintext DEK and starts locked.
            status_code, status, _status_output, status_error = self._run_cli(
                directory,
                ["status"],
            )
            self.assertEqual(status_code, 0)
            self.assertEqual(
                status,
                {"initialized": True, "status": "locked"},
            )
            self.assertEqual(status_error, "")

            unlock_code, unlocked, unlock_output, unlock_error = self._run_cli(
                directory,
                ["unlock"],
                prompts=[MASTER_PASSPHRASE],
            )
            self.assertEqual(unlock_code, 0)
            self.assertEqual(
                unlocked,
                {"initialized": True, "status": "unlocked"},
            )
            self.assertEqual(unlock_error, "")

            register_code, registration, register_output, register_error = (
                self._run_cli(
                    directory,
                    ["register", "--email", " Alice@Example.COM "],
                    prompts=[USER_PASSPHRASE, USER_PASSPHRASE],
                )
            )
            self.assertEqual(register_code, 0)
            self.assertEqual(
                registration,
                {"email": EMAIL, "registered": True},
            )
            self.assertEqual(register_error, "")

            login_code, login, login_output, login_error = self._run_cli(
                directory,
                ["login", "--email", EMAIL],
                prompts=[USER_PASSPHRASE],
            )
            self.assertEqual(login_code, 0)
            self.assertEqual(login["email"], EMAIL)
            self.assertIn("expires_at", login)
            self.assertIsInstance(login["token"], str)
            self.assertGreaterEqual(len(login["token"]), 32)
            self.assertEqual(login_error, "")

            token = login["token"]
            validate_code, identity, validate_output, validate_error = (
                self._run_cli(
                    directory,
                    ["validate-session"],
                    prompts=[token],
                )
            )
            self.assertEqual(validate_code, 0)
            self.assertEqual(identity["email"], EMAIL)
            self.assertEqual(identity["expires_at"], login["expires_at"])
            self.assertEqual(validate_error, "")

            # Hidden prompts never echo passphrases. The bearer token is
            # returned once at login but is not repeated by validation.
            non_login_output = "".join(
                (
                    init_output,
                    unlock_output,
                    register_output,
                    validate_output,
                )
            )
            self.assertNotIn(MASTER_PASSPHRASE, non_login_output)
            self.assertNotIn(USER_PASSPHRASE, non_login_output)
            self.assertIn(token, login_output)
            self.assertNotIn(token, validate_output)

            raw_vault = Path(directory, VAULT_METADATA_FILE).read_text("utf-8")
            raw_users = Path(directory, USERS_FILE).read_text("utf-8")
            raw_sessions = Path(directory, SESSIONS_FILE).read_text("utf-8")
            self.assertNotIn(MASTER_PASSPHRASE, raw_vault)
            self.assertNotIn(USER_PASSPHRASE, raw_users)
            self.assertNotIn(token, raw_sessions)
            self.assertIn("$argon2id$", raw_users)


if __name__ == "__main__":
    unittest.main()
