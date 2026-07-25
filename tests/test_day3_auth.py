"""Security and timing tests for Person 1 Day 3 authentication."""

from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from argon2 import PasswordHasher
from argon2.low_level import Type

from main import main
from src.auth.service import (
    ACCOUNT_LOCKOUT_DURATION,
    INVALID_CREDENTIALS_MESSAGE,
    SESSION_LIFETIME,
    AuthService,
)
from src.core.vault import Vault
from src.crypto_utils import Argon2idParameters
from src.errors import (
    ACCOUNT_LOCKED,
    EMAIL_ALREADY_REGISTERED,
    INVALID_INPUT,
    UNAUTHENTICATED,
    MiniVaultError,
)
from src.storage.repository import (
    SESSIONS_FILE,
    USERS_FILE,
    JsonRepository,
)


EMAIL = "alice@example.com"
USER_PASSPHRASE = "User-Passphrase-7!"
WRONG_PASSPHRASE = "Wrong-Passphrase-2!"
FAST_PASSWORD_HASHER = PasswordHasher(
    time_cost=1,
    memory_cost=8_192,
    parallelism=1,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)
FAST_VAULT_KDF = Argon2idParameters(
    time_cost=1,
    memory_cost_kib=8_192,
    parallelism=1,
)


class MutableClock:
    def __init__(self) -> None:
        self.current = datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.current

    def advance(self, delta: timedelta) -> None:
        self.current += delta


class AuthDay3Tests(unittest.TestCase):
    def _service(self, directory: str, clock: MutableClock) -> AuthService:
        return AuthService(
            JsonRepository(directory),
            password_hasher=FAST_PASSWORD_HASHER,
            clock=clock,
        )

    def _registered_service(
        self,
        directory: str,
        clock: MutableClock,
    ) -> AuthService:
        service = self._service(directory, clock)
        service.register(EMAIL, USER_PASSPHRASE, USER_PASSPHRASE)
        return service

    def test_registration_stores_only_an_argon2id_password_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            service = self._service(directory, MutableClock())
            response = service.register(
                " Alice@Example.COM ",
                USER_PASSPHRASE,
                USER_PASSPHRASE,
            )

            raw_storage = Path(directory, USERS_FILE).read_text("utf-8")
            stored = json.loads(raw_storage)
            user = stored["users"][EMAIL]

            self.assertEqual(response, {"email": EMAIL, "registered": True})
            self.assertTrue(user["password_hash"].startswith("$argon2id$"))
            self.assertTrue(
                FAST_PASSWORD_HASHER.verify(
                    user["password_hash"],
                    USER_PASSPHRASE,
                )
            )
            self.assertNotIn(USER_PASSPHRASE, raw_storage)
            self.assertNotIn("passphrase", user)
            self.assertEqual(user["failed_attempts"], 0)
            self.assertIsNone(user["locked_until"])

    def test_email_is_unique_after_case_normalization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            service = self._registered_service(directory, MutableClock())

            with self.assertRaises(MiniVaultError) as raised:
                service.register(
                    "ALICE@EXAMPLE.COM",
                    USER_PASSPHRASE,
                    USER_PASSPHRASE,
                )

            self.assertEqual(raised.exception.code, EMAIL_ALREADY_REGISTERED)

    def test_registration_rejects_invalid_input_and_mismatched_confirmation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            service = self._service(directory, MutableClock())

            for email, passphrase, confirmation in (
                ("not-an-email", USER_PASSPHRASE, USER_PASSPHRASE),
                (EMAIL, "too-weak", "too-weak"),
                (EMAIL, USER_PASSPHRASE, WRONG_PASSPHRASE),
            ):
                with self.subTest(email=email, passphrase=passphrase):
                    with self.assertRaises(MiniVaultError) as raised:
                        service.register(email, passphrase, confirmation)
                    self.assertEqual(raised.exception.code, INVALID_INPUT)

            self.assertFalse(Path(directory, USERS_FILE).exists())

    def test_successful_login_returns_token_but_stores_only_its_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            clock = MutableClock()
            service = self._registered_service(directory, clock)

            result = service.login(EMAIL, USER_PASSPHRASE)
            raw_sessions = Path(directory, SESSIONS_FILE).read_text("utf-8")
            stored_sessions = json.loads(raw_sessions)["sessions"]
            fingerprint = hashlib.sha256(
                result["token"].encode("ascii")
            ).hexdigest()

            self.assertEqual(result["email"], EMAIL)
            self.assertEqual(
                result["expires_at"],
                (clock.current + SESSION_LIFETIME)
                .isoformat()
                .replace("+00:00", "Z"),
            )
            self.assertGreaterEqual(len(result["token"]), 32)
            self.assertNotIn(result["token"], raw_sessions)
            self.assertIn(fingerprint, stored_sessions)

            # Hashed session storage permits validation after a CLI restart.
            restarted_service = self._service(directory, clock)
            identity = restarted_service.validate_session(result["token"])
            self.assertEqual(identity.email, EMAIL)

    def test_invalid_and_missing_session_tokens_are_unauthenticated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            service = self._registered_service(directory, MutableClock())

            for token in (
                "",
                "not-a-valid-session-token",
                " token-with-space ",
                "không-phải-token",
            ):
                with self.subTest(token=token):
                    with self.assertRaises(MiniVaultError) as raised:
                        service.validate_session(token)
                    self.assertEqual(raised.exception.code, UNAUTHENTICATED)

    def test_session_is_rejected_at_exact_expiry_and_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            clock = MutableClock()
            service = self._registered_service(directory, clock)
            token = service.login(EMAIL, USER_PASSPHRASE)["token"]

            clock.advance(SESSION_LIFETIME - timedelta(microseconds=1))
            self.assertEqual(service.validate_session(token).email, EMAIL)

            clock.advance(timedelta(microseconds=1))
            with self.assertRaises(MiniVaultError) as raised:
                service.validate_session(token)
            self.assertEqual(raised.exception.code, UNAUTHENTICATED)
            sessions = JsonRepository(directory).load(SESSIONS_FILE)["sessions"]
            self.assertEqual(sessions, {})

    def test_five_failures_lock_for_exactly_five_minutes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            clock = MutableClock()
            service = self._registered_service(directory, clock)

            for attempt in range(1, 5):
                with self.subTest(attempt=attempt):
                    with self.assertRaises(MiniVaultError) as raised:
                        service.login(EMAIL, WRONG_PASSPHRASE)
                    self.assertEqual(raised.exception.code, UNAUTHENTICATED)

            with self.assertRaises(MiniVaultError) as fifth:
                service.login(EMAIL, WRONG_PASSPHRASE)
            self.assertEqual(fifth.exception.code, ACCOUNT_LOCKED)

            stored_user = JsonRepository(directory).load(USERS_FILE)["users"][
                EMAIL
            ]
            expected_unlock_time = clock.current + ACCOUNT_LOCKOUT_DURATION
            self.assertEqual(stored_user["failed_attempts"], 5)
            self.assertEqual(
                stored_user["locked_until"],
                expected_unlock_time.isoformat().replace("+00:00", "Z"),
            )

            # A correct passphrase cannot bypass the active lockout.
            clock.advance(ACCOUNT_LOCKOUT_DURATION - timedelta(microseconds=1))
            with self.assertRaises(MiniVaultError) as still_locked:
                service.login(EMAIL, USER_PASSPHRASE)
            self.assertEqual(still_locked.exception.code, ACCOUNT_LOCKED)

            # At exactly five minutes the account is available again.
            clock.advance(timedelta(microseconds=1))
            result = service.login(EMAIL, USER_PASSPHRASE)
            self.assertIn("token", result)
            reset_user = JsonRepository(directory).load(USERS_FILE)["users"][
                EMAIL
            ]
            self.assertEqual(reset_user["failed_attempts"], 0)
            self.assertIsNone(reset_user["locked_until"])

    def test_success_resets_consecutive_failure_counter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            clock = MutableClock()
            service = self._registered_service(directory, clock)

            for _attempt in range(3):
                with self.assertRaises(MiniVaultError):
                    service.login(EMAIL, WRONG_PASSPHRASE)
            service.login(EMAIL, USER_PASSPHRASE)

            user = JsonRepository(directory).load(USERS_FILE)["users"][EMAIL]
            self.assertEqual(user["failed_attempts"], 0)
            self.assertIsNone(user["locked_until"])

    def test_failed_attempts_survive_service_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            clock = MutableClock()
            service = self._registered_service(directory, clock)
            for _attempt in range(2):
                with self.assertRaises(MiniVaultError):
                    service.login(EMAIL, WRONG_PASSPHRASE)

            restarted_service = self._service(directory, clock)
            for _attempt in range(2):
                with self.assertRaises(MiniVaultError) as raised:
                    restarted_service.login(EMAIL, WRONG_PASSPHRASE)
                self.assertEqual(raised.exception.code, UNAUTHENTICATED)
            with self.assertRaises(MiniVaultError) as fifth:
                restarted_service.login(EMAIL, WRONG_PASSPHRASE)
            self.assertEqual(fifth.exception.code, ACCOUNT_LOCKED)

    def test_unknown_account_uses_generic_credentials_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            service = self._service(directory, MutableClock())

            with self.assertRaises(MiniVaultError) as raised:
                service.login("nobody@example.com", USER_PASSPHRASE)

            self.assertEqual(raised.exception.code, UNAUTHENTICATED)
            self.assertEqual(
                raised.exception.message,
                INVALID_CREDENTIALS_MESSAGE,
            )


class AuthCliDay3Tests(unittest.TestCase):
    def test_cli_register_and_login_use_secure_prompts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = JsonRepository(directory)
            clock = MutableClock()
            auth = AuthService(
                repository,
                password_hasher=FAST_PASSWORD_HASHER,
                clock=clock,
            )
            vault = Vault(
                repository,
                kdf_parameters=FAST_VAULT_KDF,
            )

            registration_output = io.StringIO()
            with (
                patch(
                    "main.getpass.getpass",
                    side_effect=[USER_PASSPHRASE, USER_PASSPHRASE],
                ),
                redirect_stdout(registration_output),
            ):
                register_code = main(
                    ["register", "--email", EMAIL],
                    vault=vault,
                    auth=auth,
                )

            login_output = io.StringIO()
            with (
                patch("main.getpass.getpass", return_value=USER_PASSPHRASE),
                redirect_stdout(login_output),
            ):
                login_code = main(
                    ["login", "--email", EMAIL],
                    vault=vault,
                    auth=auth,
                )

            registration = json.loads(registration_output.getvalue())
            login = json.loads(login_output.getvalue())
            self.assertEqual(register_code, 0)
            self.assertEqual(login_code, 0)
            self.assertTrue(registration["registered"])
            self.assertIn("token", login)
            self.assertNotIn(USER_PASSPHRASE, registration_output.getvalue())
            self.assertNotIn(USER_PASSPHRASE, login_output.getvalue())


if __name__ == "__main__":
    unittest.main()
