"""Day 6 acceptance tests assigned to Person 1.

These tests mirror the eight Person 1 cases listed in PLAN.md and the minimum
test list in SPEC.md.  KV and Transit must both enter through RequestGuard, so
their locked-state contract is tested at that shared boundary until the
teammate-owned feature services expose concrete operations.
"""

from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from argon2 import PasswordHasher
from argon2.low_level import Type

from src.auth.service import (
    ACCOUNT_LOCKOUT_DURATION,
    SESSION_LIFETIME,
    AuthService,
)
from src.core.access_control import RequestGuard
from src.core.vault import GENERIC_UNLOCK_MESSAGE, Vault
from src.crypto_utils import (
    AES_256_KEY_BYTES,
    AES_GCM_NONCE_BYTES,
    AES_GCM_TAG_BYTES,
    ARGON2_SALT_BYTES,
    Argon2idParameters,
)
from src.errors import (
    ACCOUNT_LOCKED,
    UNAUTHENTICATED,
    UNLOCK_FAILED,
    VAULT_LOCKED,
    MiniVaultError,
)
from src.storage.audit_log import AccessDeniedLogger
from src.storage.repository import (
    SESSIONS_FILE,
    USERS_FILE,
    VAULT_METADATA_FILE,
    JsonRepository,
)


MASTER_PASSPHRASE = "Day-Six-Master-8!"
WRONG_MASTER_PASSPHRASE = "Wrong-Day-Six-7!"
EMAIL = "alice@example.com"
USER_PASSPHRASE = "Alice-Day-Six-6!"
WRONG_USER_PASSPHRASE = "Wrong-Day-Six-5!"
KNOWN_DEK = b"D" * AES_256_KEY_BYTES

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


class MutableClock:
    """Provide exact session-expiry and account-lockout boundary times."""

    def __init__(self) -> None:
        self.current = datetime(2026, 7, 25, 14, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.current

    def advance(self, delta: timedelta) -> None:
        self.current += delta


class KnownVaultRandom:
    """Provide a known DEK so the storage test can search for plaintext."""

    def __init__(self) -> None:
        self._values = iter(
            (
                b"S" * ARGON2_SALT_BYTES,
                KNOWN_DEK,
                b"N" * AES_GCM_NONCE_BYTES,
            )
        )

    def __call__(self, length: int) -> bytes:
        value = next(self._values)
        if len(value) != length:
            raise AssertionError("Unexpected random byte request.")
        return value


class Person1Day6AcceptanceTests(unittest.TestCase):
    """Required vault and authentication acceptance tests for Person 1."""

    def _vault(
        self,
        directory: str,
        *,
        random_bytes=None,
    ) -> Vault:
        arguments = {
            "repository": JsonRepository(directory),
            "kdf_parameters": FAST_KDF,
        }
        if random_bytes is not None:
            arguments["random_bytes"] = random_bytes
        return Vault(**arguments)

    def _auth(self, directory: str, clock: MutableClock) -> AuthService:
        return AuthService(
            JsonRepository(directory),
            password_hasher=FAST_PASSWORD_HASHER,
            clock=clock,
        )

    def _registered_auth(
        self,
        directory: str,
        clock: MutableClock,
    ) -> AuthService:
        auth = self._auth(directory, clock)
        auth.register(EMAIL, USER_PASSPHRASE, USER_PASSPHRASE)
        return auth

    def test_vault_initialization_stores_only_encrypted_dek(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault = self._vault(
                directory,
                random_bytes=KnownVaultRandom(),
            )
            vault.initialize(MASTER_PASSPHRASE)

            raw_storage = Path(directory, VAULT_METADATA_FILE).read_text(
                encoding="utf-8"
            )
            metadata = json.loads(raw_storage)
            encrypted_dek = base64.b64decode(
                metadata["encrypted_dek_b64"],
                validate=True,
            )

            self.assertEqual(
                set(metadata),
                {
                    "version",
                    "kdf",
                    "kdf_salt_b64",
                    "kdf_parameters",
                    "encrypted_dek_b64",
                    "status",
                },
            )
            self.assertEqual(metadata["status"], "locked")
            self.assertEqual(
                len(encrypted_dek),
                AES_GCM_NONCE_BYTES
                + AES_256_KEY_BYTES
                + AES_GCM_TAG_BYTES,
            )
            self.assertNotIn(
                base64.b64encode(KNOWN_DEK).decode("ascii"),
                raw_storage,
            )
            self.assertNotIn(MASTER_PASSPHRASE, raw_storage)
            self.assertNotIn("plaintext_dek", metadata)

    def test_vault_restart_returns_to_locked_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self._vault(directory).initialize(MASTER_PASSPHRASE)

            restarted_vault = self._vault(directory)

            self.assertTrue(restarted_vault.is_locked)
            with self.assertRaises(MiniVaultError) as raised:
                restarted_vault.require_unlocked()
            self.assertEqual(raised.exception.code, VAULT_LOCKED)

    def test_wrong_master_passphrase_fails_unlock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self._vault(directory).initialize(MASTER_PASSPHRASE)
            restarted_vault = self._vault(directory)

            with self.assertRaises(MiniVaultError) as raised:
                restarted_vault.unlock(WRONG_MASTER_PASSPHRASE)

            self.assertEqual(raised.exception.code, UNLOCK_FAILED)
            self.assertEqual(raised.exception.message, GENERIC_UNLOCK_MESSAGE)
            self.assertTrue(restarted_vault.is_locked)

    def test_feature_1_and_feature_2_fail_while_locked(self) -> None:
        """Exercise the mandatory entry guard for both feature families."""

        with tempfile.TemporaryDirectory() as directory:
            clock = MutableClock()
            vault = self._vault(directory)
            vault.initialize(MASTER_PASSPHRASE)
            auth = self._registered_auth(directory, clock)
            token = auth.login(EMAIL, USER_PASSPHRASE)["token"]
            audit = AccessDeniedLogger(Path(directory, "logs"), clock=clock)
            guard = RequestGuard(vault, auth, audit)
            vault.lock()

            feature_requests = (
                {
                    "operation": "write",
                    "resource_type": "kv_path",
                    "resource_id": f"secret/{EMAIL}/database",
                },
                {
                    "operation": "encrypt",
                    "resource_type": "transit_key",
                    "resource_id": "payments-key",
                },
            )
            for request in feature_requests:
                with self.subTest(feature=request["resource_type"]):
                    with self.assertRaises(MiniVaultError) as raised:
                        guard.authorize_owner(
                            token,
                            EMAIL,
                            **request,
                        )
                    self.assertEqual(raised.exception.code, VAULT_LOCKED)

            # Lock rejection occurs before authorization and must not produce
            # a misleading cross-owner audit record.
            self.assertFalse(audit.path.exists())

    def test_registration_persists_only_argon2id_password_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self._registered_auth(directory, MutableClock())

            raw_storage = Path(directory, USERS_FILE).read_text("utf-8")
            user = json.loads(raw_storage)["users"][EMAIL]

            self.assertTrue(user["password_hash"].startswith("$argon2id$"))
            self.assertTrue(
                FAST_PASSWORD_HASHER.verify(
                    user["password_hash"],
                    USER_PASSPHRASE,
                )
            )
            self.assertNotIn(USER_PASSPHRASE, raw_storage)
            self.assertNotIn("password", user)
            self.assertNotIn("passphrase", user)

    def test_successful_login_returns_session_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            auth = self._registered_auth(directory, MutableClock())

            response = auth.login(EMAIL, USER_PASSPHRASE)
            raw_sessions = Path(directory, SESSIONS_FILE).read_text("utf-8")
            fingerprint = hashlib.sha256(
                response["token"].encode("utf-8")
            ).hexdigest()
            sessions = json.loads(raw_sessions)["sessions"]

            self.assertEqual(response["email"], EMAIL)
            self.assertGreaterEqual(len(response["token"]), 32)
            self.assertIn("expires_at", response)
            self.assertNotIn(response["token"], raw_sessions)
            self.assertIn(fingerprint, sessions)

    def test_expired_session_token_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            clock = MutableClock()
            auth = self._registered_auth(directory, clock)
            token = auth.login(EMAIL, USER_PASSPHRASE)["token"]

            clock.advance(SESSION_LIFETIME)
            with self.assertRaises(MiniVaultError) as raised:
                auth.validate_session(token)

            self.assertEqual(raised.exception.code, UNAUTHENTICATED)
            self.assertEqual(
                JsonRepository(directory).load(SESSIONS_FILE)["sessions"],
                {},
            )

    def test_five_failed_logins_lock_account_for_exactly_five_minutes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            clock = MutableClock()
            auth = self._registered_auth(directory, clock)

            for attempt in range(1, 5):
                with self.subTest(attempt=attempt):
                    with self.assertRaises(MiniVaultError) as raised:
                        auth.login(EMAIL, WRONG_USER_PASSPHRASE)
                    self.assertEqual(raised.exception.code, UNAUTHENTICATED)

            with self.assertRaises(MiniVaultError) as fifth:
                auth.login(EMAIL, WRONG_USER_PASSPHRASE)
            self.assertEqual(fifth.exception.code, ACCOUNT_LOCKED)

            expected_unlock = clock.current + ACCOUNT_LOCKOUT_DURATION
            stored_user = JsonRepository(directory).load(USERS_FILE)["users"][
                EMAIL
            ]
            self.assertEqual(stored_user["failed_attempts"], 5)
            self.assertEqual(
                stored_user["locked_until"],
                expected_unlock.isoformat().replace("+00:00", "Z"),
            )

            clock.advance(
                ACCOUNT_LOCKOUT_DURATION - timedelta(microseconds=1)
            )
            with self.assertRaises(MiniVaultError) as still_locked:
                auth.login(EMAIL, USER_PASSPHRASE)
            self.assertEqual(still_locked.exception.code, ACCOUNT_LOCKED)

            clock.advance(timedelta(microseconds=1))
            self.assertIn("token", auth.login(EMAIL, USER_PASSPHRASE))


if __name__ == "__main__":
    unittest.main()
