"""Person 1 Day 5 tests for shared request guards and denial auditing."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from argon2 import PasswordHasher
from argon2.low_level import Type

from src.auth.service import AuthService
from src.core.access_control import PERMISSION_DENIED_MESSAGE, RequestGuard
from src.core.vault import Vault
from src.crypto_utils import Argon2idParameters
from src.errors import (
    AUDIT_ERROR,
    INVALID_INPUT,
    PERMISSION_DENIED,
    UNAUTHENTICATED,
    VAULT_LOCKED,
    MiniVaultError,
)
from src.storage.audit_log import AccessDeniedLogger
from src.storage.repository import JsonRepository


MASTER_PASSPHRASE = "Day-Five-Master-8!"
ALICE_PASSPHRASE = "Alice-Passphrase-7!"
FAST_KDF = Argon2idParameters(
    time_cost=1,
    memory_cost_kib=8_192,
    parallelism=1,
)
FAST_HASHER = PasswordHasher(
    time_cost=1,
    memory_cost=8_192,
    parallelism=1,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)
FIXED_TIME = datetime(2026, 7, 25, 12, 30, tzinfo=timezone.utc)


class Day5IntegrationTests(unittest.TestCase):
    def _services(
        self,
        directory: str,
    ) -> tuple[Vault, AuthService, AccessDeniedLogger, str]:
        repository = JsonRepository(directory)
        vault = Vault(repository, kdf_parameters=FAST_KDF)
        vault.initialize(MASTER_PASSPHRASE)
        auth = AuthService(
            repository,
            password_hasher=FAST_HASHER,
            clock=lambda: FIXED_TIME,
        )
        auth.register(
            "alice@example.com",
            ALICE_PASSPHRASE,
            ALICE_PASSPHRASE,
        )
        token = auth.login(
            "alice@example.com",
            ALICE_PASSPHRASE,
        )["token"]
        logger = AccessDeniedLogger(
            Path(directory, "logs"),
            clock=lambda: FIXED_TIME,
        )
        return vault, auth, logger, token

    def test_locked_vault_is_rejected_before_session_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault, auth, logger, token = self._services(directory)
            vault.lock()
            guard = RequestGuard(vault, auth, logger)

            with self.assertRaises(MiniVaultError) as raised:
                guard.authorize_owner(
                    token,
                    "bob@example.com",
                    operation="read",
                    resource_type="kv_path",
                    resource_id="secret/bob@example.com/db",
                )

            self.assertEqual(raised.exception.code, VAULT_LOCKED)
            self.assertFalse(logger.path.exists())

    def test_invalid_token_stops_before_owner_validation_or_logging(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault, auth, logger, _token = self._services(directory)
            guard = RequestGuard(vault, auth, logger)

            with self.assertRaises(MiniVaultError) as raised:
                guard.authorize_owner(
                    "invalid-token",
                    # This would raise INVALID_INPUT if ownership were reached.
                    "not-an-email",
                    operation="read",
                    resource_type="kv_path",
                    resource_id="secret/bob@example.com/db",
                )

            self.assertEqual(raised.exception.code, UNAUTHENTICATED)
            self.assertFalse(logger.path.exists())

    def test_owner_is_allowed_without_creating_denial_log(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault, auth, logger, token = self._services(directory)
            guard = RequestGuard(vault, auth, logger)

            identity = guard.authorize_owner(
                token,
                "ALICE@EXAMPLE.COM",
                operation="write",
                resource_type="kv_path",
                resource_id="secret/alice@example.com/db",
            )

            self.assertEqual(identity.email, "alice@example.com")
            self.assertFalse(logger.path.exists())

    def test_cross_owner_denial_is_logged_then_returns_generic_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault, auth, logger, token = self._services(directory)
            guard = RequestGuard(vault, auth, logger)
            denied_path = "secret/bob@example.com/db"

            with self.assertRaises(MiniVaultError) as raised:
                guard.authorize_owner(
                    token,
                    "bob@example.com",
                    operation="read",
                    resource_type="kv_path",
                    resource_id=denied_path,
                )

            self.assertEqual(raised.exception.code, PERMISSION_DENIED)
            self.assertEqual(
                raised.exception.message,
                PERMISSION_DENIED_MESSAGE,
            )
            self.assertNotIn(denied_path, raised.exception.message)

            raw_log = logger.path.read_text("utf-8")
            event = json.loads(raw_log)
            self.assertEqual(
                event,
                {
                    "event": "access_denied",
                    "operation": "read",
                    "requester_email": "alice@example.com",
                    "resource_id": denied_path,
                    "resource_type": "kv_path",
                    "timestamp": "2026-07-25T12:30:00Z",
                },
            )
            self.assertNotIn(token, raw_log)
            self.assertNotIn(ALICE_PASSPHRASE, raw_log)

    def test_transit_denial_uses_same_non_disclosing_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault, auth, logger, token = self._services(directory)
            guard = RequestGuard(vault, auth, logger)

            with self.assertRaises(MiniVaultError) as raised:
                guard.authorize_owner(
                    token,
                    "bob@example.com",
                    operation="encrypt",
                    resource_type="transit_key",
                    resource_id="payments-key",
                )

            self.assertEqual(raised.exception.code, PERMISSION_DENIED)
            self.assertEqual(
                raised.exception.message,
                PERMISSION_DENIED_MESSAGE,
            )
            event = json.loads(logger.path.read_text("utf-8"))
            self.assertEqual(event["resource_type"], "transit_key")
            self.assertEqual(event["resource_id"], "payments-key")

    def test_json_lines_encoding_prevents_log_injection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            logger = AccessDeniedLogger(
                directory,
                clock=lambda: FIXED_TIME,
            )
            injected_resource = "secret/bob@example.com/db\nforged-event"

            logger.log_access_denied(
                requester_email="alice@example.com",
                operation="read",
                resource_type="kv_path",
                resource_id=injected_resource,
            )

            raw_log = logger.path.read_text("utf-8")
            self.assertEqual(len(raw_log.splitlines()), 1)
            self.assertEqual(
                json.loads(raw_log)["resource_id"],
                injected_resource,
            )

    def test_invalid_audit_filename_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(MiniVaultError) as raised:
                AccessDeniedLogger(
                    directory,
                    filename="../outside.jsonl",
                )
            self.assertEqual(raised.exception.code, INVALID_INPUT)

    def test_audit_failure_still_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault, auth, _logger, token = self._services(directory)
            invalid_log_directory = Path(directory, "not-a-directory")
            invalid_log_directory.write_text("occupied", encoding="utf-8")
            failing_logger = AccessDeniedLogger(invalid_log_directory)
            guard = RequestGuard(vault, auth, failing_logger)

            with self.assertRaises(MiniVaultError) as raised:
                guard.authorize_owner(
                    token,
                    "bob@example.com",
                    operation="decrypt",
                    resource_type="transit_key",
                    resource_id="payments-key",
                )

            self.assertEqual(raised.exception.code, AUDIT_ERROR)


if __name__ == "__main__":
    unittest.main()
