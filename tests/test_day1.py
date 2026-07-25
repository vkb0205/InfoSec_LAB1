"""Person 1 Day 1 tests that require only the Python standard library."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from main import main
from src.errors import (
    INVALID_KEY_USAGE,
    NOT_FOUND,
    PERMISSION_DENIED,
    REQUIRED_ERROR_CODES,
    UNAUTHENTICATED,
    VAULT_LOCKED,
    MiniVaultError,
)
from src.storage.repository import JsonRepository


class SharedErrorTests(unittest.TestCase):
    def test_required_error_contract_is_defined(self) -> None:
        self.assertEqual(
            REQUIRED_ERROR_CODES,
            {
                VAULT_LOCKED,
                UNAUTHENTICATED,
                PERMISSION_DENIED,
                NOT_FOUND,
                INVALID_KEY_USAGE,
            },
        )

    def test_error_has_stable_boundary_representation(self) -> None:
        error = MiniVaultError(VAULT_LOCKED, "Vault is locked.")
        self.assertEqual(
            error.to_dict(),
            {"error_code": "VAULT_LOCKED", "message": "Vault is locked."},
        )


class JsonRepositoryTests(unittest.TestCase):
    def test_round_trip_uses_json_object(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = JsonRepository(directory)
            repository.save("example.json", {"owner": "alice@example.com"})

            self.assertEqual(
                repository.load("example.json"),
                {"owner": "alice@example.com"},
            )
            self.assertEqual(
                json.loads(Path(directory, "example.json").read_text("utf-8")),
                {"owner": "alice@example.com"},
            )

    def test_missing_file_returns_empty_object(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(JsonRepository(directory).load("missing.json"), {})

    def test_filename_cannot_escape_data_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = JsonRepository(directory)
            with self.assertRaises(MiniVaultError):
                repository.load("../outside.json")


class CliSkeletonTests(unittest.TestCase):
    def _run(self, *arguments: str) -> tuple[int, dict[str, object]]:
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = main(arguments)
        return exit_code, json.loads(output.getvalue())

    def test_health_command_reports_json_storage(self) -> None:
        exit_code, response = self._run("health")
        self.assertEqual(exit_code, 0)
        self.assertEqual(response["status"], "healthy")
        self.assertEqual(response["storage_backend"], "json")

    def test_interfaces_command_publishes_team_contracts(self) -> None:
        exit_code, response = self._run("interfaces")
        self.assertEqual(exit_code, 0)
        self.assertIn("kv", response["interfaces"])
        self.assertIn("transit", response["interfaces"])


if __name__ == "__main__":
    unittest.main()
