"""Atomic JSON persistence for Mini Vault.

JSON is the agreed Day 1 storage format.  This repository deliberately handles
serialization only: encryption, authentication, and authorization belong to
the core, auth, KV, and Transit services.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from src.errors import INVALID_INPUT, STORAGE_ERROR, MiniVaultError


VAULT_METADATA_FILE = "vault.json"
USERS_FILE = "users.json"
KV_SECRETS_FILE = "kv_secrets.json"
TRANSIT_KEYS_FILE = "transit_keys.json"


class JsonRepository:
    """Load and atomically save JSON objects below one data directory."""

    def __init__(self, data_dir: str | Path = "data") -> None:
        self.data_dir = Path(data_dir)

    def _path_for(self, filename: str) -> Path:
        candidate = Path(filename)
        if (
            not filename
            or candidate.is_absolute()
            or candidate.name != filename
            or candidate.suffix.lower() != ".json"
        ):
            raise MiniVaultError(
                INVALID_INPUT,
                "Storage filename must be a plain .json filename.",
            )
        return self.data_dir / candidate

    def exists(self, filename: str) -> bool:
        """Return whether a validated storage file already exists."""

        return self._path_for(filename).is_file()

    def load(self, filename: str) -> dict[str, Any]:
        """Return a stored JSON object, or an empty object if it does not exist."""

        path = self._path_for(filename)
        if not path.exists():
            return {}

        try:
            with path.open("r", encoding="utf-8") as handle:
                value = json.load(handle)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise MiniVaultError(
                STORAGE_ERROR,
                f"Could not read JSON storage file: {filename}",
            ) from exc

        if not isinstance(value, dict):
            raise MiniVaultError(
                STORAGE_ERROR,
                f"JSON storage file must contain an object: {filename}",
            )
        return value

    def save(self, filename: str, data: Mapping[str, Any]) -> None:
        """Atomically replace a JSON object without leaving a partial file."""

        path = self._path_for(filename)
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.data_dir,
                prefix=f".{path.stem}-",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temp_path = Path(handle.name)
                json.dump(dict(data), handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, path)
        except (OSError, TypeError, ValueError) as exc:
            if "temp_path" in locals():
                temp_path.unlink(missing_ok=True)
            raise MiniVaultError(
                STORAGE_ERROR,
                f"Could not write JSON storage file: {filename}",
            ) from exc
