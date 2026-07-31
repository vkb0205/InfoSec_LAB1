"""JSON file backend for KV ciphertext records."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_DEFAULT_PATH = Path(__file__).resolve().parents[2] / "data" / "kv_store.json"


class KVFileStorage:
    """Load/save path → encrypted record map under one JSON file."""

    def __init__(self, storage_path: str | Path | None = None) -> None:
        self.storage_path = Path(storage_path) if storage_path is not None else _DEFAULT_PATH

    def _load(self) -> dict[str, Any]:
        if not self.storage_path.exists():
            return {}
        try:
            with self.storage_path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                return {}
            return data
        except (OSError, json.JSONDecodeError):
            return {}

    def _save(self, store: dict[str, Any]) -> None:
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        with self.storage_path.open("w", encoding="utf-8") as fh:
            json.dump(store, fh, sort_keys=True, indent=2)

    def get(self, path: str) -> Any:
        return self._load().get(path)

    def set(self, path: str, record: Any) -> None:
        store = self._load()
        store[path] = record
        self._save(store)

    def exists(self, path: str) -> bool:
        return path in self._load()

    def delete(self, path: str) -> None:
        store = self._load()
        if path in store:
            del store[path]
            self._save(store)
