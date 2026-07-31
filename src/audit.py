"""Small SHA-256 hash-chained audit log."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

DEFAULT_AUDIT_LOG_PATH = (
    Path(__file__).resolve().parents[1] / "data/logs/audit.jsonl"
)
GENESIS_HASH = "0" * 64
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
RESERVED_FIELDS = frozenset({
    "sequence",
    "timestamp",
    "previous_hash",
    "entry_hash",
})


class AuditIntegrityError(ValueError):
    """The persisted audit chain is malformed or no longer valid."""


def _canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _entry_hash(entry_without_hash: dict[str, Any]) -> str:
    return hashlib.sha256(
        _canonical_json(entry_without_hash).encode("utf-8")
    ).hexdigest()


class AuditLog:
    """Append and verify canonical JSONL entries linked by SHA-256 hashes."""

    def __init__(
        self,
        path: str | Path = DEFAULT_AUDIT_LOG_PATH,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.path = Path(path)
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def append(self, event_fields: dict[str, Any]) -> dict[str, Any]:
        if (
            not isinstance(event_fields, dict)
            or not event_fields
            or not all(isinstance(key, str) for key in event_fields)
            or RESERVED_FIELDS.intersection(event_fields)
            or not isinstance(event_fields.get("event"), str)
            or not event_fields["event"]
        ):
            raise ValueError("INVALID_AUDIT_EVENT")

        existing = self.read_verified()
        now = self._clock()
        if not isinstance(now, datetime):
            raise ValueError("INVALID_AUDIT_TIMESTAMP")
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        timestamp = (
            now.astimezone(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )

        body = dict(event_fields)
        body.update({
            "sequence": len(existing) + 1,
            "timestamp": timestamp,
            "previous_hash": (
                existing[-1]["entry_hash"] if existing else GENESIS_HASH
            ),
        })
        try:
            complete = {**body, "entry_hash": _entry_hash(body)}
            serialized = _canonical_json(complete)
        except (TypeError, ValueError) as exc:
            raise ValueError("INVALID_AUDIT_EVENT") from exc

        self.path.parent.mkdir(parents=True, exist_ok=True)
        needs_separator = (
            self.path.exists()
            and self.path.stat().st_size > 0
            and not self.path.read_bytes().endswith(b"\n")
        )
        with self.path.open("a", encoding="utf-8", newline="\n") as log:
            if needs_separator:
                log.write("\n")
            log.write(serialized + "\n")
        return complete

    def read_verified(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        try:
            content = self.path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise AuditIntegrityError() from exc
        if not content:
            return []

        entries: list[dict[str, Any]] = []
        expected_previous = GENESIS_HASH
        for expected_sequence, line in enumerate(content.splitlines(), start=1):
            if not line:
                raise AuditIntegrityError()
            try:
                entry = json.loads(line)
            except (json.JSONDecodeError, ValueError) as exc:
                raise AuditIntegrityError() from exc
            if not isinstance(entry, dict):
                raise AuditIntegrityError()
            if (
                not RESERVED_FIELDS.issubset(entry)
                or not isinstance(entry.get("event"), str)
                or not entry["event"]
                or isinstance(entry["sequence"], bool)
                or not isinstance(entry["sequence"], int)
                or entry["sequence"] != expected_sequence
                or not isinstance(entry["timestamp"], str)
                or not entry["timestamp"]
                or not isinstance(entry["previous_hash"], str)
                or not HASH_RE.fullmatch(entry["previous_hash"])
                or entry["previous_hash"] != expected_previous
                or not isinstance(entry["entry_hash"], str)
                or not HASH_RE.fullmatch(entry["entry_hash"])
            ):
                raise AuditIntegrityError()

            body = dict(entry)
            stored_hash = body.pop("entry_hash")
            try:
                calculated_hash = _entry_hash(body)
                canonical_entry = _canonical_json(entry)
            except (TypeError, ValueError) as exc:
                raise AuditIntegrityError() from exc
            if stored_hash != calculated_hash or line != canonical_entry:
                raise AuditIntegrityError()

            entries.append(entry)
            expected_previous = stored_hash
        return entries

    def verify(self) -> bool:
        try:
            self.read_verified()
        except (AuditIntegrityError, OSError):
            return False
        return True


def verify_audit_log(
    path: str | Path = DEFAULT_AUDIT_LOG_PATH,
) -> bool:
    """Return whether an audit file is a valid chain."""

    return AuditLog(path).verify()
