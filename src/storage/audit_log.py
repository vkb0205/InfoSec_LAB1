"""Append-only JSON Lines logging for denied authorization attempts."""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from src.errors import AUDIT_ERROR, INVALID_INPUT, MiniVaultError


ACCESS_DENIED_LOG_FILE = "access_denied.jsonl"
MAX_AUDIT_FIELD_LENGTH = 4_096


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError("Audit timestamps must be timezone-aware.")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class AccessDeniedLogger:
    """Write minimal denial records without accepting tokens or secret data."""

    def __init__(
        self,
        log_dir: str | Path = "data/logs",
        *,
        filename: str = ACCESS_DENIED_LOG_FILE,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        candidate = Path(filename)
        if (
            not filename
            or candidate.is_absolute()
            or candidate.name != filename
            or candidate.suffix.lower() != ".jsonl"
        ):
            raise MiniVaultError(
                INVALID_INPUT,
                "Audit filename must be a plain .jsonl filename.",
            )
        self._log_dir = Path(log_dir)
        self._filename = filename
        self._clock = clock
        self._write_lock = threading.RLock()

    @property
    def path(self) -> Path:
        return self._log_dir / self._filename

    def log_access_denied(
        self,
        *,
        requester_email: str,
        operation: str,
        resource_type: str,
        resource_id: str,
    ) -> None:
        """Durably append one denial event.

        The method intentionally has no session-token, plaintext, or key
        parameter, making accidental sensitive-data logging less likely.
        """

        fields = {
            "requester_email": requester_email,
            "operation": operation,
            "resource_type": resource_type,
            "resource_id": resource_id,
        }
        if any(
            not isinstance(value, str)
            or not value
            or len(value) > MAX_AUDIT_FIELD_LENGTH
            for value in fields.values()
        ):
            raise MiniVaultError(
                AUDIT_ERROR,
                "Access denial could not be audited safely.",
            )

        try:
            timestamp = _format_timestamp(self._clock())
            record = {
                "event": "access_denied",
                "timestamp": timestamp,
                **fields,
            }
            encoded_record = json.dumps(
                record,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            with self._write_lock:
                self._log_dir.mkdir(parents=True, exist_ok=True)
                descriptor = os.open(
                    self.path,
                    os.O_APPEND | os.O_CREAT | os.O_WRONLY,
                    0o600,
                )
                with os.fdopen(
                    descriptor,
                    mode="a",
                    encoding="utf-8",
                    newline="\n",
                ) as handle:
                    handle.write(encoded_record)
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
        except (OSError, TypeError, ValueError) as exc:
            raise MiniVaultError(
                AUDIT_ERROR,
                "Access denial could not be audited safely.",
            ) from exc
