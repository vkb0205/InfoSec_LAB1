"""Advanced Feature 5: tamper-evident hash-chained audit logging."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import pytest

from src.audit import (
    GENESIS_HASH,
    AuditIntegrityError,
    AuditLog,
    verify_audit_log,
)
from src.errors import PermissionDeniedError
from src.kv.crypto_utils import CryptoEngine
from src.kv.kv_engine import KVEngine
from src.storage.repository import TransitKeyRepository
from src.transit.service import TransitService


FIXED_TIME = datetime(2026, 7, 31, 2, 30, tzinfo=timezone.utc)


def make_log(path):
    return AuditLog(path, clock=lambda: FIXED_TIME)


def test_entries_are_chained_and_continue_after_restart(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = make_log(path)

    first = audit.append({
        "event": "KV_PERMISSION_DENIED",
        "operation": "READ",
        "path": "secret/alice@example.com/notes",
        "requester_email": "bob@example.com",
        "owner_email": "alice@example.com",
    })
    second = make_log(path).append({
        "event": "TRANSIT_PERMISSION_DENIED",
        "requester_email": "bob@example.com",
        "key_name": "payments",
    })

    assert first["sequence"] == 1
    assert first["previous_hash"] == GENESIS_HASH
    assert second["sequence"] == 2
    assert second["previous_hash"] == first["entry_hash"]
    assert len(first["entry_hash"]) == 64
    assert audit.verify() is True
    assert verify_audit_log(path) is True
    assert audit.read_verified() == [first, second]

    lines = path.read_text(encoding="utf-8").splitlines()
    assert all(
        line == json.dumps(
            json.loads(line),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        for line in lines
    )


def valid_three_entry_log(path):
    audit = make_log(path)
    for number in range(1, 4):
        audit.append({
            "event": "TEST_EVENT",
            "number": number,
        })
    return path.read_text(encoding="utf-8").splitlines()


@pytest.mark.parametrize(
    "tamper",
    [
        lambda lines: [
            *lines[:1],
            lines[1].replace('"number":2', '"number":20'),
            *lines[2:],
        ],
        lambda lines: [lines[0], lines[2]],
        lambda lines: [lines[0], lines[0], *lines[1:]],
        lambda lines: [lines[1], lines[0], lines[2]],
        lambda lines: [lines[0], "{invalid-json", lines[2]],
    ],
    ids=["edit", "delete", "insert", "reorder", "invalid-json"],
)
def test_tampering_is_detected_and_damaged_chain_is_not_extended(
    tmp_path,
    tamper,
):
    path = tmp_path / "audit.jsonl"
    lines = valid_three_entry_log(path)
    path.write_text(
        "\n".join(tamper(lines)) + "\n",
        encoding="utf-8",
    )
    damaged = path.read_bytes()
    audit = make_log(path)

    assert audit.verify() is False
    assert verify_audit_log(path) is False
    with pytest.raises(AuditIntegrityError):
        audit.read_verified()
    with pytest.raises(AuditIntegrityError):
        audit.append({"event": "MUST_NOT_BE_WRITTEN"})
    assert path.read_bytes() == damaged


def test_invalid_event_fields_are_rejected_without_creating_a_file(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = make_log(path)

    for invalid in (
        {},
        {"event": ""},
        {"event": "TEST", "sequence": 99},
        {"event": "TEST", "value": float("nan")},
    ):
        with pytest.raises(ValueError, match="INVALID_AUDIT_EVENT"):
            audit.append(invalid)
    assert not path.exists()


class Auth:
    identities = {
        "alice-token": "alice@example.com",
        "bob-token": "bob@example.com",
    }

    def verify_token(self, token):
        return self.identities[token]


class Storage:
    def __init__(self):
        self.records = {}

    def set(self, path, record):
        self.records[path] = record

    def get(self, path):
        return self.records.get(path)

    def exists(self, path):
        return path in self.records

    def delete(self, path):
        self.records.pop(path, None)


class Vault:
    def __init__(self):
        self.dek = b"d" * 32

    def is_locked(self):
        return False

    def get_dek(self):
        return self.dek


def test_kv_and_transit_denials_share_one_verified_chain(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    kv = KVEngine(
        CryptoEngine(os.urandom(32)),
        Storage(),
        Auth(),
        audit_log_path=audit_path,
    )
    path = "secret/alice@example.com/notes"
    kv.write(path, "private-value", "alice-token")
    with pytest.raises(PermissionError, match="PERMISSION_DENIED"):
        kv.read(path, "bob-token")

    transit = TransitService(
        Vault(),
        auth_validator=Auth.identities.__getitem__,
        repository=TransitKeyRepository(tmp_path / "transit_keys.json"),
        access_log_path=tmp_path / "legacy-transit.jsonl",
        audit_log_path=audit_path,
    )
    transit.create_key("alice-token", "payments")
    with pytest.raises(PermissionDeniedError):
        transit.encrypt(
            "bob-token",
            "payments",
            "cHJpdmF0ZS10cmFuc2l0LXZhbHVl",
            key_owner_email="alice@example.com",
        )

    entries = AuditLog(audit_path).read_verified()
    assert [
        {
            key: entry[key]
            for key in entry
            if key not in {
                "sequence",
                "timestamp",
                "previous_hash",
                "entry_hash",
            }
        }
        for entry in entries
    ] == [
        {
            "event": "KV_PERMISSION_DENIED",
            "operation": "READ",
            "path": path,
            "requester_email": "bob@example.com",
            "owner_email": "alice@example.com",
        },
        {
            "event": "TRANSIT_PERMISSION_DENIED",
            "requester_email": "bob@example.com",
            "key_name": "payments",
        },
    ]
    serialized = audit_path.read_text(encoding="utf-8")
    for sensitive in (
        "alice-token",
        "bob-token",
        "private-value",
        "cHJpdmF0ZS10cmFuc2l0LXZhbHVl",
    ):
        assert sensitive not in serialized

    assert json.loads(
        (tmp_path / "legacy-transit.jsonl").read_text(encoding="utf-8")
    ) == {
        "event": "TRANSIT_PERMISSION_DENIED",
        "requester_email": "bob@example.com",
        "key_name": "payments",
    }
