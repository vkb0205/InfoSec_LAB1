"""Locked vault gate ordering tests for Transit operations."""

from __future__ import annotations

import pytest

from src.errors import VAULT_LOCKED, VaultLockedError
from src.transit.service import TransitService


class LockedVaultStub:
    def is_locked(self) -> bool:
        return True

    def get_dek(self) -> bytes:  # pragma: no cover - must not be called by gate tests
        raise AssertionError("downstream DEK access was called")


@pytest.mark.parametrize(
    ("method", "args"),
    [
        ("create_key", ("token", "key-name")),
        ("list_keys", ("token",)),
        ("revoke_key", ("token", "key-name")),
        ("encrypt", ("token", "key-name", "cGxhaW50ZXh0")),
        ("decrypt", ("token", "vault:key-name:ciphertext")),
        ("create_signing_key", ("token", "signing-key")),
        ("sign", ("token", "signing-key", "bWVzc2FnZQ==")),
        ("verify", ("token", "signing-key", "bWVzc2FnZQ==", "signature")),
        ("grant_key_access", ("token", "key-name", "user@example.com", ["ENCRYPT"])),
        ("revoke_key_access", ("token", "key-name", "user@example.com")),
        ("get_key_acl", ("token", "key-name")),
        ("list_shared_keys", ("token",)),
    ],
)
def test_locked_transit_operations_fail_before_downstream(method, args) -> None:
    downstream_calls = []
    service = TransitService(vault=LockedVaultStub(), downstream=lambda *a, **kw: downstream_calls.append((a, kw)))

    with pytest.raises(VaultLockedError) as exc_info:
        getattr(service, method)(*args)

    assert exc_info.value.code == VAULT_LOCKED
    assert downstream_calls == []
