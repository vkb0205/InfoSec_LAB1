"""Locked vault gate ordering tests for KV operations."""

from __future__ import annotations

import pytest

from src.errors import VAULT_LOCKED, VaultLockedError
from src.kv.service import KVService


class LockedVaultStub:
    def is_locked(self) -> bool:
        return True

    def get_dek(self) -> bytes:  # pragma: no cover - must not be called by gate tests
        raise AssertionError("downstream DEK access was called")


@pytest.mark.parametrize(
    ("method", "args"),
    [
        ("write", ("token", "secret/path", {"value": "secret"})),
        ("read", ("token", "secret/path")),
        ("delete", ("token", "secret/path")),
    ],
)
def test_locked_kv_operations_fail_before_downstream(method, args) -> None:
    downstream_calls = []
    service = KVService(vault=LockedVaultStub(), downstream=lambda *a, **kw: downstream_calls.append((a, kw)))

    with pytest.raises(VaultLockedError) as exc_info:
        getattr(service, method)(*args)

    assert exc_info.value.code == VAULT_LOCKED
    assert downstream_calls == []
