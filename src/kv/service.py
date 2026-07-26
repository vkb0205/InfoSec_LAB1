"""KV engine service placeholders with locked-vault gate."""

from __future__ import annotations

from typing import Any, Callable

from src.errors import VaultLockedError


class KVService:
    """Feature 1 KV service boundary.

    Feature 0.1 implements only the vault locked gate. Downstream KV
    persistence, authorization, and cryptography are intentionally out of scope.
    """

    def __init__(self, vault: Any, downstream: Callable[..., Any] | None = None,
                 auth_validator: Callable[[str], str] | None = None) -> None:
        self._vault = vault
        self._downstream = downstream
        self._auth_validator = auth_validator

    def _require_unlocked(self) -> None:
        if self._vault.is_locked():
            raise VaultLockedError()

    def _require_authenticated(self, token: str) -> str:
        if self._auth_validator is None:
            return token
        return self._auth_validator(token)

    def write(self, token: str, path: str, secret: Any) -> Any:
        self._require_unlocked()
        identity = self._require_authenticated(token)
        if self._downstream is not None:
            return self._downstream("write", identity, path, secret)
        raise NotImplementedError("KV write is out of scope for Feature 0.1")

    def read(self, token: str, path: str) -> Any:
        self._require_unlocked()
        identity = self._require_authenticated(token)
        if self._downstream is not None:
            return self._downstream("read", identity, path)
        raise NotImplementedError("KV read is out of scope for Feature 0.1")

    def delete(self, token: str, path: str) -> Any:
        self._require_unlocked()
        identity = self._require_authenticated(token)
        if self._downstream is not None:
            return self._downstream("delete", identity, path)
        raise NotImplementedError("KV delete is out of scope for Feature 0.1")
