"""Transit service placeholders with locked-vault gate."""

from __future__ import annotations

from typing import Any, Callable

from src.errors import VaultLockedError


class TransitService:
    """Feature 2 Transit service boundary.

    Feature 0.1 implements only the vault locked gate. Key management,
    encryption, decryption, signing, and verification are intentionally out of
    scope until later features.
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

    def create_key(self, token: str, key_name: str) -> Any:
        self._require_unlocked()
        identity = self._require_authenticated(token)
        if self._downstream is not None:
            return self._downstream("create_key", identity, key_name)
        raise NotImplementedError("Transit key creation is out of scope for Feature 0.1")

    def list_keys(self, token: str) -> Any:
        self._require_unlocked()
        identity = self._require_authenticated(token)
        if self._downstream is not None:
            return self._downstream("list_keys", identity)
        raise NotImplementedError("Transit key listing is out of scope for Feature 0.1")

    def revoke_key(self, token: str, key_name: str) -> Any:
        self._require_unlocked()
        identity = self._require_authenticated(token)
        if self._downstream is not None:
            return self._downstream("revoke_key", identity, key_name)
        raise NotImplementedError("Transit key revocation is out of scope for Feature 0.1")

    def encrypt(self, token: str, key_name: str, plaintext_b64: str) -> Any:
        self._require_unlocked()
        identity = self._require_authenticated(token)
        if self._downstream is not None:
            return self._downstream("encrypt", identity, key_name, plaintext_b64)
        raise NotImplementedError("Transit encryption is out of scope for Feature 0.1")

    def decrypt(self, token: str, ciphertext: str) -> Any:
        self._require_unlocked()
        identity = self._require_authenticated(token)
        if self._downstream is not None:
            return self._downstream("decrypt", identity, ciphertext)
        raise NotImplementedError("Transit decryption is out of scope for Feature 0.1")

    def create_signing_key(self, token: str, key_name: str) -> Any:
        self._require_unlocked()
        identity = self._require_authenticated(token)
        if self._downstream is not None:
            return self._downstream("create_signing_key", identity, key_name)
        raise NotImplementedError("Transit signing key creation is out of scope for Feature 0.1")

    def sign(self, token: str, key_name: str, message_b64: str) -> Any:
        self._require_unlocked()
        identity = self._require_authenticated(token)
        if self._downstream is not None:
            return self._downstream("sign", identity, key_name, message_b64)
        raise NotImplementedError("Transit signing is out of scope for Feature 0.1")

    def verify(self, token: str, key_name: str, message_b64: str, signature: str) -> Any:
        self._require_unlocked()
        identity = self._require_authenticated(token)
        if self._downstream is not None:
            return self._downstream("verify", identity, key_name, message_b64, signature)
        raise NotImplementedError("Transit verification is out of scope for Feature 0.1")
