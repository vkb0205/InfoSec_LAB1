"""Named AES key management for the Transit service."""

from __future__ import annotations

import json
import secrets
from typing import Any, Callable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.crypto_utils import b64_encode, random_nonce
from src.errors import InvalidInputError, VaultLockedError
from src.storage.repository import TransitKeyRepository

KEY_USAGE = "ENCRYPT_DECRYPT"


class TransitService:
    """Transit boundary with Feature 2.1 named-key management."""

    def __init__(self, vault: Any, downstream: Callable[..., Any] | None = None,
                 auth_validator: Callable[[str], str] | None = None,
                 repository: TransitKeyRepository | None = None) -> None:
        self._vault = vault
        self._downstream = downstream
        self._auth_validator = auth_validator
        self._repository = repository if repository is not None else TransitKeyRepository()

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
        self._validate_key_name(key_name)

        key_material = secrets.token_bytes(32)
        nonce = random_nonce()
        encrypted = AESGCM(self._vault.get_dek()).encrypt(
            nonce,
            key_material,
            self._key_aad(identity, key_name),
        )
        self._repository.create_key({
            "key_name": key_name,
            "owner_email": identity,
            "key_usage": KEY_USAGE,
            "encrypted_key_material_b64": b64_encode(nonce + encrypted),
        })
        return {"key_name": key_name, "key_usage": KEY_USAGE}

    def list_keys(self, token: str) -> Any:
        self._require_unlocked()
        identity = self._require_authenticated(token)
        if self._downstream is not None:
            return self._downstream("list_keys", identity)
        records = self._repository.list_keys(identity)
        return sorted(
            ({"key_name": record["key_name"], "key_usage": record["key_usage"]} for record in records),
            key=lambda record: record["key_name"],
        )

    def revoke_key(self, token: str, key_name: str) -> Any:
        self._require_unlocked()
        identity = self._require_authenticated(token)
        if self._downstream is not None:
            return self._downstream("revoke_key", identity, key_name)
        self._validate_key_name(key_name)
        self._repository.delete_key(identity, key_name)
        return {"key_name": key_name, "revoked": True}

    @staticmethod
    def _validate_key_name(key_name: str) -> None:
        if not isinstance(key_name, str) or not key_name or key_name != key_name.strip() or ":" in key_name:
            raise InvalidInputError()

    @staticmethod
    def _key_aad(owner_email: str, key_name: str) -> bytes:
        return json.dumps(
            {"key_name": key_name, "key_usage": KEY_USAGE, "owner_email": owner_email},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

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
