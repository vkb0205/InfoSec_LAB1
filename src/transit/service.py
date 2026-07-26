"""Named AES key management for the Transit service."""

from __future__ import annotations

import json
import secrets
from typing import Any, Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.crypto_utils import (
    DEK_LEN,
    GCM_TAG_LEN,
    NONCE_LEN,
    MetadataValidationError,
    b64_decode,
    b64_encode,
    random_nonce,
)
from src.errors import (
    DecryptionFailedError,
    InvalidCiphertextError,
    InvalidInputError,
    InvalidKeyUsageError,
    VaultLockedError,
)
from src.storage.repository import TransitKeyRepository

KEY_USAGE = "ENCRYPT_DECRYPT"


class TransitService:
    """Transit boundary with named-key management and AES-GCM operations."""

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
        self._validate_key_name(key_name)
        try:
            plaintext = b64_decode(plaintext_b64)
        except MetadataValidationError as exc:
            raise InvalidInputError() from exc

        key = self._load_encryption_key(identity, key_name)
        nonce = random_nonce()
        encrypted = AESGCM(key).encrypt(nonce, plaintext, self._ciphertext_aad(key_name))
        return f"vault:{key_name}:{b64_encode(nonce + encrypted)}"

    def decrypt(self, token: str, ciphertext: str) -> Any:
        self._require_unlocked()
        identity = self._require_authenticated(token)
        if self._downstream is not None:
            return self._downstream("decrypt", identity, ciphertext)
        if not isinstance(ciphertext, str):
            raise InvalidCiphertextError()
        parts = ciphertext.split(":", 2)
        if len(parts) != 3 or parts[0] != "vault":
            raise InvalidCiphertextError()
        key_name, encoded = parts[1], parts[2]
        try:
            self._validate_key_name(key_name)
            envelope = b64_decode(encoded)
        except (InvalidInputError, MetadataValidationError) as exc:
            raise InvalidCiphertextError() from exc
        if len(envelope) < NONCE_LEN + GCM_TAG_LEN:
            raise InvalidCiphertextError()

        key = self._load_encryption_key(identity, key_name)
        try:
            plaintext = AESGCM(key).decrypt(
                envelope[:NONCE_LEN],
                envelope[NONCE_LEN:],
                self._ciphertext_aad(key_name),
            )
        except (InvalidTag, ValueError) as exc:
            raise DecryptionFailedError() from exc
        return b64_encode(plaintext)

    def _load_encryption_key(self, owner_email: str, key_name: str) -> bytes:
        record = self._repository.get_key(owner_email, key_name)
        if record["key_usage"] != KEY_USAGE:
            raise InvalidKeyUsageError()
        try:
            envelope = b64_decode(record["encrypted_key_material_b64"])
            key = AESGCM(self._vault.get_dek()).decrypt(
                envelope[:NONCE_LEN],
                envelope[NONCE_LEN:],
                self._key_aad(owner_email, key_name),
            )
        except (MetadataValidationError, InvalidTag, ValueError) as exc:
            raise DecryptionFailedError() from exc
        if len(key) != DEK_LEN:
            raise DecryptionFailedError()
        return key

    @staticmethod
    def _ciphertext_aad(key_name: str) -> bytes:
        return f"mini-vault:transit:v1:{key_name}".encode("utf-8")

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
