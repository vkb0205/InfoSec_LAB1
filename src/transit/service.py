"""Transit service with vault-locked gate, key management, encryption, and signing."""

from __future__ import annotations

import base64
import os
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from src.errors import VaultLockedError, InvalidInputError
from src.storage.repository import TransitKeyRepository


class TransitService:
    """Transit service boundary with persistent key storage."""

    def __init__(self, vault: Any, *args: Any, auth_validator: Callable[[str], str] | None = None,
                 repository: TransitKeyRepository | None = None, downstream: Callable[..., Any] | None = None) -> None:
        self._vault = vault
        self._downstream = downstream
        self._auth_validator = auth_validator
        self._repository = repository if repository is not None else TransitKeyRepository()

        if self._downstream is None and args:
            if len(args) >= 2 and callable(args[0]) and callable(args[1]):
                self._downstream = args[0]
                self._auth_validator = args[1]
            elif callable(args[0]):
                self._auth_validator = args[0]

            if repository is None:
                for candidate in reversed(args):
                    if isinstance(candidate, TransitKeyRepository):
                        self._repository = candidate
                        break

    def _require_unlocked(self) -> None:
        if self._vault.is_locked():
            raise VaultLockedError()

    def _require_authenticated(self, token: str) -> str:
        if self._auth_validator is None:
            raise InvalidInputError()
        return self._auth_validator(token)

    @staticmethod
    def _encrypt_key_material(dek: bytes, material: bytes) -> str:
        aesgcm = AESGCM(dek)
        nonce = os.urandom(12)
        encrypted = aesgcm.encrypt(nonce, material, None)
        return base64.b64encode(nonce + encrypted).decode("utf-8")

    @staticmethod
    def _decrypt_key_material(dek: bytes, encrypted_b64: str) -> bytes:
        aesgcm = AESGCM(dek)
        payload = base64.b64decode(encrypted_b64)
        nonce = payload[:12]
        ciphertext = payload[12:]
        return aesgcm.decrypt(nonce, ciphertext, None)

    def _load_key(self, owner_email: str, key_name: str) -> dict[str, Any]:
        store = self._repository.read()
        key = store["keys"].get(key_name)
        if key is None or key["owner_email"] != owner_email:
            raise InvalidInputError()
        return key

    def list_keys(self, token: str) -> tuple[str, str]:
        self._require_unlocked()
        owner = self._require_authenticated(token)
        if self._downstream is not None:
            return self._downstream("list_keys", owner)
        raise NotImplementedError("Transit list_keys is out of scope")

    def revoke_key(self, token: str, key_name: str) -> tuple[str, str, str]:
        self._require_unlocked()
        owner = self._require_authenticated(token)
        if self._downstream is not None:
            return self._downstream("revoke_key", owner, key_name)
        raise NotImplementedError("Transit revoke_key is out of scope")

    def create_key(self, token: str, key_name: str) -> dict[str, Any]:
        self._require_unlocked()
        owner = self._require_authenticated(token)
        if not isinstance(key_name, str) or not key_name:
            raise InvalidInputError()
        key = {
            "name": key_name,
            "owner_email": owner,
            "key_usage": "ENCRYPT_DECRYPT",
            "algorithm": "AES-256-GCM",
            "encrypted_key_material_b64": self._encrypt_key_material(self._vault.get_dek(), os.urandom(32)),
            "public_key_b64": None,
            "created_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        }
        self._repository.create_key(key)
        return {"key_name": key_name, "key_usage": key["key_usage"]}

    def encrypt(self, token: str, key_name: str, plaintext_b64: str) -> str:
        self._require_unlocked()
        owner = self._require_authenticated(token)
        key = self._load_key(owner, key_name)
        if key["key_usage"] != "ENCRYPT_DECRYPT":
            raise InvalidInputError()
        key_material = self._decrypt_key_material(self._vault.get_dek(), key["encrypted_key_material_b64"])
        aesgcm = AESGCM(key_material)
        nonce = os.urandom(12)
        plaintext = base64.b64decode(plaintext_b64)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        payload = base64.b64encode(nonce + ciphertext).decode("utf-8")
        return f"vault:{key_name}:{payload}"

    def decrypt(self, token: str, ciphertext: str) -> str:
        self._require_unlocked()
        owner = self._require_authenticated(token)
        if not isinstance(ciphertext, str) or not ciphertext.startswith("vault:"):
            raise InvalidInputError()
        _, key_name, payload_b64 = ciphertext.split(":", 2)
        key = self._load_key(owner, key_name)
        if key["key_usage"] != "ENCRYPT_DECRYPT":
            raise InvalidInputError()
        key_material = self._decrypt_key_material(self._vault.get_dek(), key["encrypted_key_material_b64"])
        aesgcm = AESGCM(key_material)
        payload = base64.b64decode(payload_b64)
        nonce = payload[:12]
        encrypted = payload[12:]
        plaintext = aesgcm.decrypt(nonce, encrypted, None)
        return base64.b64encode(plaintext).decode("utf-8")

    def create_signing_key(self, token: str, key_name: str) -> dict[str, Any]:
        self._require_unlocked()
        owner = self._require_authenticated(token)
        if not isinstance(key_name, str) or not key_name:
            raise InvalidInputError()
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        serialized_private = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        serialized_public = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        key = {
            "name": key_name,
            "owner_email": owner,
            "key_usage": "SIGN_VERIFY",
            "algorithm": "ED25519",
            "encrypted_key_material_b64": self._encrypt_key_material(self._vault.get_dek(), serialized_private),
            "public_key_b64": base64.b64encode(serialized_public).decode("utf-8"),
            "created_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        }
        self._repository.create_key(key)
        return {"key_name": key_name, "key_usage": key["key_usage"]}

    def sign(self, token: str, key_name: str, message_b64: str) -> str:
        self._require_unlocked()
        owner = self._require_authenticated(token)
        key = self._load_key(owner, key_name)
        if key["key_usage"] != "SIGN_VERIFY":
            raise InvalidInputError()
        private_bytes = self._decrypt_key_material(self._vault.get_dek(), key["encrypted_key_material_b64"])
        private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
        message = base64.b64decode(message_b64)
        signature = private_key.sign(message)
        return base64.b64encode(signature).decode("utf-8")

    def verify(self, token: str, key_name: str, message_b64: str, signature: str) -> dict[str, Any]:
        self._require_unlocked()
        owner = self._require_authenticated(token)
        key = self._load_key(owner, key_name)
        if key["key_usage"] != "SIGN_VERIFY":
            raise InvalidInputError()
        public_bytes = base64.b64decode(key["public_key_b64"])
        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
        message = base64.b64decode(message_b64)
        signature_bytes = base64.b64decode(signature)
        try:
            public_key.verify(signature_bytes, message)
            valid = True
        except InvalidSignature:
            valid = False
        return {
            "key_name": key_name,
            "signature_valid": valid,
            "signing_algorithm": key["algorithm"],
        }
