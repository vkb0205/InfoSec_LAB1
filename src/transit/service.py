"""Transit service with vault-locked gate, key management, encryption, signing, and rotation."""

from __future__ import annotations

import base64
import os
from datetime import datetime, timezone
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from src.errors import VaultLockedError, InvalidInputError
from src.storage.repository import TransitKeyRepository


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class TransitService:
    """Transit service boundary with persistent key storage and versioned rotation."""

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

    @staticmethod
    def _normalize_key(key: dict[str, Any]) -> dict[str, Any]:
        """Ensure key record has version map (legacy single-material → v1)."""
        if isinstance(key.get("versions"), dict) and key["versions"] and isinstance(key.get("latest_version"), int):
            return key
        material = key["encrypted_key_material_b64"]
        pub = key.get("public_key_b64")
        created = key["created_at"]
        normalized = dict(key)
        normalized["latest_version"] = 1
        normalized["versions"] = {
            "1": {
                "encrypted_key_material_b64": material,
                "public_key_b64": pub,
                "created_at": created,
            }
        }
        return normalized

    def _load_key(self, owner_email: str, key_name: str) -> dict[str, Any]:
        store = self._repository.read()
        key = store["keys"].get(key_name)
        if key is None or key["owner_email"] != owner_email:
            raise InvalidInputError()
        return self._normalize_key(key)

    def _version_entry(self, key: dict[str, Any], version: int) -> dict[str, Any]:
        entry = key["versions"].get(str(version))
        if entry is None:
            raise InvalidInputError()
        return entry

    def _mirror_latest(self, key: dict[str, Any]) -> dict[str, Any]:
        latest = key["latest_version"]
        entry = key["versions"][str(latest)]
        key["encrypted_key_material_b64"] = entry["encrypted_key_material_b64"]
        key["public_key_b64"] = entry.get("public_key_b64")
        return key

    def list_keys(self, token: str) -> Any:
        self._require_unlocked()
        owner = self._require_authenticated(token)
        if self._downstream is not None:
            return self._downstream("list_keys", owner)
        store = self._repository.read()
        result = []
        for name, key in store["keys"].items():
            if key.get("owner_email") != owner:
                continue
            item = {"key_name": name, "key_usage": key["key_usage"]}
            if isinstance(key.get("latest_version"), int):
                item["latest_version"] = key["latest_version"]
            elif "encrypted_key_material_b64" in key:
                item["latest_version"] = 1
            result.append(item)
        result.sort(key=lambda row: row["key_name"])
        return result

    def revoke_key(self, token: str, key_name: str) -> Any:
        self._require_unlocked()
        owner = self._require_authenticated(token)
        if self._downstream is not None:
            return self._downstream("revoke_key", owner, key_name)
        if not isinstance(key_name, str) or not key_name:
            raise InvalidInputError()
        self._load_key(owner, key_name)
        self._repository.delete_key(key_name)
        return {"key_name": key_name, "status": "revoked"}

    def create_key(self, token: str, key_name: str) -> dict[str, Any]:
        self._require_unlocked()
        owner = self._require_authenticated(token)
        if not isinstance(key_name, str) or not key_name:
            raise InvalidInputError()
        now = _utc_now_iso()
        wrapped = self._encrypt_key_material(self._vault.get_dek(), os.urandom(32))
        key = {
            "name": key_name,
            "owner_email": owner,
            "key_usage": "ENCRYPT_DECRYPT",
            "algorithm": "AES-256-GCM",
            "encrypted_key_material_b64": wrapped,
            "public_key_b64": None,
            "created_at": now,
            "latest_version": 1,
            "versions": {
                "1": {
                    "encrypted_key_material_b64": wrapped,
                    "public_key_b64": None,
                    "created_at": now,
                }
            },
        }
        self._repository.create_key(key)
        return {"key_name": key_name, "key_usage": key["key_usage"], "latest_version": 1}

    def rotate_key(self, token: str, key_name: str) -> dict[str, Any]:
        """Bonus: generate new key material version; keep old versions for decrypt/verify."""
        self._require_unlocked()
        owner = self._require_authenticated(token)
        if not isinstance(key_name, str) or not key_name:
            raise InvalidInputError()
        key = self._load_key(owner, key_name)
        now = _utc_now_iso()
        new_version = int(key["latest_version"]) + 1
        dek = self._vault.get_dek()

        if key["key_usage"] == "ENCRYPT_DECRYPT":
            wrapped = self._encrypt_key_material(dek, os.urandom(32))
            pub = None
        elif key["key_usage"] == "SIGN_VERIFY":
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
            wrapped = self._encrypt_key_material(dek, serialized_private)
            pub = base64.b64encode(serialized_public).decode("utf-8")
        else:
            raise InvalidInputError()

        key["versions"][str(new_version)] = {
            "encrypted_key_material_b64": wrapped,
            "public_key_b64": pub,
            "created_at": now,
        }
        key["latest_version"] = new_version
        self._mirror_latest(key)
        self._repository.replace_key(key)
        return {
            "key_name": key_name,
            "key_usage": key["key_usage"],
            "latest_version": new_version,
        }

    def encrypt(self, token: str, key_name: str, plaintext_b64: str) -> str:
        self._require_unlocked()
        owner = self._require_authenticated(token)
        key = self._load_key(owner, key_name)
        if key["key_usage"] != "ENCRYPT_DECRYPT":
            raise InvalidInputError()
        version = int(key["latest_version"])
        entry = self._version_entry(key, version)
        key_material = self._decrypt_key_material(self._vault.get_dek(), entry["encrypted_key_material_b64"])
        aesgcm = AESGCM(key_material)
        nonce = os.urandom(12)
        plaintext = base64.b64decode(plaintext_b64)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        payload = base64.b64encode(nonce + ciphertext).decode("utf-8")
        return f"vault:{key_name}:{version}:{payload}"

    def decrypt(self, token: str, ciphertext: str) -> str:
        self._require_unlocked()
        owner = self._require_authenticated(token)
        if not isinstance(ciphertext, str) or not ciphertext.startswith("vault:"):
            raise InvalidInputError()
        parts = ciphertext.split(":")
        if len(parts) == 4 and parts[2].isdigit():
            key_name = parts[1]
            version = int(parts[2])
            payload_b64 = parts[3]
            versions_to_try = [version]
        elif len(parts) == 3:
            key_name = parts[1]
            payload_b64 = parts[2]
            versions_to_try = None  # all, latest first
        else:
            raise InvalidInputError()

        key = self._load_key(owner, key_name)
        if key["key_usage"] != "ENCRYPT_DECRYPT":
            raise InvalidInputError()

        if versions_to_try is None:
            latest = int(key["latest_version"])
            versions_to_try = list(range(latest, 0, -1))

        payload = base64.b64decode(payload_b64)
        nonce = payload[:12]
        encrypted = payload[12:]
        dek = self._vault.get_dek()
        last_error: Exception | None = None
        for ver in versions_to_try:
            try:
                entry = self._version_entry(key, ver)
            except InvalidInputError as exc:
                last_error = exc
                continue
            try:
                key_material = self._decrypt_key_material(dek, entry["encrypted_key_material_b64"])
                plaintext = AESGCM(key_material).decrypt(nonce, encrypted, None)
                return base64.b64encode(plaintext).decode("utf-8")
            except (InvalidTag, ValueError, InvalidInputError) as exc:
                last_error = exc
                continue
        if last_error is not None:
            raise InvalidInputError() from last_error
        raise InvalidInputError()

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
        now = _utc_now_iso()
        wrapped = self._encrypt_key_material(self._vault.get_dek(), serialized_private)
        pub_b64 = base64.b64encode(serialized_public).decode("utf-8")
        key = {
            "name": key_name,
            "owner_email": owner,
            "key_usage": "SIGN_VERIFY",
            "algorithm": "ED25519",
            "encrypted_key_material_b64": wrapped,
            "public_key_b64": pub_b64,
            "created_at": now,
            "latest_version": 1,
            "versions": {
                "1": {
                    "encrypted_key_material_b64": wrapped,
                    "public_key_b64": pub_b64,
                    "created_at": now,
                }
            },
        }
        self._repository.create_key(key)
        return {"key_name": key_name, "key_usage": key["key_usage"], "latest_version": 1}

    def sign(self, token: str, key_name: str, message_b64: str) -> str:
        self._require_unlocked()
        owner = self._require_authenticated(token)
        key = self._load_key(owner, key_name)
        if key["key_usage"] != "SIGN_VERIFY":
            raise InvalidInputError()
        version = int(key["latest_version"])
        entry = self._version_entry(key, version)
        private_bytes = self._decrypt_key_material(self._vault.get_dek(), entry["encrypted_key_material_b64"])
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
        message = base64.b64decode(message_b64)
        try:
            signature_bytes = base64.b64decode(signature)
        except Exception as exc:
            raise InvalidInputError() from exc

        # Try latest version first, then older (post-rotation verify of old signatures).
        latest = int(key["latest_version"])
        valid = False
        for ver in range(latest, 0, -1):
            entry = key["versions"].get(str(ver))
            if entry is None or not entry.get("public_key_b64"):
                continue
            public_bytes = base64.b64decode(entry["public_key_b64"])
            public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
            try:
                public_key.verify(signature_bytes, message)
                valid = True
                break
            except InvalidSignature:
                continue

        return {
            "key_name": key_name,
            "signature_valid": valid,
            "signing_algorithm": key["algorithm"],
        }
