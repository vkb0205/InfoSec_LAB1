<<<<<<< HEAD
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
=======
"""Named AES key management for the Transit service."""

from __future__ import annotations

import hashlib
import json
import secrets
from pathlib import Path
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
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
    InvalidSigningAlgorithmError,
    KeyNotFoundError,
    PermissionDeniedError,
    UnauthenticatedError,
    VaultLockedError,
)
from src.storage.repository import TransitKeyRepository

KEY_USAGE = "ENCRYPT_DECRYPT"
SIGNING_KEY_USAGE = "SIGN_VERIFY"
SIGNING_ALGORITHM = "ED25519"
DEFAULT_ACCESS_LOG_PATH = Path(__file__).resolve().parents[2] / "data/logs/access_denied.jsonl"


class TransitService:
    """Transit boundary with named-key management and AES-GCM operations."""

    def __init__(self, vault: Any, downstream: Callable[..., Any] | None = None,
                 auth_validator: Callable[[str], str] | None = None,
                 repository: TransitKeyRepository | None = None,
                 access_log_path: str | Path | None = None) -> None:
>>>>>>> kv_engine
        self._vault = vault
        self._downstream = downstream
        self._auth_validator = auth_validator
        self._repository = repository if repository is not None else TransitKeyRepository()
<<<<<<< HEAD

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
=======
        self._access_log_path = Path(access_log_path) if access_log_path is not None else DEFAULT_ACCESS_LOG_PATH
>>>>>>> kv_engine

    def _require_unlocked(self) -> None:
        if self._vault.is_locked():
            raise VaultLockedError()

    def _require_authenticated(self, token: str) -> str:
        if self._auth_validator is None:
<<<<<<< HEAD
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
=======
            raise UnauthenticatedError()
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
    def _key_aad(
        owner_email: str,
        key_name: str,
        key_usage: str = KEY_USAGE,
        signing_algorithm: str | None = None,
    ) -> bytes:
        metadata = {"key_name": key_name, "key_usage": key_usage, "owner_email": owner_email}
        if signing_algorithm is not None:
            metadata["signing_algorithm"] = signing_algorithm
        return json.dumps(
            metadata,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
>>>>>>> kv_engine

    def list_keys(self, token: str) -> tuple[str, str]:
        self._require_unlocked()
        owner = self._require_authenticated(token)
        if self._downstream is not None:
<<<<<<< HEAD
            return self._downstream("list_keys", owner)
        raise NotImplementedError("Transit list_keys is out of scope")
=======
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
>>>>>>> kv_engine

    def revoke_key(self, token: str, key_name: str) -> tuple[str, str, str]:
        self._require_unlocked()
        owner = self._require_authenticated(token)
        if self._downstream is not None:
<<<<<<< HEAD
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
=======
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
        record = self._get_owned_key(owner_email, key_name)
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

    def _get_owned_key(self, owner_email: str, key_name: str) -> dict[str, Any]:
        try:
            record = self._repository.get_key(owner_email, key_name)
        except KeyNotFoundError:
            self._deny_access(owner_email, key_name)
        if record["owner_email"] != owner_email:
            self._deny_access(owner_email, key_name)
        return record

    def _deny_access(self, requester_email: str, key_name: str) -> None:
        entry = json.dumps(
            {
                "event": "TRANSIT_PERMISSION_DENIED",
                "requester_email": requester_email,
                "key_name": key_name,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        try:
            self._access_log_path.parent.mkdir(parents=True, exist_ok=True)
            with self._access_log_path.open("a", encoding="utf-8") as log:
                log.write(entry + "\n")
        except OSError:
            pass
        raise PermissionDeniedError()

    @staticmethod
    def _ciphertext_aad(key_name: str) -> bytes:
        return f"mini-vault:transit:v1:{key_name}".encode("utf-8")

    def create_signing_key(
        self,
        token: str,
        key_name: str,
        signing_algorithm: str | None = None,
    ) -> Any:
        self._require_unlocked()
        identity = self._require_authenticated(token)
        if self._downstream is not None:
            return self._downstream("create_signing_key", identity, key_name, signing_algorithm)
        self._validate_key_name(key_name)
        if signing_algorithm != SIGNING_ALGORITHM:
            raise InvalidSigningAlgorithmError()

        private_key = Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        public_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        nonce = random_nonce()
        encrypted = AESGCM(self._vault.get_dek()).encrypt(
            nonce,
            private_bytes,
            self._key_aad(identity, key_name, SIGNING_KEY_USAGE, signing_algorithm),
        )
        self._repository.create_key({
            "key_name": key_name,
            "owner_email": identity,
            "key_usage": SIGNING_KEY_USAGE,
            "signing_algorithm": signing_algorithm,
            "encrypted_private_key_b64": b64_encode(nonce + encrypted),
            "public_key_b64": b64_encode(public_bytes),
        })
        return {
            "key_name": key_name,
            "key_usage": SIGNING_KEY_USAGE,
            "signing_algorithm": signing_algorithm,
        }

    def sign(
        self,
        token: str,
        key_name: str,
        message_b64: str,
        message_type: str | None = None,
    ) -> Any:
        self._require_unlocked()
        identity = self._require_authenticated(token)
        if self._downstream is not None:
            return self._downstream("sign", identity, key_name, message_b64, message_type)
        self._validate_key_name(key_name)
        record = self._get_signing_record(identity, key_name)
        message = self._signing_input(message_b64, message_type)
        private_key = self._load_private_key(record)
        return {
            "signature_b64": b64_encode(private_key.sign(message)),
            "key_name": key_name,
            "signing_algorithm": record["signing_algorithm"],
        }

    def verify(
        self,
        token: str,
        key_name: str,
        message_b64: str,
        message_type: str | None = None,
        signature_b64: str | None = None,
        signing_algorithm: str | None = None,
    ) -> Any:
        self._require_unlocked()
        identity = self._require_authenticated(token)
        if self._downstream is not None:
            return self._downstream(
                "verify",
                identity,
                key_name,
                message_b64,
                message_type,
                signature_b64,
                signing_algorithm,
            )
        self._validate_key_name(key_name)
        record = self._get_signing_record(identity, key_name)
        if signing_algorithm is not None and signing_algorithm != record["signing_algorithm"]:
            raise InvalidSigningAlgorithmError()
        message = self._signing_input(message_b64, message_type)
        result = {
            "key_name": key_name,
            "signature_valid": False,
            "signing_algorithm": record["signing_algorithm"],
        }
        try:
            signature_bytes = b64_decode(signature_b64)
            if len(signature_bytes) != 64:
                return result
            public_bytes = b64_decode(record["public_key_b64"])
            Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature_bytes, message)
        except (MetadataValidationError, InvalidSignature, ValueError):
            return result
        result["signature_valid"] = True
        return result

    def _get_signing_record(self, owner_email: str, key_name: str) -> dict[str, Any]:
        record = self._get_owned_key(owner_email, key_name)
        if record["key_usage"] != SIGNING_KEY_USAGE:
            raise InvalidKeyUsageError()
        if record["signing_algorithm"] != SIGNING_ALGORITHM:
            raise InvalidSigningAlgorithmError()
        return record

    def _load_private_key(self, record: dict[str, Any]) -> Ed25519PrivateKey:
        try:
            envelope = b64_decode(record["encrypted_private_key_b64"])
            private_bytes = AESGCM(self._vault.get_dek()).decrypt(
                envelope[:NONCE_LEN],
                envelope[NONCE_LEN:],
                self._key_aad(
                    record["owner_email"],
                    record["key_name"],
                    record["key_usage"],
                    record["signing_algorithm"],
                ),
            )
            return Ed25519PrivateKey.from_private_bytes(private_bytes)
        except (MetadataValidationError, InvalidTag, ValueError) as exc:
            raise DecryptionFailedError() from exc

    @staticmethod
    def _signing_input(message_b64: str, message_type: str | None) -> bytes:
        if message_type not in {"RAW", "DIGEST"}:
            raise InvalidInputError()
        try:
            message = b64_decode(message_b64)
        except MetadataValidationError as exc:
            raise InvalidInputError() from exc
        if message_type == "RAW":
            return hashlib.sha256(message).digest()
        if len(message) == 32:
            return message
        raise InvalidInputError()
>>>>>>> kv_engine
