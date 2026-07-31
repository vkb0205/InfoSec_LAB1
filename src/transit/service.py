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
from src.policy import (
    TRANSIT_KEY,
    PolicyRepository,
    canonical_email,
    normalize_permissions,
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
                 access_log_path: str | Path | None = None,
                 policy_repository: PolicyRepository | None = None) -> None:
        self._vault = vault
        self._downstream = downstream
        self._auth_validator = auth_validator
        self._repository = repository if repository is not None else TransitKeyRepository()
        self._access_log_path = Path(access_log_path) if access_log_path is not None else DEFAULT_ACCESS_LOG_PATH
        key_path = getattr(self._repository, "key_path", None)
        policy_path = Path(key_path).with_name("policies.json") if key_path is not None else None
        self._policies = (
            policy_repository
            if policy_repository is not None
            else PolicyRepository(policy_path)
        )

    def _require_unlocked(self) -> None:
        if self._vault.is_locked():
            raise VaultLockedError()

    def _require_authenticated(self, token: str) -> str:
        if self._auth_validator is None:
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
        self._policies.delete_resource(TRANSIT_KEY, identity, key_name)
        return {"key_name": key_name, "revoked": True}

    def grant_key_access(
        self,
        token: str,
        key_name: str,
        grantee_email: str,
        permissions: Any,
        key_owner_email: str | None = None,
    ) -> Any:
        self._require_unlocked()
        identity = self._require_authenticated(token)
        if self._downstream is not None:
            args = ("grant_key_access", identity, key_name, grantee_email, permissions)
            if key_owner_email is not None:
                args += (key_owner_email,)
            return self._downstream(*args)
        self._validate_key_name(key_name)
        owner_email = identity if key_owner_email is None else canonical_email(key_owner_email)
        if owner_email != identity:
            self._deny_access(identity, key_name)
        record = self._repository.get_key(owner_email, key_name)
        grantee = canonical_email(grantee_email)
        granted = self._policies.grant(
            TRANSIT_KEY,
            owner_email,
            key_name,
            grantee,
            normalize_permissions(permissions, self._permissions_for(record)),
        )
        return {
            "key_name": key_name,
            "owner_email": owner_email,
            "grantee_email": grantee,
            "permissions": granted,
        }

    def revoke_key_access(
        self,
        token: str,
        key_name: str,
        grantee_email: str,
        permissions: Any = None,
        key_owner_email: str | None = None,
    ) -> Any:
        self._require_unlocked()
        identity = self._require_authenticated(token)
        if self._downstream is not None:
            args = ("revoke_key_access", identity, key_name, grantee_email, permissions)
            if key_owner_email is not None:
                args += (key_owner_email,)
            return self._downstream(*args)
        self._validate_key_name(key_name)
        owner_email = identity if key_owner_email is None else canonical_email(key_owner_email)
        if owner_email != identity:
            self._deny_access(identity, key_name)
        record = self._repository.get_key(owner_email, key_name)
        grantee = canonical_email(grantee_email)
        normalized = (
            None
            if permissions is None
            else normalize_permissions(permissions, self._permissions_for(record))
        )
        remaining = self._policies.revoke(
            TRANSIT_KEY,
            owner_email,
            key_name,
            grantee,
            normalized,
        )
        return {
            "key_name": key_name,
            "owner_email": owner_email,
            "grantee_email": grantee,
            "permissions": remaining,
        }

    def get_key_acl(
        self,
        token: str,
        key_name: str,
        key_owner_email: str | None = None,
    ) -> Any:
        self._require_unlocked()
        identity = self._require_authenticated(token)
        if self._downstream is not None:
            args = ("get_key_acl", identity, key_name)
            if key_owner_email is not None:
                args += (key_owner_email,)
            return self._downstream(*args)
        self._validate_key_name(key_name)
        owner_email = identity if key_owner_email is None else canonical_email(key_owner_email)
        if owner_email != identity:
            self._deny_access(identity, key_name)
        self._repository.get_key(owner_email, key_name)
        return {
            "key_name": key_name,
            "owner_email": owner_email,
            "grants": self._policies.get_acl(TRANSIT_KEY, owner_email, key_name),
        }

    def list_shared_keys(self, token: str) -> Any:
        self._require_unlocked()
        identity = self._require_authenticated(token)
        if self._downstream is not None:
            return self._downstream("list_shared_keys", identity)
        shared = []
        for policy in self._policies.list_shared(TRANSIT_KEY, identity):
            try:
                record = self._repository.get_key(
                    policy["owner_email"],
                    policy["resource_id"],
                )
            except KeyNotFoundError:
                continue
            permissions = sorted(
                set(policy["permissions"]) & self._permissions_for(record)
            )
            if permissions:
                shared.append({
                    "key_name": record["key_name"],
                    "owner_email": record["owner_email"],
                    "key_usage": record["key_usage"],
                    "permissions": permissions,
                })
        return sorted(shared, key=lambda item: (item["owner_email"], item["key_name"]))

    @staticmethod
    def _permissions_for(record: dict[str, Any]) -> frozenset[str]:
        if record["key_usage"] == KEY_USAGE:
            return frozenset({"ENCRYPT", "DECRYPT"})
        if record["key_usage"] == SIGNING_KEY_USAGE:
            return frozenset({"SIGN", "VERIFY"})
        raise InvalidKeyUsageError()

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

    def encrypt(
        self,
        token: str,
        key_name: str,
        plaintext_b64: str,
        key_owner_email: str | None = None,
    ) -> Any:
        self._require_unlocked()
        identity = self._require_authenticated(token)
        if self._downstream is not None:
            args = ("encrypt", identity, key_name, plaintext_b64)
            if key_owner_email is not None:
                args += (key_owner_email,)
            return self._downstream(*args)
        owner_email, actual_key_name, qualified = self._resolve_key_reference(
            identity,
            key_name,
            key_owner_email,
        )
        self._validate_key_name(actual_key_name)
        try:
            plaintext = b64_decode(plaintext_b64)
        except MetadataValidationError as exc:
            raise InvalidInputError() from exc

        key = self._load_encryption_key(
            identity,
            owner_email,
            actual_key_name,
            "ENCRYPT",
        )
        nonce = random_nonce()
        encrypted = AESGCM(key).encrypt(
            nonce,
            plaintext,
            self._ciphertext_aad(actual_key_name),
        )
        identifier = (
            f"{owner_email}/{actual_key_name}"
            if qualified
            else actual_key_name
        )
        return f"vault:{identifier}:{b64_encode(nonce + encrypted)}"

    def decrypt(
        self,
        token: str,
        ciphertext: str,
        key_owner_email: str | None = None,
    ) -> Any:
        self._require_unlocked()
        identity = self._require_authenticated(token)
        if self._downstream is not None:
            args = ("decrypt", identity, ciphertext)
            if key_owner_email is not None:
                args += (key_owner_email,)
            return self._downstream(*args)
        if not isinstance(ciphertext, str):
            raise InvalidCiphertextError()
        parts = ciphertext.split(":", 2)
        if len(parts) != 3 or parts[0] != "vault":
            raise InvalidCiphertextError()
        key_reference, encoded = parts[1], parts[2]
        try:
            owner_email, key_name, _ = self._resolve_key_reference(
                identity,
                key_reference,
                key_owner_email,
            )
            self._validate_key_name(key_name)
            envelope = b64_decode(encoded)
        except (InvalidInputError, MetadataValidationError) as exc:
            raise InvalidCiphertextError() from exc
        if len(envelope) < NONCE_LEN + GCM_TAG_LEN:
            raise InvalidCiphertextError()

        key = self._load_encryption_key(
            identity,
            owner_email,
            key_name,
            "DECRYPT",
        )
        try:
            plaintext = AESGCM(key).decrypt(
                envelope[:NONCE_LEN],
                envelope[NONCE_LEN:],
                self._ciphertext_aad(key_name),
            )
        except (InvalidTag, ValueError) as exc:
            raise DecryptionFailedError() from exc
        return b64_encode(plaintext)

    def _load_encryption_key(
        self,
        requester_email: str,
        owner_email: str,
        key_name: str,
        permission: str,
    ) -> bytes:
        record = self._get_authorized_key(
            requester_email,
            owner_email,
            key_name,
            permission,
        )
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

    def _get_authorized_key(
        self,
        requester_email: str,
        owner_email: str,
        key_name: str,
        permission: str,
    ) -> dict[str, Any]:
        if requester_email != owner_email and not self._policies.allows(
            TRANSIT_KEY,
            owner_email,
            key_name,
            requester_email,
            permission,
        ):
            self._deny_access(requester_email, key_name)
        try:
            record = self._repository.get_key(owner_email, key_name)
        except KeyNotFoundError:
            self._deny_access(requester_email, key_name)
        if record["owner_email"] != owner_email:
            self._deny_access(requester_email, key_name)
        return record

    def _get_owned_key(self, owner_email: str, key_name: str) -> dict[str, Any]:
        return self._get_authorized_key(
            owner_email,
            owner_email,
            key_name,
            "ENCRYPT",
        )

    @staticmethod
    def _resolve_key_reference(
        requester_email: str,
        key_reference: str,
        key_owner_email: str | None,
    ) -> tuple[str, str, bool]:
        if not isinstance(key_reference, str):
            raise InvalidInputError()
        embedded_owner: str | None = None
        key_name = key_reference
        if "/" in key_reference:
            possible_owner, possible_key_name = key_reference.split("/", 1)
            try:
                embedded_owner = canonical_email(possible_owner)
            except InvalidInputError:
                embedded_owner = None
            else:
                key_name = possible_key_name

        explicit_owner = (
            None
            if key_owner_email is None
            else canonical_email(key_owner_email)
        )
        if (
            embedded_owner is not None
            and explicit_owner is not None
            and embedded_owner != explicit_owner
        ):
            raise InvalidInputError()
        owner_email = embedded_owner or explicit_owner or requester_email
        return owner_email, key_name, embedded_owner is not None or explicit_owner is not None

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
        key_owner_email: str | None = None,
    ) -> Any:
        self._require_unlocked()
        identity = self._require_authenticated(token)
        if self._downstream is not None:
            args = ("sign", identity, key_name, message_b64, message_type)
            if key_owner_email is not None:
                args += (key_owner_email,)
            return self._downstream(*args)
        owner_email, actual_key_name, _ = self._resolve_key_reference(
            identity,
            key_name,
            key_owner_email,
        )
        self._validate_key_name(actual_key_name)
        record = self._get_signing_record(
            identity,
            owner_email,
            actual_key_name,
            "SIGN",
        )
        message = self._signing_input(message_b64, message_type)
        private_key = self._load_private_key(record)
        return {
            "signature_b64": b64_encode(private_key.sign(message)),
            "key_name": actual_key_name,
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
        key_owner_email: str | None = None,
    ) -> Any:
        self._require_unlocked()
        identity = self._require_authenticated(token)
        if self._downstream is not None:
            args = (
                "verify",
                identity,
                key_name,
                message_b64,
                message_type,
                signature_b64,
                signing_algorithm,
            )
            if key_owner_email is not None:
                args += (key_owner_email,)
            return self._downstream(*args)
        owner_email, actual_key_name, _ = self._resolve_key_reference(
            identity,
            key_name,
            key_owner_email,
        )
        self._validate_key_name(actual_key_name)
        record = self._get_signing_record(
            identity,
            owner_email,
            actual_key_name,
            "VERIFY",
        )
        if signing_algorithm is not None and signing_algorithm != record["signing_algorithm"]:
            raise InvalidSigningAlgorithmError()
        message = self._signing_input(message_b64, message_type)
        result = {
            "key_name": actual_key_name,
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

    def _get_signing_record(
        self,
        requester_email: str,
        owner_email: str,
        key_name: str,
        permission: str,
    ) -> dict[str, Any]:
        record = self._get_authorized_key(
            requester_email,
            owner_email,
            key_name,
            permission,
        )
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
