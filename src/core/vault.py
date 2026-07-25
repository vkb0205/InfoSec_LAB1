"""Vault initialization, unlock, and in-memory DEK state."""

from __future__ import annotations

import secrets
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from src.crypto_utils import (
    AES_256_KEY_BYTES,
    AES_GCM_NONCE_BYTES,
    ARGON2_SALT_BYTES,
    Argon2idParameters,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    decode_base64,
    derive_argon2id_key,
    encode_base64,
)
from src.errors import (
    ALREADY_INITIALIZED,
    INVALID_INPUT,
    NOT_INITIALIZED,
    UNLOCK_FAILED,
    VAULT_LOCKED,
    MiniVaultError,
)
from src.storage.repository import VAULT_METADATA_FILE, JsonRepository


VAULT_METADATA_VERSION = 1
DEK_ASSOCIATED_DATA = b"mini-vault:dek:v1"
MIN_MASTER_PASSPHRASE_LENGTH = 12
MAX_MASTER_PASSPHRASE_LENGTH = 128
GENERIC_UNLOCK_MESSAGE = "Vault unlock failed."


@dataclass(frozen=True)
class VaultMetadata:
    """Validated public metadata and encrypted DEK stored in ``vault.json``."""

    kdf_salt_b64: str
    kdf_parameters: Argon2idParameters
    encrypted_dek_b64: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": VAULT_METADATA_VERSION,
            "kdf": "argon2id",
            "kdf_salt_b64": self.kdf_salt_b64,
            "kdf_parameters": self.kdf_parameters.to_dict(),
            "encrypted_dek_b64": self.encrypted_dek_b64,
            # Never persist an unlocked state. Unlocking is process-local.
            "status": "locked",
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "VaultMetadata":
        if value.get("version") != VAULT_METADATA_VERSION:
            raise ValueError("Unsupported vault metadata version.")
        if value.get("kdf") != "argon2id":
            raise ValueError("Unsupported vault KDF.")
        if value.get("status") != "locked":
            raise ValueError("Vault metadata status is invalid.")

        salt_b64 = value.get("kdf_salt_b64")
        encrypted_dek_b64 = value.get("encrypted_dek_b64")
        if not isinstance(salt_b64, str) or not isinstance(encrypted_dek_b64, str):
            raise ValueError("Vault metadata is incomplete.")

        return cls(
            kdf_salt_b64=salt_b64,
            kdf_parameters=Argon2idParameters.from_dict(
                value.get("kdf_parameters")
            ),
            encrypted_dek_b64=encrypted_dek_b64,
        )


def validate_master_passphrase(passphrase: str) -> None:
    """Enforce the documented master-passphrase policy."""

    if not isinstance(passphrase, str):
        raise MiniVaultError(INVALID_INPUT, "Master passphrase must be text.")
    if not MIN_MASTER_PASSPHRASE_LENGTH <= len(
        passphrase
    ) <= MAX_MASTER_PASSPHRASE_LENGTH:
        raise MiniVaultError(
            INVALID_INPUT,
            "Master passphrase must contain between 12 and 128 characters.",
        )
    if any(unicodedata.category(character) == "Cc" for character in passphrase):
        raise MiniVaultError(
            INVALID_INPUT,
            "Master passphrase must not contain control characters.",
        )

    character_classes = (
        any(character.islower() for character in passphrase),
        any(character.isupper() for character in passphrase),
        any(character.isdigit() for character in passphrase),
        any(
            not character.isalnum() and not character.isspace()
            for character in passphrase
        ),
    )
    if not all(character_classes):
        raise MiniVaultError(
            INVALID_INPUT,
            "Master passphrase must include lowercase, uppercase, number, "
            "and symbol characters.",
        )


class Vault:
    """Own the DEK and enforce the locked/unlocked process state.

    The plaintext DEK is held only by a live instance and is never included in
    a return value. Constructing a new instance always starts locked, even when
    the previous process had successfully unlocked the same metadata file.
    """

    def __init__(
        self,
        repository: JsonRepository,
        *,
        metadata_filename: str = VAULT_METADATA_FILE,
        kdf_parameters: Argon2idParameters | None = None,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        self._repository = repository
        self._metadata_filename = metadata_filename
        self._kdf_parameters = kdf_parameters or Argon2idParameters()
        self._random_bytes = random_bytes
        self._dek: bytearray | None = None

    @property
    def is_initialized(self) -> bool:
        return self._repository.exists(self._metadata_filename)

    @property
    def is_locked(self) -> bool:
        return self._dek is None

    def public_status(self) -> dict[str, bool | str]:
        """Return non-sensitive state suitable for CLI or API responses."""

        return {
            "initialized": self.is_initialized,
            "status": "locked" if self.is_locked else "unlocked",
        }

    def initialize(self, master_passphrase: str) -> dict[str, bool | str]:
        """Create and persist a new encrypted DEK on first run."""

        if self.is_initialized:
            raise MiniVaultError(
                ALREADY_INITIALIZED,
                "Vault is already initialized.",
            )
        validate_master_passphrase(master_passphrase)

        salt = self._secure_random(ARGON2_SALT_BYTES)
        dek = self._secure_random(AES_256_KEY_BYTES)
        nonce = self._secure_random(AES_GCM_NONCE_BYTES)
        wrapping_key = derive_argon2id_key(
            master_passphrase,
            salt,
            self._kdf_parameters,
        )
        encrypted_dek = aes_gcm_encrypt(
            wrapping_key,
            dek,
            nonce=nonce,
            associated_data=DEK_ASSOCIATED_DATA,
        )
        metadata = VaultMetadata(
            kdf_salt_b64=encode_base64(salt),
            kdf_parameters=self._kdf_parameters,
            encrypted_dek_b64=encode_base64(encrypted_dek),
        )

        # Save before changing process state. A failed write must not result in
        # an unlocked vault whose DEK cannot be recovered after restart.
        self._repository.save(self._metadata_filename, metadata.to_dict())
        self._replace_dek(dek)
        return self.public_status()

    def unlock(self, master_passphrase: str) -> dict[str, bool | str]:
        """Unlock using the master passphrase, returning only public state."""

        if not self.is_initialized:
            raise MiniVaultError(NOT_INITIALIZED, "Vault is not initialized.")

        stored_value = self._repository.load(self._metadata_filename)
        try:
            metadata = VaultMetadata.from_dict(stored_value)
            salt = decode_base64(metadata.kdf_salt_b64)
            if len(salt) != ARGON2_SALT_BYTES:
                raise ValueError("Unexpected salt length.")

            wrapping_key = derive_argon2id_key(
                master_passphrase,
                salt,
                metadata.kdf_parameters,
            )
            encrypted_dek = decode_base64(metadata.encrypted_dek_b64)
            dek = aes_gcm_decrypt(
                wrapping_key,
                encrypted_dek,
                associated_data=DEK_ASSOCIATED_DATA,
            )
            if len(dek) != AES_256_KEY_BYTES:
                raise ValueError("Unexpected DEK length.")
        except Exception as exc:
            # Wrong passphrases, invalid tags, malformed base64, and tampered
            # metadata intentionally share one response to avoid an oracle.
            self.lock()
            raise MiniVaultError(
                UNLOCK_FAILED,
                GENERIC_UNLOCK_MESSAGE,
            ) from exc

        self._replace_dek(dek)
        return self.public_status()

    def lock(self) -> dict[str, bool | str]:
        """Forget the in-memory DEK and return the public locked state."""

        if self._dek is not None:
            for index in range(len(self._dek)):
                self._dek[index] = 0
            self._dek = None
        return self.public_status()

    def require_unlocked(self) -> None:
        """Guard future KV and Transit operations."""

        if self.is_locked:
            raise MiniVaultError(VAULT_LOCKED, "Vault is locked.")

    def _replace_dek(self, value: bytes) -> None:
        self.lock()
        self._dek = bytearray(value)

    def _secure_random(self, length: int) -> bytes:
        value = self._random_bytes(length)
        if not isinstance(value, bytes) or len(value) != length:
            raise RuntimeError("Secure random source returned invalid output.")
        return value
