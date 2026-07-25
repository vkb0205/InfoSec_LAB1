"""Small, reviewed cryptographic primitives used by Mini Vault.

This module only combines established primitives from ``argon2-cffi`` and
``cryptography``.  It does not implement a cipher or KDF itself.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from argon2.low_level import ARGON2_VERSION, Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


AES_256_KEY_BYTES = 32
AES_GCM_NONCE_BYTES = 12
AES_GCM_TAG_BYTES = 16
ARGON2_SALT_BYTES = 16


@dataclass(frozen=True)
class AesGcmEnvelope:
    """AES-GCM nonce, ciphertext, and authentication tag.

    The shape maps directly to the required KV JSON fields and can also be
    packed as ``nonce || ciphertext || tag`` for wrapped keys and Transit.
    """

    nonce: bytes
    ciphertext: bytes
    tag: bytes

    def __post_init__(self) -> None:
        if (
            not isinstance(self.nonce, bytes)
            or len(self.nonce) != AES_GCM_NONCE_BYTES
        ):
            raise ValueError("AES-GCM envelope nonce must be exactly 96 bits.")
        if not isinstance(self.ciphertext, bytes):
            raise ValueError("AES-GCM envelope ciphertext must be bytes.")
        if not isinstance(self.tag, bytes) or len(self.tag) != AES_GCM_TAG_BYTES:
            raise ValueError("AES-GCM envelope tag must be exactly 128 bits.")

    def pack(self) -> bytes:
        """Return ``nonce || ciphertext || tag``."""

        return self.nonce + self.ciphertext + self.tag

    def to_base64_fields(self) -> dict[str, str]:
        """Return the exact encrypted fields required by KV JSON storage."""

        return {
            "nonce_b64": encode_base64(self.nonce),
            "ciphertext_b64": encode_base64(self.ciphertext),
            "tag_b64": encode_base64(self.tag),
        }

    @classmethod
    def unpack(cls, value: bytes) -> "AesGcmEnvelope":
        """Parse a packed envelope and reject malformed or truncated values."""

        if not isinstance(value, bytes):
            raise ValueError("Packed AES-GCM envelope must be bytes.")
        minimum_length = AES_GCM_NONCE_BYTES + AES_GCM_TAG_BYTES
        if len(value) < minimum_length:
            raise ValueError("Packed AES-GCM envelope is truncated.")
        return cls(
            nonce=value[:AES_GCM_NONCE_BYTES],
            ciphertext=value[AES_GCM_NONCE_BYTES:-AES_GCM_TAG_BYTES],
            tag=value[-AES_GCM_TAG_BYTES:],
        )

    @classmethod
    def from_base64_fields(
        cls,
        value: Mapping[str, Any],
    ) -> "AesGcmEnvelope":
        """Parse the three required KV fields using strict base64 decoding."""

        if not isinstance(value, Mapping):
            raise ValueError("AES-GCM storage fields must be an object.")
        return cls(
            nonce=decode_base64(value.get("nonce_b64")),
            ciphertext=decode_base64(value.get("ciphertext_b64")),
            tag=decode_base64(value.get("tag_b64")),
        )


@dataclass(frozen=True)
class Argon2idParameters:
    """Persisted Argon2id parameters for deriving a 256-bit wrapping key."""

    time_cost: int = 3
    memory_cost_kib: int = 65_536
    parallelism: int = 4
    hash_length: int = AES_256_KEY_BYTES
    version: int = ARGON2_VERSION

    def __post_init__(self) -> None:
        # Bounds also prevent a tampered metadata file from causing an
        # unreasonable CPU or memory request during unlock.
        if isinstance(self.time_cost, bool) or not 1 <= self.time_cost <= 10:
            raise ValueError("Argon2id time_cost is outside the accepted range.")
        if (
            isinstance(self.memory_cost_kib, bool)
            or not 8_192 <= self.memory_cost_kib <= 262_144
        ):
            raise ValueError(
                "Argon2id memory_cost_kib is outside the accepted range."
            )
        if (
            isinstance(self.parallelism, bool)
            or not 1 <= self.parallelism <= 16
        ):
            raise ValueError("Argon2id parallelism is outside the accepted range.")
        if self.hash_length != AES_256_KEY_BYTES:
            raise ValueError("Argon2id output must be exactly 256 bits.")
        if self.version != ARGON2_VERSION:
            raise ValueError("Unsupported Argon2 version.")

    def to_dict(self) -> dict[str, int]:
        return {
            "time_cost": self.time_cost,
            "memory_cost_kib": self.memory_cost_kib,
            "parallelism": self.parallelism,
            "hash_length": self.hash_length,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "Argon2idParameters":
        if not isinstance(value, dict):
            raise ValueError("Argon2id parameters must be a JSON object.")

        fields = (
            "time_cost",
            "memory_cost_kib",
            "parallelism",
            "hash_length",
            "version",
        )
        if any(
            field not in value
            or isinstance(value[field], bool)
            or not isinstance(value[field], int)
            for field in fields
        ):
            raise ValueError("Argon2id parameters are incomplete or invalid.")
        return cls(**{field: value[field] for field in fields})


def derive_argon2id_key(
    passphrase: str,
    salt: bytes,
    parameters: Argon2idParameters,
) -> bytes:
    """Derive an AES-256 wrapping key from an exact Unicode passphrase."""

    if not isinstance(passphrase, str):
        raise TypeError("Passphrase must be text.")
    if len(salt) < ARGON2_SALT_BYTES:
        raise ValueError("Argon2id salt is too short.")

    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=parameters.time_cost,
        memory_cost=parameters.memory_cost_kib,
        parallelism=parameters.parallelism,
        hash_len=parameters.hash_length,
        type=Type.ID,
        version=parameters.version,
    )


def aes_gcm_encrypt(
    key: bytes,
    plaintext: bytes,
    *,
    nonce: bytes,
    associated_data: bytes,
) -> bytes:
    """Low-level AES-256-GCM encryption with a caller-provided nonce.

    Application services should use ``Vault.encrypt_with_dek`` so nonce
    generation and locked-state enforcement cannot be skipped.
    """

    if not isinstance(key, bytes) or len(key) != AES_256_KEY_BYTES:
        raise ValueError("AES-256-GCM requires a 256-bit key.")
    if not isinstance(plaintext, bytes):
        raise ValueError("AES-GCM plaintext must be bytes.")
    if not isinstance(nonce, bytes) or len(nonce) != AES_GCM_NONCE_BYTES:
        raise ValueError("AES-GCM requires a 96-bit nonce in Mini Vault.")
    if not isinstance(associated_data, bytes):
        raise ValueError("AES-GCM associated data must be bytes.")

    ciphertext_and_tag = AESGCM(key).encrypt(
        nonce,
        plaintext,
        associated_data,
    )
    return AesGcmEnvelope(
        nonce=nonce,
        ciphertext=ciphertext_and_tag[:-AES_GCM_TAG_BYTES],
        tag=ciphertext_and_tag[-AES_GCM_TAG_BYTES:],
    ).pack()


def aes_gcm_decrypt(
    key: bytes,
    encrypted_blob: bytes,
    *,
    associated_data: bytes,
) -> bytes:
    """Decrypt and authenticate ``nonce || ciphertext || tag``."""

    if not isinstance(key, bytes) or len(key) != AES_256_KEY_BYTES:
        raise ValueError("AES-256-GCM requires a 256-bit key.")
    if not isinstance(associated_data, bytes):
        raise ValueError("AES-GCM associated data must be bytes.")

    envelope = AesGcmEnvelope.unpack(encrypted_blob)
    return AESGCM(key).decrypt(
        envelope.nonce,
        envelope.ciphertext + envelope.tag,
        associated_data,
    )


def encode_base64(value: bytes) -> str:
    """Encode bytes as canonical ASCII base64 for JSON persistence."""

    return base64.b64encode(value).decode("ascii")


def decode_base64(value: Any) -> bytes:
    """Decode strict base64, rejecting non-text and malformed values."""

    if not isinstance(value, str):
        raise ValueError("Base64 value must be text.")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Malformed base64 value.") from exc
