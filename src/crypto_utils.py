"""Small, reviewed cryptographic primitives used by Mini Vault.

This module only combines established primitives from ``argon2-cffi`` and
``cryptography``.  It does not implement a cipher or KDF itself.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from typing import Any

from argon2.low_level import ARGON2_VERSION, Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


AES_256_KEY_BYTES = 32
AES_GCM_NONCE_BYTES = 12
AES_GCM_TAG_BYTES = 16
ARGON2_SALT_BYTES = 16


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
    """Return ``nonce || ciphertext || tag`` using AES-256-GCM."""

    if len(key) != AES_256_KEY_BYTES:
        raise ValueError("AES-256-GCM requires a 256-bit key.")
    if len(nonce) != AES_GCM_NONCE_BYTES:
        raise ValueError("AES-GCM requires a 96-bit nonce in Mini Vault.")
    return nonce + AESGCM(key).encrypt(nonce, plaintext, associated_data)


def aes_gcm_decrypt(
    key: bytes,
    encrypted_blob: bytes,
    *,
    associated_data: bytes,
) -> bytes:
    """Decrypt and authenticate ``nonce || ciphertext || tag``."""

    minimum_length = AES_GCM_NONCE_BYTES + AES_GCM_TAG_BYTES
    if len(key) != AES_256_KEY_BYTES:
        raise ValueError("AES-256-GCM requires a 256-bit key.")
    if len(encrypted_blob) < minimum_length:
        raise ValueError("AES-GCM encrypted value is truncated.")

    nonce = encrypted_blob[:AES_GCM_NONCE_BYTES]
    ciphertext_and_tag = encrypted_blob[AES_GCM_NONCE_BYTES:]
    return AESGCM(key).decrypt(nonce, ciphertext_and_tag, associated_data)


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
