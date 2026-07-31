"""Cryptographic helpers for vault initialization and unlock.

This module owns the Feature 0.1 metadata envelope, passphrase policy,
Argon2id key derivation, strict base64 handling, and AES-256-GCM DEK wrap
operations. Public callers should translate any low-level failures to stable
Mini Vault domain errors before displaying them.
"""

from __future__ import annotations

import base64
import binascii
import secrets
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import InvalidInputError
from .shamir import SHARE_SET_ID_LEN, ShamirError, validate_config

SCHEMA_VERSION = 1
METADATA_AAD = b"mini-vault:vault-metadata:v1"
DEFAULT_METADATA_PATH = "data/vault_metadata.json"

KDF_ALGORITHM = "argon2id"
AEAD_ALGORITHM = "aes-256-gcm"
SHAMIR_ALGORITHM = "shamir-gf257"

SALT_LEN = 16
DEK_LEN = 32
NONCE_LEN = 12
GCM_TAG_LEN = 16

DEFAULT_ARGON2_MEMORY_COST_KIB = 65536
DEFAULT_ARGON2_TIME_COST = 3
DEFAULT_ARGON2_PARALLELISM = 1
DEFAULT_ARGON2_HASH_LEN = 32

MIN_ARGON2_MEMORY_COST_KIB = 8192
MAX_ARGON2_MEMORY_COST_KIB = 1048576
MIN_ARGON2_TIME_COST = 1
MAX_ARGON2_TIME_COST = 10
MIN_ARGON2_PARALLELISM = 1
MAX_ARGON2_PARALLELISM = 16
MIN_ARGON2_HASH_LEN = 16
MAX_ARGON2_HASH_LEN = 64


class MetadataValidationError(ValueError):
    """Internal non-public metadata validation failure."""


class CryptoOperationError(ValueError):
    """Internal non-public cryptographic operation failure."""


def validate_master_passphrase(passphrase: str) -> None:
    """Validate the master passphrase policy.

    Policy: at least 12 characters and at least one lowercase, uppercase,
    digit, and non-alphanumeric symbol. Only the public INVALID_INPUT domain
    error is raised for rejected user input.
    """

    if not isinstance(passphrase, str):
        raise InvalidInputError()
    if len(passphrase) < 12:
        raise InvalidInputError()
    checks = (
        any(ch.islower() for ch in passphrase),
        any(ch.isupper() for ch in passphrase),
        any(ch.isdigit() for ch in passphrase),
        any(not ch.isalnum() for ch in passphrase),
    )
    if not all(checks):
        raise InvalidInputError()


def b64_encode(data: bytes) -> str:
    if not isinstance(data, (bytes, bytearray)):
        raise MetadataValidationError()
    return base64.b64encode(bytes(data)).decode("ascii")


def b64_decode(value: str) -> bytes:
    if not isinstance(value, str):
        raise MetadataValidationError()
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise MetadataValidationError() from exc


def validate_kdf_parameters(memory_cost_kib: int, time_cost: int, parallelism: int, hash_len: int, salt: bytes) -> None:
    if not isinstance(memory_cost_kib, int) or not (MIN_ARGON2_MEMORY_COST_KIB <= memory_cost_kib <= MAX_ARGON2_MEMORY_COST_KIB):
        raise MetadataValidationError()
    if not isinstance(time_cost, int) or not (MIN_ARGON2_TIME_COST <= time_cost <= MAX_ARGON2_TIME_COST):
        raise MetadataValidationError()
    if not isinstance(parallelism, int) or not (MIN_ARGON2_PARALLELISM <= parallelism <= MAX_ARGON2_PARALLELISM):
        raise MetadataValidationError()
    if not isinstance(hash_len, int) or not (MIN_ARGON2_HASH_LEN <= hash_len <= MAX_ARGON2_HASH_LEN):
        raise MetadataValidationError()
    if not isinstance(salt, bytes) or len(salt) != SALT_LEN:
        raise MetadataValidationError()


def derive_wrapping_key(
    passphrase: str,
    salt: bytes,
    *,
    memory_cost_kib: int = DEFAULT_ARGON2_MEMORY_COST_KIB,
    time_cost: int = DEFAULT_ARGON2_TIME_COST,
    parallelism: int = DEFAULT_ARGON2_PARALLELISM,
    hash_len: int = DEFAULT_ARGON2_HASH_LEN,
) -> bytes:
    validate_kdf_parameters(memory_cost_kib, time_cost, parallelism, hash_len, salt)
    if not isinstance(passphrase, str):
        raise MetadataValidationError()
    try:
        return hash_secret_raw(
            secret=passphrase.encode("utf-8"),
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost_kib,
            parallelism=parallelism,
            hash_len=hash_len,
            type=Type.ID,
        )
    except Exception as exc:  # pragma: no cover - validated bounds should avoid normal failures
        raise CryptoOperationError() from exc


def wrap_dek(wrapping_key: bytes, dek: bytes, nonce: bytes) -> bytes:
    if not isinstance(wrapping_key, bytes) or len(wrapping_key) != DEK_LEN:
        raise CryptoOperationError()
    if not isinstance(dek, bytes) or len(dek) != DEK_LEN:
        raise CryptoOperationError()
    if not isinstance(nonce, bytes) or len(nonce) != NONCE_LEN:
        raise CryptoOperationError()
    try:
        return AESGCM(wrapping_key).encrypt(nonce, dek, METADATA_AAD)
    except Exception as exc:  # pragma: no cover - defensive
        raise CryptoOperationError() from exc


def unwrap_dek(wrapping_key: bytes, nonce: bytes, ciphertext_and_tag: bytes) -> bytes:
    if not isinstance(wrapping_key, bytes) or len(wrapping_key) != DEK_LEN:
        raise CryptoOperationError()
    if not isinstance(nonce, bytes) or len(nonce) != NONCE_LEN:
        raise MetadataValidationError()
    if not isinstance(ciphertext_and_tag, bytes) or len(ciphertext_and_tag) < GCM_TAG_LEN + 1:
        raise MetadataValidationError()
    try:
        dek = AESGCM(wrapping_key).decrypt(nonce, ciphertext_and_tag, METADATA_AAD)
    except (InvalidTag, ValueError) as exc:
        raise CryptoOperationError() from exc
    if len(dek) != DEK_LEN:
        raise CryptoOperationError()
    return dek


def construct_metadata(*, salt: bytes, nonce: bytes, ciphertext_and_tag: bytes) -> dict[str, Any]:
    metadata = {
        "schema_version": SCHEMA_VERSION,
        "kdf": {
            "algorithm": KDF_ALGORITHM,
            "salt_b64": b64_encode(salt),
            "memory_cost_kib": DEFAULT_ARGON2_MEMORY_COST_KIB,
            "time_cost": DEFAULT_ARGON2_TIME_COST,
            "parallelism": DEFAULT_ARGON2_PARALLELISM,
            "hash_len": DEFAULT_ARGON2_HASH_LEN,
        },
        "aead": {
            "algorithm": AEAD_ALGORITHM,
            "nonce_b64": b64_encode(nonce),
            "ciphertext_and_tag_b64": b64_encode(ciphertext_and_tag),
        },
    }
    validate_metadata(metadata)
    return metadata


def construct_shamir_metadata(
    *,
    threshold: int,
    total_shares: int,
    share_set_id: bytes,
    nonce: bytes,
    ciphertext_and_tag: bytes,
) -> dict[str, Any]:
    metadata = {
        "schema_version": SCHEMA_VERSION,
        "shamir": {
            "algorithm": SHAMIR_ALGORITHM,
            "threshold": threshold,
            "total_shares": total_shares,
            "share_set_id_b64": b64_encode(share_set_id),
        },
        "aead": {
            "algorithm": AEAD_ALGORITHM,
            "nonce_b64": b64_encode(nonce),
            "ciphertext_and_tag_b64": b64_encode(ciphertext_and_tag),
        },
    }
    validate_metadata(metadata)
    return metadata


def validate_metadata(metadata: Any) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        raise MetadataValidationError()
    fields = set(metadata)
    passphrase_fields = {"schema_version", "kdf", "aead"}
    shamir_fields = {"schema_version", "shamir", "aead"}
    if fields not in (passphrase_fields, shamir_fields):
        raise MetadataValidationError()
    if metadata.get("schema_version") != SCHEMA_VERSION:
        raise MetadataValidationError()

    aead = metadata.get("aead")
    if not isinstance(aead, dict):
        raise MetadataValidationError()
    if set(aead) != {"algorithm", "nonce_b64", "ciphertext_and_tag_b64"}:
        raise MetadataValidationError()
    if aead["algorithm"] != AEAD_ALGORITHM:
        raise MetadataValidationError()

    nonce = b64_decode(aead["nonce_b64"])
    ciphertext_and_tag = b64_decode(aead["ciphertext_and_tag_b64"])
    if len(nonce) != NONCE_LEN:
        raise MetadataValidationError()
    if len(ciphertext_and_tag) < GCM_TAG_LEN + 1:
        raise MetadataValidationError()

    if fields == passphrase_fields:
        kdf = metadata.get("kdf")
        if not isinstance(kdf, dict):
            raise MetadataValidationError()
        if set(kdf) != {"algorithm", "salt_b64", "memory_cost_kib", "time_cost", "parallelism", "hash_len"}:
            raise MetadataValidationError()
        if kdf["algorithm"] != KDF_ALGORITHM:
            raise MetadataValidationError()
        salt = b64_decode(kdf["salt_b64"])
        validate_kdf_parameters(
            kdf["memory_cost_kib"],
            kdf["time_cost"],
            kdf["parallelism"],
            kdf["hash_len"],
            salt,
        )
    else:
        shamir = metadata.get("shamir")
        if not isinstance(shamir, dict) or set(shamir) != {
            "algorithm",
            "threshold",
            "total_shares",
            "share_set_id_b64",
        }:
            raise MetadataValidationError()
        if shamir["algorithm"] != SHAMIR_ALGORITHM:
            raise MetadataValidationError()
        try:
            validate_config(shamir["threshold"], shamir["total_shares"])
        except ShamirError as exc:
            raise MetadataValidationError() from exc
        share_set_id = b64_decode(shamir["share_set_id_b64"])
        if len(share_set_id) != SHARE_SET_ID_LEN:
            raise MetadataValidationError()

    return metadata


def extract_metadata_fields(metadata: Any) -> tuple[bytes, bytes, bytes, int, int, int, int]:
    validated = validate_metadata(metadata)
    kdf = validated["kdf"]
    aead = validated["aead"]
    return (
        b64_decode(kdf["salt_b64"]),
        b64_decode(aead["nonce_b64"]),
        b64_decode(aead["ciphertext_and_tag_b64"]),
        kdf["memory_cost_kib"],
        kdf["time_cost"],
        kdf["parallelism"],
        kdf["hash_len"],
    )


def extract_shamir_metadata_fields(
    metadata: Any,
) -> tuple[int, int, bytes, bytes, bytes]:
    validated = validate_metadata(metadata)
    shamir = validated["shamir"]
    aead = validated["aead"]
    return (
        shamir["threshold"],
        shamir["total_shares"],
        b64_decode(shamir["share_set_id_b64"]),
        b64_decode(aead["nonce_b64"]),
        b64_decode(aead["ciphertext_and_tag_b64"]),
    )


def random_salt() -> bytes:
    return secrets.token_bytes(SALT_LEN)


def random_dek() -> bytes:
    return secrets.token_bytes(DEK_LEN)


def random_nonce() -> bytes:
    return secrets.token_bytes(NONCE_LEN)
