"""Minimal RFC 6238 TOTP helpers and passphrase-wrapped seed storage."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
from datetime import datetime
from urllib.parse import quote, urlencode

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.crypto_utils import (
    NONCE_LEN,
    SALT_LEN,
    MetadataValidationError,
    b64_decode,
    b64_encode,
    derive_wrapping_key,
    random_nonce,
    random_salt,
)

TOTP_TYPE = "TOTP"
TOTP_ALGORITHM = "SHA1"
TOTP_DIGITS = 6
TOTP_PERIOD = 30
TOTP_SEED_LEN = 20
TOTP_WINDOW = 1
ENCRYPTED_SEED_ENVELOPE_LEN = SALT_LEN + NONCE_LEN + TOTP_SEED_LEN + 16
MFA_AAD_PREFIX = "mini-vault:mfa-seed:v1:"


class TotpDataError(ValueError):
    """Internal failure for malformed or unauthentic MFA data."""


def generate_seed() -> bytes:
    return secrets.token_bytes(TOTP_SEED_LEN)


def encode_seed(seed: bytes) -> str:
    if not isinstance(seed, bytes) or len(seed) != TOTP_SEED_LEN:
        raise TotpDataError()
    return base64.b32encode(seed).decode("ascii").rstrip("=")


def decode_seed(secret_b32: str) -> bytes:
    if not isinstance(secret_b32, str) or not secret_b32:
        raise TotpDataError()
    padding = "=" * ((8 - len(secret_b32) % 8) % 8)
    try:
        seed = base64.b32decode(secret_b32 + padding, casefold=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise TotpDataError() from exc
    if len(seed) != TOTP_SEED_LEN:
        raise TotpDataError()
    return seed


def totp_code(secret_b32: str, at_time: datetime) -> str:
    return _code_for_counter(decode_seed(secret_b32), _counter(at_time))


def verify_totp(seed: bytes, otp: str | None, at_time: datetime) -> bool:
    if (
        not isinstance(seed, bytes)
        or len(seed) != TOTP_SEED_LEN
        or not isinstance(otp, str)
        or len(otp) != TOTP_DIGITS
        or not otp.isascii()
        or not otp.isdigit()
    ):
        return False
    counter = _counter(at_time)
    valid = False
    for offset in range(-TOTP_WINDOW, TOTP_WINDOW + 1):
        if counter + offset < 0:
            continue
        valid = hmac.compare_digest(
            otp,
            _code_for_counter(seed, counter + offset),
        ) | valid
    return valid


def provisioning_uri(secret_b32: str, email: str, issuer: str = "Mini Vault") -> str:
    decode_seed(secret_b32)
    if not isinstance(email, str) or not email or not isinstance(issuer, str) or not issuer:
        raise TotpDataError()
    label = quote(f"{issuer}:{email}", safe="")
    query = urlencode({
        "secret": secret_b32,
        "issuer": issuer,
        "algorithm": TOTP_ALGORITHM,
        "digits": TOTP_DIGITS,
        "period": TOTP_PERIOD,
    })
    return f"otpauth://totp/{label}?{query}"


def encrypt_seed(seed: bytes, passphrase: str, email: str) -> str:
    if (
        not isinstance(seed, bytes)
        or len(seed) != TOTP_SEED_LEN
        or not isinstance(passphrase, str)
        or not isinstance(email, str)
        or not email
    ):
        raise TotpDataError()
    wrapping_key: bytes | None = None
    try:
        salt = random_salt()
        nonce = random_nonce()
        wrapping_key = derive_wrapping_key(passphrase, salt)
        encrypted = AESGCM(wrapping_key).encrypt(nonce, seed, _aad(email))
        return b64_encode(salt + nonce + encrypted)
    except Exception as exc:
        raise TotpDataError() from exc
    finally:
        wrapping_key = None


def decrypt_seed(encrypted_seed_b64: str, passphrase: str, email: str) -> bytes:
    wrapping_key: bytes | None = None
    try:
        envelope = b64_decode(encrypted_seed_b64)
        if len(envelope) != ENCRYPTED_SEED_ENVELOPE_LEN:
            raise TotpDataError()
        salt = envelope[:SALT_LEN]
        nonce = envelope[SALT_LEN:SALT_LEN + NONCE_LEN]
        encrypted = envelope[SALT_LEN + NONCE_LEN:]
        wrapping_key = derive_wrapping_key(passphrase, salt)
        seed = AESGCM(wrapping_key).decrypt(nonce, encrypted, _aad(email))
        if len(seed) != TOTP_SEED_LEN:
            raise TotpDataError()
        return seed
    except (MetadataValidationError, InvalidTag, ValueError, TypeError) as exc:
        raise TotpDataError() from exc
    finally:
        wrapping_key = None


def _counter(at_time: datetime) -> int:
    if not isinstance(at_time, datetime) or at_time.tzinfo is None:
        raise TotpDataError()
    return int(at_time.timestamp()) // TOTP_PERIOD


def _code_for_counter(seed: bytes, counter: int) -> str:
    if counter < 0:
        raise TotpDataError()
    digest = hmac.new(
        seed,
        counter.to_bytes(8, "big"),
        hashlib.sha1,
    ).digest()
    offset = digest[-1] & 0x0F
    truncated = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return str(truncated % (10 ** TOTP_DIGITS)).zfill(TOTP_DIGITS)


def _aad(email: str) -> bytes:
    return f"{MFA_AAD_PREFIX}{email}".encode("utf-8")
