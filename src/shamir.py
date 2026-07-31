"""Small GF(257) Shamir implementation for 32-byte vault wrapping keys."""

from __future__ import annotations

import base64
import binascii
import secrets
from dataclasses import dataclass
from typing import Iterable

PRIME = 257
MIN_THRESHOLD = 2
MAX_SHARES = 255
SECRET_LEN = 32
SHARE_SET_ID_LEN = 16

SHARE_MAGIC = b"MVSS"
SHARE_VERSION = 1
SHARE_HEADER_LEN = len(SHARE_MAGIC) + 4 + SHARE_SET_ID_LEN
SHARE_RAW_LEN = SHARE_HEADER_LEN + SECRET_LEN * 2


class ShamirError(ValueError):
    """Internal failure for invalid Shamir inputs or shares."""


@dataclass(frozen=True)
class DecodedShare:
    threshold: int
    total_shares: int
    index: int
    share_set_id: bytes
    values: tuple[int, ...]


def validate_config(threshold: int, total_shares: int) -> None:
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, int)
        or isinstance(total_shares, bool)
        or not isinstance(total_shares, int)
        or threshold < MIN_THRESHOLD
        or threshold > total_shares
        or total_shares > MAX_SHARES
    ):
        raise ShamirError()


def generate_share_set_id() -> bytes:
    return secrets.token_bytes(SHARE_SET_ID_LEN)


def split_secret(
    secret: bytes,
    threshold: int,
    total_shares: int,
    share_set_id: bytes,
) -> list[str]:
    validate_config(threshold, total_shares)
    if (
        not isinstance(secret, bytes)
        or len(secret) != SECRET_LEN
        or not isinstance(share_set_id, bytes)
        or len(share_set_id) != SHARE_SET_ID_LEN
    ):
        raise ShamirError()

    polynomials = [
        [secret_byte] + [secrets.randbelow(PRIME) for _ in range(threshold - 1)]
        for secret_byte in secret
    ]
    shares = []
    for index in range(1, total_shares + 1):
        values = tuple(_evaluate(coefficients, index) for coefficients in polynomials)
        shares.append(_encode_share(
            DecodedShare(
                threshold=threshold,
                total_shares=total_shares,
                index=index,
                share_set_id=share_set_id,
                values=values,
            )
        ))
    return shares


def combine_shares(
    encoded_shares: Iterable[str],
    threshold: int,
    total_shares: int,
    share_set_id: bytes,
) -> bytes:
    validate_config(threshold, total_shares)
    if (
        isinstance(encoded_shares, (str, bytes))
        or not isinstance(share_set_id, bytes)
        or len(share_set_id) != SHARE_SET_ID_LEN
    ):
        raise ShamirError()
    try:
        supplied = list(encoded_shares)
    except TypeError as exc:
        raise ShamirError() from exc
    if len(supplied) < threshold:
        raise ShamirError()

    decoded = [_decode_share(share) for share in supplied]
    indexes: set[int] = set()
    for share in decoded:
        if (
            share.threshold != threshold
            or share.total_shares != total_shares
            or share.share_set_id != share_set_id
            or share.index in indexes
        ):
            raise ShamirError()
        indexes.add(share.index)

    selected = sorted(decoded, key=lambda share: share.index)[:threshold]
    secret = bytearray()
    for position in range(SECRET_LEN):
        value = 0
        for current in selected:
            numerator = 1
            denominator = 1
            for other in selected:
                if other.index == current.index:
                    continue
                numerator = numerator * (-other.index) % PRIME
                denominator = denominator * (current.index - other.index) % PRIME
            value = (
                value
                + current.values[position]
                * numerator
                * pow(denominator, -1, PRIME)
            ) % PRIME
        if value > 255:
            raise ShamirError()
        secret.append(value)
    return bytes(secret)


def _evaluate(coefficients: list[int], x: int) -> int:
    result = 0
    for coefficient in reversed(coefficients):
        result = (result * x + coefficient) % PRIME
    return result


def _encode_share(share: DecodedShare) -> str:
    raw = bytearray(SHARE_MAGIC)
    raw.extend((
        SHARE_VERSION,
        share.threshold,
        share.total_shares,
        share.index,
    ))
    raw.extend(share.share_set_id)
    for value in share.values:
        raw.extend(value.to_bytes(2, "big"))
    return base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode("ascii")


def _decode_share(encoded: str) -> DecodedShare:
    if not isinstance(encoded, str) or not encoded or "=" in encoded:
        raise ShamirError()
    try:
        encoded_bytes = encoded.encode("ascii")
        padding = b"=" * ((4 - len(encoded_bytes) % 4) % 4)
        raw = base64.b64decode(
            encoded_bytes + padding,
            altchars=b"-_",
            validate=True,
        )
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ShamirError() from exc
    if (
        len(raw) != SHARE_RAW_LEN
        or raw[:len(SHARE_MAGIC)] != SHARE_MAGIC
        or raw[len(SHARE_MAGIC)] != SHARE_VERSION
        or base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != encoded
    ):
        raise ShamirError()

    offset = len(SHARE_MAGIC) + 1
    threshold, total_shares, index = raw[offset:offset + 3]
    share_set_offset = offset + 3
    share_set_id = raw[share_set_offset:share_set_offset + SHARE_SET_ID_LEN]
    values_bytes = raw[share_set_offset + SHARE_SET_ID_LEN:]
    try:
        validate_config(threshold, total_shares)
    except ShamirError:
        raise
    if index < 1 or index > total_shares:
        raise ShamirError()
    values = tuple(
        int.from_bytes(values_bytes[position:position + 2], "big")
        for position in range(0, len(values_bytes), 2)
    )
    if len(values) != SECRET_LEN or any(value >= PRIME for value in values):
        raise ShamirError()
    return DecodedShare(
        threshold=threshold,
        total_shares=total_shares,
        index=index,
        share_set_id=share_set_id,
        values=values,
    )
