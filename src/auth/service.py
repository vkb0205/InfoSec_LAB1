"""User registration, login, sessions, and mandatory account lockout."""

from __future__ import annotations

import hashlib
import re
import secrets
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from argon2.low_level import Type

from src.errors import (
    ACCOUNT_LOCKED,
    EMAIL_ALREADY_REGISTERED,
    INVALID_INPUT,
    STORAGE_ERROR,
    UNAUTHENTICATED,
    MiniVaultError,
)
from src.storage.repository import SESSIONS_FILE, USERS_FILE, JsonRepository


AUTH_STORAGE_VERSION = 1
MIN_USER_PASSPHRASE_LENGTH = 12
MAX_USER_PASSPHRASE_LENGTH = 128
SESSION_TOKEN_BYTES = 32
SESSION_LIFETIME = timedelta(minutes=30)
ACCOUNT_LOCKOUT_DURATION = timedelta(minutes=5)
MAX_FAILED_ATTEMPTS = 5

INVALID_CREDENTIALS_MESSAGE = "Invalid email or passphrase."
ACCOUNT_LOCKED_MESSAGE = "Account is temporarily locked."
UNAUTHENTICATED_MESSAGE = "Session token is invalid or expired."

# ASCII email addresses keep the owner component unambiguous in the required
# ``secret/<email>/...`` namespace. Slash and backslash are intentionally not
# allowed in the local part.
EMAIL_PATTERN = re.compile(
    r"^[a-z0-9.!#$%&'*+=?^_`{|}~-]+@"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("Timestamp must be text.")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Timestamp must include a timezone.")
    return parsed.astimezone(timezone.utc)


def normalize_email(email: str) -> str:
    """Validate and canonicalize an email for identity and path ownership."""

    if not isinstance(email, str):
        raise MiniVaultError(INVALID_INPUT, "Email must be text.")
    normalized = email.strip().casefold()
    if (
        len(normalized) > 254
        or normalized.count("@") != 1
        or not EMAIL_PATTERN.fullmatch(normalized)
    ):
        raise MiniVaultError(INVALID_INPUT, "Email address is invalid.")

    local_part, domain = normalized.rsplit("@", 1)
    if (
        len(local_part) > 64
        or local_part.startswith(".")
        or local_part.endswith(".")
        or ".." in local_part
        or any(len(label) > 63 for label in domain.split("."))
    ):
        raise MiniVaultError(INVALID_INPUT, "Email address is invalid.")
    return normalized


def validate_user_passphrase(passphrase: str) -> None:
    """Enforce the documented user-passphrase strength policy."""

    if not isinstance(passphrase, str):
        raise MiniVaultError(INVALID_INPUT, "User passphrase must be text.")
    if not MIN_USER_PASSPHRASE_LENGTH <= len(
        passphrase
    ) <= MAX_USER_PASSPHRASE_LENGTH:
        raise MiniVaultError(
            INVALID_INPUT,
            "User passphrase must contain between 12 and 128 characters.",
        )
    if any(unicodedata.category(character) == "Cc" for character in passphrase):
        raise MiniVaultError(
            INVALID_INPUT,
            "User passphrase must not contain control characters.",
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
            "User passphrase must include lowercase, uppercase, number, "
            "and symbol characters.",
        )


@dataclass(frozen=True)
class UserRecord:
    """Persistent user authentication and lockout state."""

    email: str
    password_hash: str
    failed_attempts: int = 0
    locked_until: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "email": self.email,
            "password_hash": self.password_hash,
            "failed_attempts": self.failed_attempts,
            "locked_until": (
                _format_timestamp(self.locked_until)
                if self.locked_until is not None
                else None
            ),
        }

    @classmethod
    def from_dict(cls, value: Any) -> "UserRecord":
        if not isinstance(value, dict):
            raise ValueError("User record must be a JSON object.")
        email = value.get("email")
        password_hash = value.get("password_hash")
        failed_attempts = value.get("failed_attempts")
        locked_value = value.get("locked_until")
        if (
            not isinstance(email, str)
            or not isinstance(password_hash, str)
            or not password_hash.startswith("$argon2")
            or isinstance(failed_attempts, bool)
            or not isinstance(failed_attempts, int)
            or not 0 <= failed_attempts <= MAX_FAILED_ATTEMPTS
        ):
            raise ValueError("User record is invalid.")

        locked_until = (
            None if locked_value is None else _parse_timestamp(locked_value)
        )
        if (failed_attempts == MAX_FAILED_ATTEMPTS) != (
            locked_until is not None
        ):
            raise ValueError("User lockout state is inconsistent.")
        return cls(
            email=email,
            password_hash=password_hash,
            failed_attempts=failed_attempts,
            locked_until=locked_until,
        )


@dataclass(frozen=True)
class SessionIdentity:
    """Authenticated identity returned to KV and Transit authorization."""

    email: str
    expires_at: datetime

    def to_dict(self) -> dict[str, str]:
        return {
            "email": self.email,
            "expires_at": _format_timestamp(self.expires_at),
        }


@dataclass(frozen=True)
class SessionRecord:
    """Persistent session metadata keyed by a one-way token fingerprint."""

    email: str
    created_at: datetime
    expires_at: datetime

    def to_dict(self) -> dict[str, str]:
        return {
            "email": self.email,
            "created_at": _format_timestamp(self.created_at),
            "expires_at": _format_timestamp(self.expires_at),
        }

    @classmethod
    def from_dict(cls, value: Any) -> "SessionRecord":
        if not isinstance(value, dict) or not isinstance(value.get("email"), str):
            raise ValueError("Session record is invalid.")
        created_at = _parse_timestamp(value.get("created_at"))
        expires_at = _parse_timestamp(value.get("expires_at"))
        if expires_at <= created_at:
            raise ValueError("Session expiry must be after creation.")
        return cls(
            email=value["email"],
            created_at=created_at,
            expires_at=expires_at,
        )


class AuthService:
    """Authenticate users without persisting passwords or raw session tokens."""

    def __init__(
        self,
        repository: JsonRepository,
        *,
        users_filename: str = USERS_FILE,
        sessions_filename: str = SESSIONS_FILE,
        password_hasher: PasswordHasher | None = None,
        token_generator: Callable[[int], str] = secrets.token_urlsafe,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._repository = repository
        self._users_filename = users_filename
        self._sessions_filename = sessions_filename
        self._password_hasher = password_hasher or PasswordHasher(
            time_cost=3,
            memory_cost=65_536,
            parallelism=4,
            hash_len=32,
            salt_len=16,
            type=Type.ID,
        )
        self._token_generator = token_generator
        self._clock = clock

    def register(
        self,
        email: str,
        passphrase: str,
        confirm_passphrase: str,
    ) -> dict[str, bool | str]:
        """Register a unique normalized email with an Argon2id password hash."""

        normalized_email = normalize_email(email)
        validate_user_passphrase(passphrase)
        if not isinstance(confirm_passphrase, str) or not secrets.compare_digest(
            passphrase.encode("utf-8"),
            confirm_passphrase.encode("utf-8"),
        ):
            raise MiniVaultError(INVALID_INPUT, "User passphrases do not match.")

        users = self._load_users()
        if normalized_email in users:
            raise MiniVaultError(
                EMAIL_ALREADY_REGISTERED,
                "Email address is already registered.",
            )

        users[normalized_email] = UserRecord(
            email=normalized_email,
            password_hash=self._password_hasher.hash(passphrase),
        )
        self._save_users(users)
        return {"email": normalized_email, "registered": True}

    def login(self, email: str, passphrase: str) -> dict[str, str]:
        """Verify credentials, update lockout state, and issue a session."""

        try:
            normalized_email = normalize_email(email)
        except MiniVaultError as exc:
            raise MiniVaultError(
                UNAUTHENTICATED,
                INVALID_CREDENTIALS_MESSAGE,
            ) from exc
        if not isinstance(passphrase, str):
            raise MiniVaultError(UNAUTHENTICATED, INVALID_CREDENTIALS_MESSAGE)

        users = self._load_users()
        user = users.get(normalized_email)
        if user is None:
            raise MiniVaultError(UNAUTHENTICATED, INVALID_CREDENTIALS_MESSAGE)

        now = self._now()
        if user.locked_until is not None:
            if now < user.locked_until:
                raise MiniVaultError(ACCOUNT_LOCKED, ACCOUNT_LOCKED_MESSAGE)
            # Exactly at locked_until the five-minute lockout has expired and
            # the new sequence starts from zero.
            user = replace(user, failed_attempts=0, locked_until=None)

        try:
            password_matches = self._password_hasher.verify(
                user.password_hash,
                passphrase,
            )
        except VerificationError:
            password_matches = False

        if not password_matches:
            failed_attempts = user.failed_attempts + 1
            if failed_attempts >= MAX_FAILED_ATTEMPTS:
                user = replace(
                    user,
                    failed_attempts=MAX_FAILED_ATTEMPTS,
                    locked_until=now + ACCOUNT_LOCKOUT_DURATION,
                )
                users[normalized_email] = user
                self._save_users(users)
                raise MiniVaultError(ACCOUNT_LOCKED, ACCOUNT_LOCKED_MESSAGE)

            users[normalized_email] = replace(
                user,
                failed_attempts=failed_attempts,
                locked_until=None,
            )
            self._save_users(users)
            raise MiniVaultError(
                UNAUTHENTICATED,
                INVALID_CREDENTIALS_MESSAGE,
            )

        password_hash = user.password_hash
        if self._password_hasher.check_needs_rehash(password_hash):
            password_hash = self._password_hasher.hash(passphrase)
        users[normalized_email] = replace(
            user,
            password_hash=password_hash,
            failed_attempts=0,
            locked_until=None,
        )
        self._save_users(users)
        return self._create_session(normalized_email, now)

    def validate_session(self, token: str) -> SessionIdentity:
        """Return the token owner or reject a missing, invalid, or expired token."""

        if (
            not isinstance(token, str)
            or not token
            or token.strip() != token
        ):
            raise MiniVaultError(UNAUTHENTICATED, UNAUTHENTICATED_MESSAGE)

        sessions = self._load_sessions()
        token_fingerprint = self._token_fingerprint(token)
        record = sessions.get(token_fingerprint)
        if record is None:
            raise MiniVaultError(UNAUTHENTICATED, UNAUTHENTICATED_MESSAGE)

        now = self._now()
        if now >= record.expires_at:
            del sessions[token_fingerprint]
            self._save_sessions(sessions)
            raise MiniVaultError(UNAUTHENTICATED, UNAUTHENTICATED_MESSAGE)

        # Reject sessions whose user has been removed or whose stored identity
        # was tampered with.
        users = self._load_users()
        if record.email not in users:
            del sessions[token_fingerprint]
            self._save_sessions(sessions)
            raise MiniVaultError(UNAUTHENTICATED, UNAUTHENTICATED_MESSAGE)

        return SessionIdentity(
            email=record.email,
            expires_at=record.expires_at,
        )

    def _create_session(self, email: str, now: datetime) -> dict[str, str]:
        sessions = self._load_sessions()
        self._remove_expired_sessions(sessions, now)

        for _attempt in range(5):
            token = self._token_generator(SESSION_TOKEN_BYTES)
            if not isinstance(token, str) or len(token) < SESSION_TOKEN_BYTES:
                raise RuntimeError("Secure token generator returned invalid output.")
            fingerprint = self._token_fingerprint(token)
            if fingerprint not in sessions:
                break
        else:
            raise RuntimeError("Could not generate a unique session token.")

        expires_at = now + SESSION_LIFETIME
        sessions[fingerprint] = SessionRecord(
            email=email,
            created_at=now,
            expires_at=expires_at,
        )
        self._save_sessions(sessions)
        return {
            "email": email,
            "token": token,
            "expires_at": _format_timestamp(expires_at),
        }

    def _load_users(self) -> dict[str, UserRecord]:
        stored = self._repository.load(self._users_filename)
        if not stored:
            return {}
        if (
            stored.get("version") != AUTH_STORAGE_VERSION
            or not isinstance(stored.get("users"), dict)
        ):
            raise MiniVaultError(STORAGE_ERROR, "User storage schema is invalid.")

        try:
            users = {
                email: UserRecord.from_dict(record)
                for email, record in stored["users"].items()
            }
            if any(
                normalize_email(email) != email
                or normalize_email(record.email) != record.email
                or email != record.email
                for email, record in users.items()
            ):
                raise ValueError("User storage key does not match record email.")
            return users
        except (MiniVaultError, TypeError, ValueError) as exc:
            raise MiniVaultError(
                STORAGE_ERROR,
                "User storage contains an invalid record.",
            ) from exc

    def _save_users(self, users: Mapping[str, UserRecord]) -> None:
        self._repository.save(
            self._users_filename,
            {
                "version": AUTH_STORAGE_VERSION,
                "users": {
                    email: record.to_dict()
                    for email, record in users.items()
                },
            },
        )

    def _load_sessions(self) -> dict[str, SessionRecord]:
        stored = self._repository.load(self._sessions_filename)
        if not stored:
            return {}
        if (
            stored.get("version") != AUTH_STORAGE_VERSION
            or not isinstance(stored.get("sessions"), dict)
        ):
            raise MiniVaultError(
                STORAGE_ERROR,
                "Session storage schema is invalid.",
            )

        try:
            sessions = {
                fingerprint: SessionRecord.from_dict(record)
                for fingerprint, record in stored["sessions"].items()
            }
            if any(
                not isinstance(fingerprint, str)
                or not re.fullmatch(r"[0-9a-f]{64}", fingerprint)
                or normalize_email(record.email) != record.email
                for fingerprint, record in sessions.items()
            ):
                raise ValueError("Session fingerprint is invalid.")
            return sessions
        except (MiniVaultError, TypeError, ValueError) as exc:
            raise MiniVaultError(
                STORAGE_ERROR,
                "Session storage contains an invalid record.",
            ) from exc

    def _save_sessions(self, sessions: Mapping[str, SessionRecord]) -> None:
        self._repository.save(
            self._sessions_filename,
            {
                "version": AUTH_STORAGE_VERSION,
                "sessions": {
                    fingerprint: record.to_dict()
                    for fingerprint, record in sessions.items()
                },
            },
        )

    def _now(self) -> datetime:
        value = self._clock()
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() is None
        ):
            raise RuntimeError("Authentication clock must be timezone-aware.")
        return value.astimezone(timezone.utc)

    @staticmethod
    def _token_fingerprint(token: str) -> str:
        # A fast hash is correct for a uniformly random 256-bit token. Passwords
        # use the deliberately expensive Argon2id function above.
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def _remove_expired_sessions(
        sessions: dict[str, SessionRecord],
        now: datetime,
    ) -> None:
        expired = [
            fingerprint
            for fingerprint, record in sessions.items()
            if now >= record.expires_at
        ]
        for fingerprint in expired:
            del sessions[fingerprint]
