"""Registration, Argon2 verification, process-local sessions, and lockout policy."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re
import secrets
from typing import Callable

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from src.crypto_utils import validate_master_passphrase
from src.errors import AccountLockedError, InvalidCredentialsError, InvalidInputError, UnauthenticatedError
from src.storage.repository import UserRepository

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
SESSION_LIFETIME = timedelta(minutes=30)
LOCKOUT_LIFETIME = timedelta(minutes=5)


class AuthService:
    def __init__(self, repository: UserRepository, *, clock: Callable[[], datetime] | None = None,
                 token_factory: Callable[[], str] | None = None, password_hasher: PasswordHasher | None = None) -> None:
        self._repository = repository
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._token_factory = token_factory or (lambda: secrets.token_urlsafe(32))
        self._hasher = password_hasher or PasswordHasher()
        self._sessions: dict[str, tuple[str, datetime]] = {}

    @staticmethod
    def canonical_email(email: str) -> str:
        if not isinstance(email, str):
            raise InvalidInputError()
        canonical = email.strip().casefold()
        if not EMAIL_RE.fullmatch(canonical):
            raise InvalidInputError()
        return canonical

    def register(self, email: str, passphrase: str, confirmation: str) -> None:
        canonical = self.canonical_email(email)
        if not isinstance(confirmation, str) or passphrase != confirmation:
            raise InvalidInputError()
        validate_master_passphrase(passphrase)
        self._repository.create_account({"email": canonical, "password_hash": self._hasher.hash(passphrase), "failed_attempts": 0, "locked_until": None})

    def login(self, email: str, passphrase: str) -> str:
        canonical = self.canonical_email(email)
        if not isinstance(passphrase, str):
            raise InvalidInputError()
        account = self._repository.read()["users"].get(canonical)
        if account is None:
            raise InvalidCredentialsError()
        now = self._now()
        locked_until = self._parse_time(account["locked_until"])
        if locked_until is not None and now < locked_until:
            raise AccountLockedError()
        try:
            verified = self._hasher.verify(account["password_hash"], passphrase)
        except (VerificationError, InvalidHashError):
            verified = False
        if not verified:
            failures = account["failed_attempts"] + 1
            account["failed_attempts"] = failures
            account["locked_until"] = self._format_time(now + LOCKOUT_LIFETIME) if failures >= 5 else None
            self._repository.replace_account(account)
            raise InvalidCredentialsError()
        account["failed_attempts"] = 0
        account["locked_until"] = None
        self._repository.replace_account(account)
        token = self._token_factory()
        if not isinstance(token, str) or not token:
            raise InvalidInputError()
        self._sessions[token] = (canonical, now + SESSION_LIFETIME)
        return token

    def validate_session(self, token: str) -> str:
        if not isinstance(token, str) or not token or token not in self._sessions:
            raise UnauthenticatedError()
        email, expires_at = self._sessions[token]
        if self._now() >= expires_at:
            del self._sessions[token]
            raise UnauthenticatedError()
        return email

    def _now(self) -> datetime:
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise InvalidInputError()
        return now.astimezone(timezone.utc)

    @staticmethod
    def _format_time(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat()

    @staticmethod
    def _parse_time(value: str | None) -> datetime | None:
        if value is None:
            return None
        try:
            parsed = datetime.fromisoformat(value)
        except (TypeError, ValueError) as exc:
            raise InvalidCredentialsError() from exc
        if parsed.tzinfo is None:
            raise InvalidCredentialsError()
        return parsed.astimezone(timezone.utc)
