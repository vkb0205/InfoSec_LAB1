"""Shared, transport-independent errors for Mini Vault.

Services raise :class:`MiniVaultError`; the CLI (and a future REST adapter) is
responsible for converting it into an appropriate response.  Keeping HTTP
details out of this module prevents the core and service layers from depending
on a particular user interface.
"""

from __future__ import annotations

from dataclasses import dataclass


VAULT_LOCKED = "VAULT_LOCKED"
UNAUTHENTICATED = "UNAUTHENTICATED"
PERMISSION_DENIED = "PERMISSION_DENIED"
NOT_FOUND = "NOT_FOUND"
INVALID_KEY_USAGE = "INVALID_KEY_USAGE"

# Supporting errors used by later implementation days.
INVALID_INPUT = "INVALID_INPUT"
DUPLICATE_KEY = "DUPLICATE_KEY"
UNLOCK_FAILED = "UNLOCK_FAILED"
STORAGE_ERROR = "STORAGE_ERROR"
ALREADY_INITIALIZED = "ALREADY_INITIALIZED"
NOT_INITIALIZED = "NOT_INITIALIZED"

REQUIRED_ERROR_CODES = frozenset(
    {
        VAULT_LOCKED,
        UNAUTHENTICATED,
        PERMISSION_DENIED,
        NOT_FOUND,
        INVALID_KEY_USAGE,
    }
)


@dataclass(eq=False)
class MiniVaultError(Exception):
    """An expected application error safe to translate at the system boundary."""

    code: str
    message: str

    def __post_init__(self) -> None:
        super().__init__(self.message)

    def to_dict(self) -> dict[str, str]:
        """Return the stable error response shared by CLI and future adapters."""

        return {"error_code": self.code, "message": self.message}
