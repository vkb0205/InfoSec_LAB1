"""Public domain errors for Mini Vault."""

INVALID_INPUT = "INVALID_INPUT"
ALREADY_INITIALIZED = "ALREADY_INITIALIZED"
UNLOCK_FAILED = "UNLOCK_FAILED"
VAULT_LOCKED = "VAULT_LOCKED"
DUPLICATE_USER = "DUPLICATE_USER"
INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
UNAUTHENTICATED = "UNAUTHENTICATED"
DUPLICATE_KEY = "DUPLICATE_KEY"
KEY_NOT_FOUND = "KEY_NOT_FOUND"


class VaultError(Exception):
    """Base error exposing only a stable public code."""

    code = "VAULT_ERROR"

    def __init__(self) -> None:
        super().__init__(self.code)


class InvalidInputError(VaultError):
    code = INVALID_INPUT


class AlreadyInitializedError(VaultError):
    code = ALREADY_INITIALIZED


class UnlockFailedError(VaultError):
    code = UNLOCK_FAILED


class VaultLockedError(VaultError):
    code = VAULT_LOCKED


class DuplicateUserError(VaultError):
    code = DUPLICATE_USER


class InvalidCredentialsError(VaultError):
    code = INVALID_CREDENTIALS


class AccountLockedError(VaultError):
    code = ACCOUNT_LOCKED


class UnauthenticatedError(VaultError):
    code = UNAUTHENTICATED


class DuplicateKeyError(VaultError):
    code = DUPLICATE_KEY


class KeyNotFoundError(VaultError):
    code = KEY_NOT_FOUND
