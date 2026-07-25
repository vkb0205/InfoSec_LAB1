"""Authentication service and identity contract."""

from src.auth.service import (
    ACCOUNT_LOCKOUT_DURATION,
    SESSION_LIFETIME,
    AuthService,
    SessionIdentity,
    normalize_email,
    validate_user_passphrase,
)

__all__ = [
    "ACCOUNT_LOCKOUT_DURATION",
    "SESSION_LIFETIME",
    "AuthService",
    "SessionIdentity",
    "normalize_email",
    "validate_user_passphrase",
]
