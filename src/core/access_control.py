"""Shared request ordering and ownership authorization for feature services."""

from __future__ import annotations

import secrets

from src.auth.service import AuthService, SessionIdentity, normalize_email
from src.core.vault import Vault
from src.errors import PERMISSION_DENIED, MiniVaultError
from src.storage.audit_log import AccessDeniedLogger


PERMISSION_DENIED_MESSAGE = "Permission denied."


class RequestGuard:
    """Enforce vault, authentication, ownership, and audit ordering.

    KV and Transit should depend on this class instead of independently
    reimplementing security checks with inconsistent ordering.
    """

    def __init__(
        self,
        vault: Vault,
        auth: AuthService,
        audit_logger: AccessDeniedLogger,
    ) -> None:
        self._vault = vault
        self._auth = auth
        self._audit_logger = audit_logger

    def authenticate(self, token: str) -> SessionIdentity:
        """Require an unlocked vault, then validate the session token."""

        self._vault.require_unlocked()
        return self._auth.validate_session(token)

    def require_owner(
        self,
        identity: SessionIdentity,
        owner_email: str,
        *,
        operation: str,
        resource_type: str,
        resource_id: str,
    ) -> None:
        """Deny and audit a valid user attempting cross-owner access."""

        normalized_owner = normalize_email(owner_email)
        if secrets.compare_digest(
            identity.email.encode("utf-8"),
            normalized_owner.encode("utf-8"),
        ):
            return

        self._audit_logger.log_access_denied(
            requester_email=identity.email,
            operation=operation,
            resource_type=resource_type,
            resource_id=resource_id,
        )
        raise MiniVaultError(
            PERMISSION_DENIED,
            PERMISSION_DENIED_MESSAGE,
        )

    def authorize_owner(
        self,
        token: str,
        owner_email: str,
        *,
        operation: str,
        resource_type: str,
        resource_id: str,
    ) -> SessionIdentity:
        """Run the complete guard sequence and return the valid identity."""

        identity = self.authenticate(token)
        self.require_owner(
            identity,
            owner_email,
            operation=operation,
            resource_type=resource_type,
            resource_id=resource_id,
        )
        return identity
