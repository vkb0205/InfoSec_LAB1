"""FastAPI surface for Feature 0.1 (vault) and 0.2 (auth).

Long-lived process holds:
- one Vault — unlock survives across HTTP calls until server restart
- one AuthService — session tokens live in RAM until expiry or restart
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from src.auth.service import AuthService
from src.core.vault import Vault
from src.errors import (
    AccountLockedError,
    AlreadyInitializedError,
    DuplicateUserError,
    InvalidCredentialsError,
    InvalidInputError,
    UnauthenticatedError,
    UnlockFailedError,
    VaultError,
    VaultLockedError,
)
from src.storage.repository import MetadataRepository, UserRepository

# Public error → HTTP status (body always {"code": "..."} only)
_ERROR_HTTP_STATUS: dict[type[VaultError], int] = {
    InvalidInputError: 400,
    AlreadyInitializedError: 409,
    DuplicateUserError: 409,
    UnlockFailedError: 401,
    InvalidCredentialsError: 401,
    UnauthenticatedError: 401,
    AccountLockedError: 403,
    VaultLockedError: 403,
}


class PassphraseBody(BaseModel):
    """Master passphrase in JSON body — never query string or path."""

    passphrase: str = Field(min_length=1)


class RegisterBody(BaseModel):
    email: str = Field(min_length=1)
    passphrase: str = Field(min_length=1)
    confirmation: str = Field(min_length=1)


class LoginBody(BaseModel):
    email: str = Field(min_length=1)
    passphrase: str = Field(min_length=1)


def vault_status(vault: Vault) -> str:
    """Same three states as CLI `status`."""
    if not vault.is_initialized():
        return "uninitialized"
    if vault.is_locked():
        return "locked"
    return "unlocked"


def create_app(
    *,
    vault: Vault | None = None,
    auth: AuthService | None = None,
    metadata_path: str | os.PathLike[str] | Path | None = None,
    users_path: str | os.PathLike[str] | Path | None = None,
) -> FastAPI:
    """Build API app.

    Pass `vault` / `auth` or path overrides in tests for isolation.
    """
    if vault is None:
        repo = MetadataRepository(metadata_path) if metadata_path is not None else MetadataRepository()
        vault = Vault(repo)
    if auth is None:
        user_repo = UserRepository(users_path) if users_path is not None else UserRepository()
        auth = AuthService(user_repo)

    app = FastAPI(title="Mini Vault", version="0.2.0")
    app.state.vault = vault
    app.state.auth = auth

    @app.exception_handler(VaultError)
    async def _vault_error_handler(_request: Request, exc: VaultError) -> JSONResponse:
        status = _ERROR_HTTP_STATUS.get(type(exc), 400)
        return JSONResponse(status_code=status, content={"code": exc.code})

    # ----- Feature 0.1: vault -----

    @app.get("/v1/status")
    def get_status(request: Request) -> dict[str, str]:
        v: Vault = request.app.state.vault
        return {"status": vault_status(v)}

    @app.post("/v1/init")
    def post_init(body: PassphraseBody, request: Request) -> dict[str, str]:
        v: Vault = request.app.state.vault
        v.initialize(body.passphrase)
        return {"result": "initialized", "status": "locked"}

    @app.post("/v1/unlock")
    def post_unlock(body: PassphraseBody, request: Request) -> dict[str, str]:
        v: Vault = request.app.state.vault
        v.unlock(body.passphrase)
        return {"status": "unlocked"}

    # ----- Feature 0.2: auth -----

    @app.post("/v1/auth/register")
    def post_register(body: RegisterBody, request: Request) -> dict[str, str]:
        a: AuthService = request.app.state.auth
        a.register(body.email, body.passphrase, body.confirmation)
        return {"result": "registered"}

    @app.post("/v1/auth/login")
    def post_login(body: LoginBody, request: Request) -> dict[str, str]:
        a: AuthService = request.app.state.auth
        token = a.login(body.email, body.passphrase)
        return {"token": token}

    @app.get("/v1/auth/session")
    def get_session(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, str]:
        """Validate Bearer token; return canonical email. Sessions are RAM-only."""
        a: AuthService = request.app.state.auth
        token = _bearer_token(authorization)
        email = a.validate_session(token)
        return {"email": email}

    return app


def _bearer_token(authorization: str | None) -> str:
    if not authorization or not isinstance(authorization, str):
        raise UnauthenticatedError()
    parts = authorization.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise UnauthenticatedError()
    return parts[1].strip()


def app_from_env() -> FastAPI:
    """ASGI entry for uvicorn: `uvicorn src.api.app:app`."""
    return create_app()


# Default module-level app for `uvicorn src.api.app:app`
app = create_app()
