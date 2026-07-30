"""Mini Vault CLI entry point."""

from __future__ import annotations

import argparse
import getpass
import sys
from typing import Sequence

from src.api.app import vault_status
from src.core.vault import Vault
from src.auth.service import AuthService
from src.errors import AlreadyInitializedError, InvalidInputError, UnlockFailedError, VaultError
from src.storage.repository import MetadataRepository, UserRepository


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # noqa: D401 - argparse override
        # Stable public code only — no argparse help text (may echo bad args).
        print("INVALID_INPUT")
        raise SystemExit(2)


def _build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(prog="mini-vault", add_help=True)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("init")
    subparsers.add_parser("unlock")
    subparsers.add_parser("status")
    subparsers.add_parser("register")
    subparsers.add_parser("login")
    serve = subparsers.add_parser("serve", help="Run Feature 0.1 REST API (long-lived process)")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    vault = Vault(MetadataRepository())
    auth = AuthService(UserRepository())

    try:
        if args.command == "status":
            print(vault_status(vault))
            return 0

        if args.command == "init":
            passphrase = getpass.getpass("Master Passphrase: ")
            vault.initialize(passphrase)
            print("initialized")
            print("locked")
            return 0

        if args.command == "unlock":
            passphrase = getpass.getpass("Master Passphrase: ")
            vault.unlock(passphrase)
            print("unlocked")
            return 0

        if args.command == "register":
            email = input("Email: ")
            passphrase = getpass.getpass("Passphrase: ")
            confirmation = getpass.getpass("Confirm Passphrase: ")
            auth.register(email, passphrase, confirmation)
            print("registered")
            return 0

        if args.command == "login":
            email = input("Email: ")
            passphrase = getpass.getpass("Passphrase: ")
            print(auth.login(email, passphrase))
            return 0

        if args.command == "serve":
            import uvicorn

            from src.api.app import create_app

            # One Vault + one AuthService for the whole server process.
            # Unlock and session tokens persist across HTTP calls until restart.
            uvicorn.run(
                create_app(vault=vault, auth=auth),
                host=args.host,
                port=args.port,
                log_level="info",
            )
            return 0
    except (InvalidInputError, AlreadyInitializedError, UnlockFailedError, VaultError) as exc:
        print(exc.code)
        return 1


    print("INVALID_INPUT")
    return 1


if __name__ == "__main__":
    sys.exit(main())
