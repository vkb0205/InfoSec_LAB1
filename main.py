"""Mini Vault CLI entry point."""

from __future__ import annotations

import argparse
import getpass
import sys
from typing import Sequence

from src.core.vault import Vault
from src.auth.service import AuthService
from src.errors import AlreadyInitializedError, InvalidInputError, UnlockFailedError, VaultError
from src.storage.repository import MetadataRepository, UserRepository


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # noqa: D401 - argparse override
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
    return parser


def _status(vault: Vault) -> str:
    if not vault.is_initialized():
        return "uninitialized"
    if vault.is_locked():
        return "locked"
    return "unlocked"


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    vault = Vault(MetadataRepository())
    auth = AuthService(UserRepository())

    try:
        if args.command == "status":
            print(_status(vault))
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
    except (InvalidInputError, AlreadyInitializedError, UnlockFailedError, VaultError) as exc:
        print(exc.code)
        return 1

    print("INVALID_INPUT")
    return 1


if __name__ == "__main__":
    sys.exit(main())
