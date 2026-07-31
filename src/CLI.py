"""Interactive CLI entrypoint for the InfoSec Lab 1 vault project."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import main as main_module
from main import main as _main
import getpass
import base64
import src.auth.service as auth_module
import src.core.vault as vault_module
import src.storage.repository as repository_module
import src.transit.service as transit_module

MetadataRepository = repository_module.MetadataRepository
UserRepository = repository_module.UserRepository
TransitKeyRepository = repository_module.TransitKeyRepository
Vault = vault_module.Vault
AuthService = auth_module.AuthService
TransitService = transit_module.TransitService


def _run_command(command: str) -> int:
    return _main([command])


def _resolve_factory(name: str):
    local = globals().get(name)
    fallback = getattr(main_module, name, None)
    imported_origin = getattr(repository_module, name, None)
    if local is not None and local is not imported_origin:
        return local
    if fallback is not None and fallback is not imported_origin:
        return fallback
    return local or fallback


def _build_services() -> tuple[Vault, AuthService, TransitService, dict[str, str | None]]:
    metadata_factory = _resolve_factory("MetadataRepository")
    user_factory = _resolve_factory("UserRepository")
    transit_key_factory = _resolve_factory("TransitKeyRepository")
    vault_cls = _resolve_factory("Vault")
    auth_cls = _resolve_factory("AuthService")
    transit_cls = _resolve_factory("TransitService")

    vault = vault_cls(metadata_factory())
    auth = auth_cls(user_factory())
    transit = transit_cls(
        vault,
        auth_validator=auth.validate_session,
        repository=transit_key_factory(),
    )
    return vault, auth, transit, {"token": None}


def _run_interactive_action(choice: str, session: tuple[Vault, AuthService, TransitService, dict[str, str | None]]) -> None:
    vault, auth, transit, state = session
    if choice == "1":
        passphrase = getpass.getpass("Master Passphrase: ")
        vault.initialize(passphrase)
        print("initialized")
        print("locked")
        return

    if choice == "2":
        passphrase = getpass.getpass("Master Passphrase: ")
        vault.unlock(passphrase)
        print("unlocked")
        return

    if choice == "3":
        if not vault.is_initialized():
            print("uninitialized")
        elif vault.is_locked():
            print("locked")
        else:
            print("unlocked")
        return

    if choice == "4":
        email = input("Email: ").strip()
        passphrase = getpass.getpass("Passphrase: ")
        confirmation = getpass.getpass("Confirm Passphrase: ")
        auth.register(email, passphrase, confirmation)
        print("registered")
        return

    if choice == "5":
        email = input("Email: ").strip()
        passphrase = getpass.getpass("Passphrase: ")
        try:
            token = auth.login(email, passphrase)
            state["token"] = token
            print(token)
        except Exception as exc:
            state["token"] = None
            print(exc)
        return

    if choice == "6":
        if not vault.is_initialized():
            print("Vault is not initialized yet. Please initialize first.")
            return
        if vault.is_locked():
            print("Vault is locked. Please unlock first.")
            return

        token = state.get("token")
        if not token:
            email = input("Email: ").strip()
            passphrase = getpass.getpass("Passphrase: ")
            token = auth.login(email, passphrase)
            state["token"] = token

        key_name = input("Key name: ").strip()
        try:
            transit.create_key(token, key_name)
        except Exception:
            pass
        plaintext = input("Plaintext: ").strip()
        plaintext_b64 = base64.b64encode(plaintext.encode("utf-8")).decode("ascii")
        ciphertext = transit.encrypt(token, key_name, plaintext_b64)
        print(f"ciphertext: {ciphertext}")
        return


def _interactive_menu() -> int:
    session = _build_services()
    while True:
        print("\n=== InfoSec Lab 1 Vault CLI ===")
        print("1. Initialize vault")
        print("2. Unlock vault")
        print("3. Check status")
        print("4. Register user")
        print("5. Login")
        print("6. Encrypt data")
        print("0. Exit")

        choice = input("Choose an option: ").strip()
        print()

        if choice == "0":
            print("Goodbye!")
            return 0

        if choice in {"1", "2", "3", "4", "5", "6"}:
            if choice in {"1", "2"}:
                print("Master passphrase must be at least 12 characters long and include uppercase, lowercase, a number, and a symbol.")
            try:
                _run_interactive_action(choice, session)
            except Exception as exc:
                print(f"Action failed: {exc}")
            print("-" * 40)
            continue

        print("Invalid choice. Please try again.")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the interactive menu when no command is provided."""
    if argv is not None:
        args = list(argv)
    else:
        args = list(sys.argv[1:])

    if not args:
        return _interactive_menu()

    if args[0] in {"init", "unlock", "status", "register", "login"} or args[0] in {"-h", "--help"}:
        return _main(args)

    return _interactive_menu()


if __name__ == "__main__":
    sys.exit(main())