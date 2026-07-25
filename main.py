"""Mini Vault command-line entry point."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import secrets
import sys
from collections.abc import Sequence
from typing import Any

from dotenv import load_dotenv

from src.core.vault import Vault
from src.errors import INVALID_INPUT, MiniVaultError
from src.storage.repository import VAULT_METADATA_FILE, JsonRepository


INTERFACE_CONTRACTS = {
    "core": ["initialize(master_passphrase)", "unlock(master_passphrase)"],
    "auth": [
        "register(email, passphrase, confirm_passphrase)",
        "login(email, passphrase)",
        "validate_session(token)",
    ],
    "kv": [
        "write(path, data, token)",
        "read(path, token)",
        "delete(path, token)",
    ],
    "transit": [
        "create_key(key_name, token)",
        "list_keys(token)",
        "revoke_key(key_name, token)",
        "encrypt(key_name, plaintext_b64, token)",
        "decrypt(ciphertext, token)",
        "create_signing_key(key_name, signing_algorithm, token)",
        "sign(key_name, message_b64, message_type, token)",
        "verify(key_name, message_b64, message_type, signature_b64, token)",
    ],
}


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI without placing passphrases in command arguments."""

    parser = argparse.ArgumentParser(
        prog="mini-vault",
        description="Secure secret storage and cryptography service",
    )
    subparsers = parser.add_subparsers(dest="command")

    health_parser = subparsers.add_parser(
        "health",
        help="check whether the CLI skeleton is runnable",
    )
    health_parser.set_defaults(handler=_health)

    contracts_parser = subparsers.add_parser(
        "interfaces",
        help="show the service interfaces agreed for later implementation days",
    )
    contracts_parser.set_defaults(handler=_interfaces)

    status_parser = subparsers.add_parser(
        "status",
        help="show whether the vault is initialized and locked",
    )
    status_parser.set_defaults(handler=_status)

    init_parser = subparsers.add_parser(
        "init",
        help="initialize a new vault and prompt securely for its passphrase",
    )
    init_parser.set_defaults(handler=_initialize)

    unlock_parser = subparsers.add_parser(
        "unlock",
        help="unlock the vault for the lifetime of this CLI process",
    )
    unlock_parser.set_defaults(handler=_unlock)

    lock_parser = subparsers.add_parser(
        "lock",
        help="remove the DEK from this CLI process",
    )
    lock_parser.set_defaults(handler=_lock)
    return parser


def _health(_args: argparse.Namespace, vault: Vault) -> dict[str, Any]:
    return {
        "status": "healthy",
        "service": "Mini Vault",
        "storage_backend": "json",
        "implementation_stage": "person-1-day-2",
        "vault": vault.public_status(),
    }


def _interfaces(_args: argparse.Namespace, _vault: Vault) -> dict[str, Any]:
    return {"interfaces": INTERFACE_CONTRACTS}


def _status(_args: argparse.Namespace, vault: Vault) -> dict[str, bool | str]:
    return vault.public_status()


def _initialize(
    _args: argparse.Namespace,
    vault: Vault,
) -> dict[str, bool | str]:
    passphrase = getpass.getpass("New Master Passphrase: ")
    confirmation = getpass.getpass("Confirm Master Passphrase: ")
    if not secrets.compare_digest(
        passphrase.encode("utf-8"),
        confirmation.encode("utf-8"),
    ):
        raise MiniVaultError(INVALID_INPUT, "Master passphrases do not match.")
    return vault.initialize(passphrase)


def _unlock(_args: argparse.Namespace, vault: Vault) -> dict[str, bool | str]:
    passphrase = getpass.getpass("Master Passphrase: ")
    return vault.unlock(passphrase)


def _lock(_args: argparse.Namespace, vault: Vault) -> dict[str, bool | str]:
    return vault.lock()


def _default_vault() -> Vault:
    load_dotenv()
    data_dir = os.getenv("MINI_VAULT_DATA_DIR", "data")
    metadata_filename = os.getenv(
        "MINI_VAULT_VAULT_FILE",
        VAULT_METADATA_FILE,
    )
    return Vault(
        JsonRepository(data_dir),
        metadata_filename=metadata_filename,
    )


def main(
    argv: Sequence[str] | None = None,
    *,
    vault: Vault | None = None,
) -> int:
    """Run the CLI and return a process exit code."""

    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "handler"):
        parser.print_help()
        return 0

    try:
        result = args.handler(args, vault or _default_vault())
    except MiniVaultError as exc:
        print(json.dumps(exc.to_dict()), file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
