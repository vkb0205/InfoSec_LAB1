"""Mini Vault command-line entry point.

Day 1 provides a runnable shell and publishes the interfaces planned for later
days.  Security-sensitive commands are added only when their implementations
and tests exist.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from typing import Any

from src.errors import MiniVaultError


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
    """Build the Day 1 CLI without performing any application work."""

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
    return parser


def _health(_args: argparse.Namespace) -> dict[str, str]:
    return {
        "status": "healthy",
        "service": "Mini Vault",
        "storage_backend": "json",
        "implementation_stage": "person-1-day-1",
    }


def _interfaces(_args: argparse.Namespace) -> dict[str, Any]:
    return {"interfaces": INTERFACE_CONTRACTS}


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""

    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "handler"):
        parser.print_help()
        return 0

    try:
        result = args.handler(args)
    except MiniVaultError as exc:
        print(json.dumps(exc.to_dict()), file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
