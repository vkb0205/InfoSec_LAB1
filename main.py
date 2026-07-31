"""Mini Vault CLI entry point."""

from __future__ import annotations

import argparse
import base64
import getpass
import sys
from typing import Sequence

from src.api.app import vault_status
from src.core.vault import Vault
from src.auth.service import AuthService
from src.errors import AlreadyInitializedError, InvalidInputError, UnlockFailedError, VaultError
from src.kv.crypto_utils import CryptoEngine
from src.kv.kv_engine import KVEngine
from src.kv.storage import KVFileStorage
from src.storage.repository import MetadataRepository, TransitKeyRepository, UserRepository
from src.transit.service import TransitService


class _AuthTokenValidator:
    def __init__(self, auth_service: AuthService) -> None:
        self._auth_service = auth_service

    def verify_token(self, token: str) -> str:
        return self._auth_service.validate_session(token)


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
    subparsers.add_parser("interactive")
    serve_parser = subparsers.add_parser("serve")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8000)

    kv_parser = subparsers.add_parser("kv")
    kv_sub = kv_parser.add_subparsers(dest="kv_command", required=True)
    write_parser = kv_sub.add_parser("write")
    write_parser.add_argument("--token", default=None)
    write_parser.add_argument("--path", default=None)
    write_parser.add_argument("--secret", default=None)
    read_parser = kv_sub.add_parser("read")
    read_parser.add_argument("--token", default=None)
    read_parser.add_argument("--path", default=None)
    delete_parser = kv_sub.add_parser("delete")
    delete_parser.add_argument("--token", default=None)
    delete_parser.add_argument("--path", default=None)

    transit_parser = subparsers.add_parser("transit")
    transit_sub = transit_parser.add_subparsers(dest="transit_command", required=True)
    create_key_parser = transit_sub.add_parser("create-key")
    create_key_parser.add_argument("--token", default=None)
    create_key_parser.add_argument("--key-name", default=None)
    encrypt_parser = transit_sub.add_parser("encrypt")
    encrypt_parser.add_argument("--token", default=None)
    encrypt_parser.add_argument("--key-name", default=None)
    encrypt_parser.add_argument("--plaintext", default=None)
    decrypt_parser = transit_sub.add_parser("decrypt")
    decrypt_parser.add_argument("--token", default=None)
    decrypt_parser.add_argument("--ciphertext", default=None)
    create_signing_key_parser = transit_sub.add_parser("create-signing-key")
    create_signing_key_parser.add_argument("--token", default=None)
    create_signing_key_parser.add_argument("--key-name", default=None)
    sign_parser = transit_sub.add_parser("sign")
    sign_parser.add_argument("--token", default=None)
    sign_parser.add_argument("--key-name", default=None)
    sign_parser.add_argument("--message", default=None)
    verify_parser = transit_sub.add_parser("verify")
    verify_parser.add_argument("--token", default=None)
    verify_parser.add_argument("--key-name", default=None)
    verify_parser.add_argument("--message", default=None)
    verify_parser.add_argument("--signature", default=None)
    list_keys_parser = transit_sub.add_parser("list-keys")
    list_keys_parser.add_argument("--token", default=None)
    revoke_key_parser = transit_sub.add_parser("revoke-key")
    revoke_key_parser.add_argument("--token", default=None)
    revoke_key_parser.add_argument("--key-name", default=None)
    rotate_key_parser = transit_sub.add_parser("rotate-key")
    rotate_key_parser.add_argument("--token", default=None)
    rotate_key_parser.add_argument("--key-name", default=None)

    return parser


def _status(vault: Vault) -> str:
    if not vault.is_initialized():
        return "uninitialized"
    if vault.is_locked():
        return "locked"
    return "unlocked"


def _prompt_token() -> str:
    return input("Token: ").strip()


def _prompt_text(prompt_text: str, default: str | None = None) -> str:
    if default is None:
        return input(f"{prompt_text}: ").strip()
    value = input(f"{prompt_text} [{default}]: ").strip()
    return value if value else default


def _run_interactive(vault: Vault, auth: AuthService) -> int:
    transit = TransitService(vault, auth.validate_session, TransitKeyRepository())
    kv_store = KVFileStorage()
    kv_engine = None
    token: str | None = None
    current_email: str | None = None

    def ensure_unlocked() -> bool:
        if vault.is_locked():
            print("VAULT_LOCKED")
            return False
        return True

    def ensure_session() -> bool:
        nonlocal token, current_email
        if token is None:
            print("No active session token. Please login first.")
            return False
        try:
            auth.validate_session(token)
            return True
        except VaultError as exc:
            print(exc.code)
            token = None
            current_email = None
            return False

    while True:
        print("\nMini Vault Interactive Menu")
        print("1) status")
        print("2) init")
        print("3) unlock")
        print("4) register")
        print("5) login")
        print("6) kv write")
        print("7) kv read")
        print("8) kv delete")
        print("9) transit create-key")
        print("10) transit encrypt")
        print("11) transit decrypt")
        print("12) transit create-signing-key")
        print("13) transit sign")
        print("14) transit verify")
        print("15) transit list-keys")
        print("16) transit revoke-key")
        print("17) transit rotate-key (bonus)")
        print("0) exit")
        
        if current_email:
            prompt = f"\n{current_email}@mini-vault:/secret/{current_email}/data$ "
        else:
            prompt = "\nmini-vault> "
            
        choice = input(prompt).strip()

        try:
            if choice == "0":
                return 0

            if choice == "1":
                print(_status(vault))
                continue

            if choice == "2":
                if vault.is_initialized():
                    print("ALREADY_INITIALIZED")
                    continue
                passphrase = _prompt_text("Master Passphrase")
                vault.initialize(passphrase)
                print("initialized")
                continue

            if choice == "3":
                passphrase = _prompt_text("Master Passphrase")
                vault.unlock(passphrase)
                print("unlocked")
                continue

            if choice == "4":
                email = _prompt_text("Email")
                passphrase = _prompt_text("Passphrase")
                confirmation = _prompt_text("Confirm Passphrase")
                auth.register(email, passphrase, confirmation)
                print("registered")
                continue

            if choice == "5":
                email = _prompt_text("Email")
                passphrase = _prompt_text("Passphrase")
                token = auth.login(email, passphrase)
                current_email = email
                print(f"Logged in. Token: {token}")
                continue

            if choice == "6":
                if not ensure_unlocked() or not ensure_session():
                    continue
                path = f"secret/{current_email}/data" 
                print(f"[KV Write] Auto-path: {path}")
                value = _prompt_text("Secret value")
                kv_engine = KVEngine(CryptoEngine(vault.get_dek()), kv_store, _AuthTokenValidator(auth))
                result = kv_engine.write(path, value, token)
                print(result)
                continue

            if choice == "7":
                if not ensure_unlocked() or not ensure_session():
                    continue
                path = f"secret/{current_email}/data"
                print(f"[KV Read] Auto-path: {path}")
                kv_engine = KVEngine(CryptoEngine(vault.get_dek()), kv_store, _AuthTokenValidator(auth))
                print(kv_engine.read(path, token))
                continue

            if choice == "8":
                if not ensure_unlocked() or not ensure_session():
                    continue
                path = f"secret/{current_email}/data"
                print(f"[KV Delete] Auto-path: {path}")
                kv_engine = KVEngine(CryptoEngine(vault.get_dek()), kv_store, _AuthTokenValidator(auth))
                print(kv_engine.delete(path, token))
                continue

            if choice == "9":
                if not ensure_unlocked() or not ensure_session():
                    continue
                key_name = _prompt_text("Transit key name")
                print(transit.create_key(token, key_name))
                continue

            if choice == "10":
                if not ensure_unlocked() or not ensure_session():
                    continue
                key_name = _prompt_text("Transit key name")
                plaintext = _prompt_text("Plaintext")
                print(transit.encrypt(token, key_name, base64.b64encode(plaintext.encode("utf-8")).decode("utf-8")))
                continue

            if choice == "11":
                if not ensure_unlocked() or not ensure_session():
                    continue
                ciphertext = _prompt_text("Ciphertext")
                print(transit.decrypt(token, ciphertext))
                continue

            if choice == "12":
                if not ensure_unlocked() or not ensure_session():
                    continue
                key_name = _prompt_text("Signing key name")
                print(transit.create_signing_key(token, key_name))
                continue

            if choice == "13":
                if not ensure_unlocked() or not ensure_session():
                    continue
                key_name = _prompt_text("Signing key name")
                message = _prompt_text("Message to sign")
                print(transit.sign(token, key_name, base64.b64encode(message.encode("utf-8")).decode("utf-8")))
                continue

            if choice == "14":
                if not ensure_unlocked() or not ensure_session():
                    continue
                key_name = _prompt_text("Signing key name")
                message = _prompt_text("Message")
                signature = _prompt_text("Signature")
                print(transit.verify(token, key_name, base64.b64encode(message.encode("utf-8")).decode("utf-8"), signature))
                continue

            if choice == "15":
                if not ensure_unlocked() or not ensure_session():
                    continue
                print(transit.list_keys(token))
                continue

            if choice == "16":
                if not ensure_unlocked() or not ensure_session():
                    continue
                key_name = _prompt_text("Transit key name to revoke")
                print(transit.revoke_key(token, key_name))
                continue

            if choice == "17":
                if not ensure_unlocked() or not ensure_session():
                    continue
                key_name = _prompt_text("Transit key name to rotate")
                print(transit.rotate_key(token, key_name))
                continue

            print("INVALID_INPUT")
        except (InvalidInputError, AlreadyInitializedError, UnlockFailedError, VaultError) as exc:
            print(exc.code)
        except PermissionError as exc:
            print(str(exc))
        except Exception as exc:
            print("ERROR", str(exc))

    return 0


def _create_kv_engine(vault: Vault, auth: AuthService) -> KVEngine:
    return KVEngine(CryptoEngine(vault.get_dek()), KVFileStorage(), _AuthTokenValidator(auth))


def _get_required_value(name: str, value: str | None) -> str:
    if not isinstance(value, str) or not value:
        raise InvalidInputError()
    return value


def _run_kv_command(args: argparse.Namespace, vault: Vault, auth: AuthService) -> int:
    if vault.is_locked():
        print("VAULT_LOCKED")
        return 1
    token = _get_required_value("token", args.token)
    path = _get_required_value("path", args.path)
    kv_engine = _create_kv_engine(vault, auth)

    try:
        if args.kv_command == "write":
            secret = _get_required_value("secret", args.secret)
            print(kv_engine.write(path, secret, token))
            return 0
        if args.kv_command == "read":
            print(kv_engine.read(path, token))
            return 0
        if args.kv_command == "delete":
            print(kv_engine.delete(path, token))
            return 0
    except PermissionError as exc:
        print(str(exc))
        return 1
    except (InvalidInputError, VaultError) as exc:
        print(exc.code)
        return 1
    except Exception as exc:
        print("ERROR", str(exc))
        return 1


def _run_transit_command(args: argparse.Namespace, vault: Vault, auth: AuthService) -> int:
    if vault.is_locked():
        print("VAULT_LOCKED")
        return 1
    token = _get_required_value("token", args.token)
    transit = TransitService(vault, auth.validate_session, TransitKeyRepository())

    try:
        if args.transit_command == "create-key":
            key_name = _get_required_value("key-name", args.key_name)
            print(transit.create_key(token, key_name))
            return 0
        if args.transit_command == "encrypt":
            key_name = _get_required_value("key-name", args.key_name)
            plaintext = _get_required_value("plaintext", args.plaintext)
            print(transit.encrypt(token, key_name, base64.b64encode(plaintext.encode("utf-8")).decode("utf-8")))
            return 0
        if args.transit_command == "decrypt":
            ciphertext = _get_required_value("ciphertext", args.ciphertext)
            print(transit.decrypt(token, ciphertext))
            return 0
        if args.transit_command == "create-signing-key":
            key_name = _get_required_value("key-name", args.key_name)
            print(transit.create_signing_key(token, key_name))
            return 0
        if args.transit_command == "sign":
            key_name = _get_required_value("key-name", args.key_name)
            message = _get_required_value("message", args.message)
            print(transit.sign(token, key_name, base64.b64encode(message.encode("utf-8")).decode("utf-8")))
            return 0
        if args.transit_command == "verify":
            key_name = _get_required_value("key-name", args.key_name)
            message = _get_required_value("message", args.message)
            signature = _get_required_value("signature", args.signature)
            print(transit.verify(token, key_name, base64.b64encode(message.encode("utf-8")).decode("utf-8"), signature))
            return 0
        if args.transit_command == "list-keys":
            print(transit.list_keys(token))
            return 0
        if args.transit_command == "revoke-key":
            key_name = _get_required_value("key-name", args.key_name)
            print(transit.revoke_key(token, key_name))
            return 0
        if args.transit_command == "rotate-key":
            key_name = _get_required_value("key-name", args.key_name)
            print(transit.rotate_key(token, key_name))
            return 0
    except PermissionError as exc:
        print(str(exc))
        return 1
    except (InvalidInputError, VaultError) as exc:
        print(exc.code)
        return 1
    except Exception as exc:
        print("ERROR", str(exc))
        return 1


def main(argv: Sequence[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        argv = ["interactive"]

    parser = _build_parser()
    args = parser.parse_args(list(argv))
    
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

        if args.command == "interactive":
            return _run_interactive(vault, auth)

        if args.command == "serve":
            import uvicorn

            from src.api.app import create_app

            uvicorn.run(create_app(), host=args.host, port=args.port)
            return 0

        if args.command == "kv":
            return _run_kv_command(args, vault, auth)

        if args.command == "transit":
            return _run_transit_command(args, vault, auth)
            
    except (InvalidInputError, AlreadyInitializedError, UnlockFailedError, VaultError) as exc:
        print(exc.code)
        return 1


    print("INVALID_INPUT")
    return 1


if __name__ == "__main__":
    sys.exit(main())