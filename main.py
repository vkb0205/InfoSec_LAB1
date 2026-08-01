"""Mini Vault CLI entry point."""

from __future__ import annotations

import argparse
import base64
import getpass
from inspect import signature
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from src.core.vault import Vault
from src.auth.service import AuthService
from src.errors import AlreadyInitializedError, InvalidInputError, UnlockFailedError, VaultError
from src.kv.crypto_utils import CryptoEngine
from src.kv.kv_engine import KVEngine
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
    subparsers.add_parser("init-shamir")
    subparsers.add_parser("unlock")
    subparsers.add_parser("unlock-shamir")
    subparsers.add_parser("status")
    subparsers.add_parser("register")
    subparsers.add_parser("login")
    subparsers.add_parser("interactive")

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
    grant_verify_parser = transit_sub.add_parser("grant-verify")
    grant_verify_parser.add_argument("--token", default=None)
    grant_verify_parser.add_argument("--key-name", default=None)
    grant_verify_parser.add_argument("--verifier-email", default=None)
    list_shared_parser = transit_sub.add_parser("list-shared")
    list_shared_parser.add_argument("--token", default=None)
    revoke_verify_parser = transit_sub.add_parser("revoke-verify")
    revoke_verify_parser.add_argument("--token", default=None)
    revoke_verify_parser.add_argument("--key-name", default=None)
    revoke_verify_parser.add_argument("--verifier-email", default=None)

    subparsers.add_parser("enable-mfa")
    serve_parser = subparsers.add_parser("serve")
    serve_parser.add_argument("--host", default="127.0.0.1", type=str)
    serve_parser.add_argument("--port", default=8000, type=int)
    return parser


def _status(vault: Vault) -> str:
    if not vault.is_initialized():
        return "uninitialized"
    if vault.is_locked():
        return "locked"
    return "unlocked"


_DATA_DIR = Path(__file__).resolve().parent / "data"
_KV_STORE_PATH = _DATA_DIR / "kv_store.json"


class _KVFileStorage:
    def __init__(self, storage_path: Path | None = None) -> None:
        self.storage_path = storage_path or _KV_STORE_PATH

    def _load(self) -> dict[str, Any]:
        if not self.storage_path.exists():
            return {}
        try:
            with self.storage_path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                return {}
            return data
        except (OSError, json.JSONDecodeError):
            return {}

    def _save(self, store: dict[str, Any]) -> None:
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        with self.storage_path.open("w", encoding="utf-8") as fh:
            json.dump(store, fh, sort_keys=True, indent=2)

    def get(self, path: str) -> Any:
        return self._load().get(path)

    def set(self, path: str, record: Any) -> None:
        store = self._load()
        store[path] = record
        self._save(store)

    def exists(self, path: str) -> bool:
        return path in self._load()

    def delete(self, path: str) -> None:
        store = self._load()
        if path in store:
            del store[path]
            self._save(store)


def _prompt_token() -> str:
    return input("Token: ").strip()


def _prompt_text(prompt_text: str, default: str | None = None) -> str:
    if default is None:
        return input(f"{prompt_text}: ").strip()
    value = input(f"{prompt_text} [{default}]: ").strip()
    return value if value else default


def _run_interactive(vault: Vault, auth: AuthService) -> int:
    transit = TransitService(
        vault,
        auth_validator=auth.validate_session,
        repository=TransitKeyRepository(),
    )
    kv_store = _KVFileStorage()
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
        print("15) transit grant verify access")
        print("16) transit list shared keys")
        print("17) transit revoke verify access")
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
                plaintext_b64 = transit.decrypt(token, ciphertext)
                plaintext = base64.b64decode(plaintext_b64, validate=True).decode("utf-8")
                print(plaintext)
                continue

            if choice == "12":
                if not ensure_unlocked() or not ensure_session():
                    continue
                key_name = _prompt_text("Signing key name")
                print(transit.create_signing_key(token, key_name, "ED25519"))
                continue

            if choice == "13":
                if not ensure_unlocked() or not ensure_session():
                    continue
                key_name = _prompt_text("Signing key name")
                message = _prompt_text("Message to sign")
                message_b64 = base64.b64encode(message.encode("utf-8")).decode("utf-8")
                print(transit.sign(token, key_name, message_b64, "RAW"))
                continue

            if choice == "14":
                if not ensure_unlocked() or not ensure_session():
                    continue
                key_name = _prompt_text("Signing key name")
                message = _prompt_text("Message")
                signature = _prompt_text("Signature")
                message_b64 = base64.b64encode(message.encode("utf-8")).decode("utf-8")
                print(transit.verify(token, key_name, message_b64, "RAW", signature))
                continue

            if choice == "15":
                if not ensure_unlocked() or not ensure_session():
                    continue
                key_name = _prompt_text("Signing key name")
                verifier_email = _prompt_text("Verifier email")
                print(transit.grant_verify_access(token, key_name, verifier_email))
                continue

            if choice == "16":
                if not ensure_unlocked() or not ensure_session():
                    continue
                print(transit.list_shared_keys(token))
                continue

            if choice == "17":
                if not ensure_unlocked() or not ensure_session():
                    continue
                key_name = _prompt_text("Signing key name")
                verifier_email = _prompt_text("Verifier email")
                print(transit.revoke_verify_access(token, key_name, verifier_email))
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
    return KVEngine(CryptoEngine(vault.get_dek()), _KVFileStorage(), _AuthTokenValidator(auth))


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
    transit = TransitService(
        vault,
        auth_validator=auth.validate_session,
        repository=TransitKeyRepository(),
    )

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
            plaintext_b64 = transit.decrypt(token, ciphertext)
            plaintext = base64.b64decode(plaintext_b64, validate=True).decode("utf-8")
            print(plaintext)
            return 0
        if args.transit_command == "create-signing-key":
            key_name = _get_required_value("key-name", args.key_name)
            print(transit.create_signing_key(token, key_name, "ED25519"))
            return 0
        if args.transit_command == "sign":
            key_name = _get_required_value("key-name", args.key_name)
            message = _get_required_value("message", args.message)
            message_b64 = base64.b64encode(message.encode("utf-8")).decode("utf-8")
            print(transit.sign(token, key_name, message_b64, "RAW"))
            return 0
        if args.transit_command == "verify":
            key_name = _get_required_value("key-name", args.key_name)
            message = _get_required_value("message", args.message)
            signature = _get_required_value("signature", args.signature)
            message_b64 = base64.b64encode(message.encode("utf-8")).decode("utf-8")
            print(transit.verify(token, key_name, message_b64, "RAW", signature))
            return 0
        if args.transit_command == "grant-verify":
            key_name = _get_required_value("key-name", args.key_name)
            verifier_email = _get_required_value("verifier-email", args.verifier_email)
            print(transit.grant_verify_access(token, key_name, verifier_email))
            return 0
        if args.transit_command == "list-shared":
            print(transit.list_shared_keys(token))
            return 0
        if args.transit_command == "revoke-verify":
            key_name = _get_required_value("key-name", args.key_name)
            verifier_email = _get_required_value("verifier-email", args.verifier_email)
            print(transit.revoke_verify_access(token, key_name, verifier_email))
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
            print(_status(vault))
            return 0

        if args.command == "init":
            passphrase = getpass.getpass("Master Passphrase: ")
            vault.initialize(passphrase)
            print("initialized")
            print("locked")
            return 0

        if args.command == "init-shamir":
            try:
                total_shares = int(input("Total Shares (N): "))
                threshold = int(input("Threshold (K): "))
            except (TypeError, ValueError) as exc:
                raise InvalidInputError() from exc
            shares = vault.initialize_shamir(threshold, total_shares)
            print("initialized")
            for index, share in enumerate(shares, start=1):
                print(f"share-{index}: {share}")
            print("locked")
            return 0

        if args.command == "unlock":
            passphrase = getpass.getpass("Master Passphrase: ")
            vault.unlock(passphrase)
            print("unlocked")
            return 0

        if args.command == "unlock-shamir":
            config = vault.shamir_config()
            shares = [
                getpass.getpass(f"Share {index}: ")
                for index in range(1, config["threshold"] + 1)
            ]
            vault.unlock_with_shares(shares)
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
            otp = (
                getpass.getpass("TOTP Code: ")
                if auth.mfa_required(email)
                else None
            )
            print(auth.login(email, passphrase, otp))
            return 0

        if args.command == "enable-mfa":
            email = input("Email: ")
            passphrase = getpass.getpass("Passphrase: ")
            enrollment = auth.enable_mfa(email, passphrase)
            print(f"secret: {enrollment['secret']}")
            print(f"provisioning_uri: {enrollment['provisioning_uri']}")
            return 0

        if args.command == "interactive":
            return _run_interactive(vault, auth)

        if args.command == "kv":
            return _run_kv_command(args, vault, auth)

        if args.command == "transit":
            return _run_transit_command(args, vault, auth)

        if args.command == "serve":
            import uvicorn

            from src.api.app import create_app

            uvicorn.run(create_app(), host=args.host, port=args.port)
            return 0

    
    except Exception as exc:
        import traceback
        traceback.print_exc()  # In ra chính xác dòng code gây lỗi
        
        # Vẫn giữ lại phần in mã code nếu có
        if hasattr(exc, 'code'):
            print(f"Mã lỗi: {exc.code}")
        return 1

    print("Rơi xuống cuối hàm: Không tìm thấy command!")
    return 1


if __name__ == "__main__":
    sys.exit(main())
