from __future__ import annotations

import base64
import json
import os
import shutil
from pathlib import Path
from typing import Any

from src.auth.service import AuthService
from src.core.vault import Vault
from src.kv.crypto_utils import CryptoEngine
from src.kv.kv_engine import KVEngine
from src.storage.repository import MetadataRepository, TransitKeyRepository, UserRepository
from src.transit.service import TransitService


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("utf-8")


def _to_text(b64_text: str) -> str:
    return base64.b64decode(b64_text.encode("utf-8")).decode("utf-8")


def _prepare_demo_root(root: Path) -> None:
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)


class DictStorage:
    def __init__(self) -> None:
        self.data: dict[str, Any] = {}

    def get(self, path: str) -> Any:
        return self.data.get(path)

    def set(self, path: str, record: Any) -> None:
        self.data[path] = record

    def exists(self, path: str) -> bool:
        return path in self.data

    def delete(self, path: str) -> None:
        self.data.pop(path, None)


def run_demo() -> None:
    demo_root = Path("data")
    _prepare_demo_root(demo_root)

    metadata_path = demo_root / "vault_metadata.json"
    user_path = demo_root / "users.json"
    transit_path = demo_root / "transit_keys.json"

    print("Demo workspace:", demo_root.resolve())

    vault = Vault(MetadataRepository(metadata_path))
    auth = AuthService(UserRepository(user_path))
    transit = TransitService(vault, auth.validate_session, TransitKeyRepository(transit_path))

    master_passphrase = "Str0ng!Passphrase123"
    print("\n1) Initialize vault")
    vault.initialize(master_passphrase)
    print("  - initialized")
    print("  - status after init:", "unlocked" if not vault.is_locked() else "locked")

    print("\n2) Unlock vault")
    vault.unlock(master_passphrase)
    print("  - unlocked")

    print("\n3) Register users Alice and Bob")
    auth.register("alice@example.com", "Str0ng!Passphrase123", "Str0ng!Passphrase123")
    auth.register("bob@example.com", "An0ther!Passphrase456", "An0ther!Passphrase456")
    print("  - registered alice@example.com")
    print("  - registered bob@example.com")

    print("\n4) Login and obtain session tokens")
    alice_token = auth.login("alice@example.com", "Str0ng!Passphrase123")
    bob_token = auth.login("bob@example.com", "An0ther!Passphrase456")
    print("  - alice token:", alice_token)
    print("  - bob token:", bob_token)

    print("\n5) Write and read Alice's secret via KV engine")
    kv = KVEngine(CryptoEngine(vault.get_dek()), DictStorage(), type("AuthWrapper", (), {"verify_token": staticmethod(auth.validate_session)})())
    secret_path = "secret/alice@example.com/demo-secret"
    kv.write(secret_path, "top-secret-value", alice_token)
    print("  - wrote secret to", secret_path)
    decrypted = kv.read(secret_path, alice_token)
    print("  - read secret:", decrypted)

    print("\n6) Attempt Bob reading Alice's secret should fail")
    try:
        kv.read(secret_path, bob_token)
        print("  - ERROR: Bob was able to read Alice's secret")
    except Exception as exc:
        print("  - access denied as expected:", type(exc).__name__, str(exc))

    print("\n7) Create an encryption key for Alice and encrypt/decrypt data")
    key_name = "alice-encrypt-key"
    transit.create_key(alice_token, key_name)
    print("  - created transit key:", key_name)
    plaintext = "Hello Vault Demo"
    ciphertext = transit.encrypt(alice_token, key_name, _b64(plaintext))
    print("  - ciphertext:", ciphertext)
    restored = _to_text(transit.decrypt(alice_token, ciphertext))
    print("  - decrypted:", restored)

    print("\n8) Attempt Bob using Alice's transit key should fail")
    try:
        transit.encrypt(bob_token, key_name, _b64("bad attempt"))
        print("  - ERROR: Bob encrypted with Alice's key")
    except Exception as exc:
        print("  - denied as expected:", type(exc).__name__, str(exc))

    print("\n9) Create signing key, sign a message, and verify it")
    sign_key_name = "alice-sign-key"
    transit.create_signing_key(alice_token, sign_key_name)
    message = "Mini Vault signature demo"
    signature = transit.sign(alice_token, sign_key_name, _b64(message))
    print("  - signature:", signature)
    verification = transit.verify(alice_token, sign_key_name, _b64(message), signature)
    print("  - verification result:", json.dumps(verification, indent=2))

    print("\n10) Verify a tampered message is invalid")
    tampered_message = _b64(message + "!")
    verification_tampered = transit.verify(alice_token, sign_key_name, tampered_message, signature)
    print("  - tampered verification result:", json.dumps(verification_tampered, indent=2))

    print("\nDemo complete.")


if __name__ == "__main__":
    run_demo()
