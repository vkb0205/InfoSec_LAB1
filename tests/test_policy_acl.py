"""Advanced Feature 1: explicit Policy/ACL sharing."""

from __future__ import annotations

import base64
import os

import pytest

from src.errors import InvalidInputError, PermissionDeniedError, VaultLockedError
from src.kv.crypto_utils import CryptoEngine
from src.kv.kv_engine import KVEngine
from src.policy import KV_SECRET, PolicyRepository, TRANSIT_KEY
from src.storage.repository import TransitKeyRepository
from src.transit.service import SIGNING_ALGORITHM, TransitService


class Auth:
    identities = {
        "alice-token": "alice@example.com",
        "bob-token": "bob@example.com",
    }

    def verify_token(self, token):
        return self.identities[token]


class Storage:
    def __init__(self):
        self.data = {}

    def set(self, path, record):
        self.data[path] = record

    def get(self, path):
        return self.data.get(path)

    def exists(self, path):
        return path in self.data

    def delete(self, path):
        self.data.pop(path, None)


class CountingCrypto:
    def __init__(self):
        self.engine = CryptoEngine(os.urandom(32))
        self.calls = 0

    def encrypt(self, plaintext):
        self.calls += 1
        return self.engine.encrypt(plaintext)

    def decrypt(self, nonce, ciphertext, tag):
        self.calls += 1
        return self.engine.decrypt(nonce, ciphertext, tag)


class Vault:
    def __init__(self, locked=False):
        self.locked = locked
        self.dek_accesses = 0
        self.dek = b"d" * 32

    def is_locked(self):
        return self.locked

    def get_dek(self):
        self.dek_accesses += 1
        return self.dek


def b64(value):
    return base64.b64encode(value).decode("ascii")


def test_kv_acl_is_granular_persistent_and_revocable(tmp_path):
    policies = PolicyRepository(tmp_path / "policies.json")
    crypto = CountingCrypto()
    engine = KVEngine(crypto, Storage(), Auth(), policies)
    path = "secret/alice@example.com/database"
    engine.write(path, "version one", "alice-token")

    result = engine.grant_access(
        path,
        "Bob@Example.com",
        ["read"],
        "alice-token",
    )
    assert result["permissions"] == ["READ"]
    assert engine.read(path, "bob-token") == "version one"
    calls_before_denials = crypto.calls

    with pytest.raises(PermissionError, match="PERMISSION_DENIED"):
        engine.write(path, "not allowed", "bob-token")
    with pytest.raises(PermissionError, match="PERMISSION_DENIED"):
        engine.delete(path, "bob-token")
    assert crypto.calls == calls_before_denials

    engine.grant_access(path, "bob@example.com", ["WRITE"], "alice-token")
    assert engine.write(path, "version two", "bob-token")["version"] == 2
    assert engine.read(path, "alice-token") == "version two"
    assert engine.list_shared("bob-token") == [{
        "path": path,
        "owner_email": "alice@example.com",
        "permissions": ["READ", "WRITE"],
    }]
    assert PolicyRepository(tmp_path / "policies.json").allows(
        KV_SECRET,
        "alice@example.com",
        path,
        "bob@example.com",
        "READ",
    )

    engine.revoke_access(path, "bob@example.com", "alice-token", ["READ"])
    with pytest.raises(PermissionError, match="PERMISSION_DENIED"):
        engine.read(path, "bob-token")
    assert engine.get_acl(path, "alice-token")["grants"] == {
        "bob@example.com": ["WRITE"],
    }


def test_only_kv_owner_can_manage_acl_and_delete_cleans_policy(tmp_path):
    policies = PolicyRepository(tmp_path / "policies.json")
    engine = KVEngine(CountingCrypto(), Storage(), Auth(), policies)
    path = "secret/alice@example.com/item"
    engine.write(path, "secret", "alice-token")

    with pytest.raises(PermissionError, match="PERMISSION_DENIED"):
        engine.grant_access(path, "bob@example.com", ["READ"], "bob-token")
    with pytest.raises(PermissionError, match="PERMISSION_DENIED"):
        engine.get_acl(path, "bob-token")
    with pytest.raises(InvalidInputError):
        engine.grant_access(path, "alice@example.com", ["READ"], "alice-token")

    engine.grant_access(path, "bob@example.com", ["DELETE"], "alice-token")
    assert engine.delete(path, "bob-token") == "DELETED_SUCCESSFULLY"
    assert policies.get_acl(KV_SECRET, "alice@example.com", path) == {}


def make_transit(tmp_path, vault=None):
    vault = vault or Vault()
    repository = TransitKeyRepository(tmp_path / "transit_keys.json")
    service = TransitService(
        vault,
        auth_validator=Auth.identities.__getitem__,
        repository=repository,
        access_log_path=tmp_path / "access_denied.jsonl",
    )
    return service, repository, vault


def test_transit_acl_selects_owner_and_enforces_each_permission(tmp_path):
    service, repository, vault = make_transit(tmp_path)
    service.create_key("alice-token", "shared-name")
    service.create_key("bob-token", "shared-name")
    service.grant_key_access(
        "alice-token",
        "shared-name",
        "bob@example.com",
        ["ENCRYPT"],
    )

    ciphertext = service.encrypt(
        "bob-token",
        "shared-name",
        b64(b"shared data"),
        key_owner_email="alice@example.com",
    )
    assert ciphertext.startswith("vault:alice@example.com/shared-name:")
    accesses_before_denial = vault.dek_accesses
    with pytest.raises(PermissionDeniedError):
        service.decrypt("bob-token", ciphertext)
    assert vault.dek_accesses == accesses_before_denial

    service.grant_key_access(
        "alice-token",
        "shared-name",
        "bob@example.com",
        ["DECRYPT"],
    )
    assert service.decrypt("bob-token", ciphertext) == b64(b"shared data")
    assert service.list_shared_keys("bob-token") == [{
        "key_name": "shared-name",
        "owner_email": "alice@example.com",
        "key_usage": "ENCRYPT_DECRYPT",
        "permissions": ["DECRYPT", "ENCRYPT"],
    }]

    restarted = TransitService(
        Vault(),
        auth_validator=Auth.identities.__getitem__,
        repository=repository,
        access_log_path=tmp_path / "restarted-access.jsonl",
    )
    assert restarted.decrypt("bob-token", ciphertext) == b64(b"shared data")
    restarted.revoke_key_access(
        "alice-token",
        "shared-name",
        "bob@example.com",
        ["DECRYPT"],
    )
    with pytest.raises(PermissionDeniedError):
        restarted.decrypt("bob-token", ciphertext)


def test_transit_sign_and_verify_have_independent_grants(tmp_path):
    service, _, vault = make_transit(tmp_path)
    service.create_signing_key("alice-token", "signer", SIGNING_ALGORITHM)
    signature = service.sign(
        "alice-token",
        "signer",
        b64(b"message"),
        "RAW",
    )["signature_b64"]
    service.grant_key_access(
        "alice-token",
        "signer",
        "bob@example.com",
        ["VERIFY"],
    )

    assert service.verify(
        "bob-token",
        "signer",
        b64(b"message"),
        "RAW",
        signature,
        key_owner_email="alice@example.com",
    )["signature_valid"] is True
    accesses_before_denial = vault.dek_accesses
    with pytest.raises(PermissionDeniedError):
        service.sign(
            "bob-token",
            "signer",
            b64(b"message"),
            "RAW",
            key_owner_email="alice@example.com",
        )
    assert vault.dek_accesses == accesses_before_denial

    with pytest.raises(InvalidInputError):
        service.grant_key_access(
            "alice-token",
            "signer",
            "bob@example.com",
            ["ENCRYPT"],
        )
    with pytest.raises(PermissionDeniedError):
        service.get_key_acl(
            "bob-token",
            "signer",
            key_owner_email="alice@example.com",
        )


def test_transit_revoke_key_removes_acl_and_acl_apis_keep_lock_precedence(tmp_path):
    service, _, _ = make_transit(tmp_path)
    service.create_key("alice-token", "temporary")
    service.grant_key_access(
        "alice-token",
        "temporary",
        "bob@example.com",
        ["ENCRYPT"],
    )
    service.revoke_key("alice-token", "temporary")
    policies = PolicyRepository(tmp_path / "policies.json")
    assert policies.get_acl(TRANSIT_KEY, "alice@example.com", "temporary") == {}

    locked, _, vault = make_transit(tmp_path / "locked", Vault(locked=True))
    for operation in (
        lambda: locked.grant_key_access(
            "bad-token",
            "key",
            "bob@example.com",
            ["ENCRYPT"],
        ),
        lambda: locked.revoke_key_access(
            "bad-token",
            "key",
            "bob@example.com",
        ),
        lambda: locked.get_key_acl("bad-token", "key"),
        lambda: locked.list_shared_keys("bad-token"),
    ):
        with pytest.raises(VaultLockedError):
            operation()
    assert vault.dek_accesses == 0
