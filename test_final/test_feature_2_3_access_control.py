"""Final acceptance tests for Feature 2.3: Transit named-key access control."""

from __future__ import annotations

import base64
import json
from pathlib import Path
import sys

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.errors import (
    PERMISSION_DENIED,
    PermissionDeniedError,
    UnauthenticatedError,
    VaultLockedError,
)
from src.storage.repository import TransitKeyRepository
from src.transit.service import TransitService


IDENTITIES = {
    "alice-token": "alice@example.com",
    "bob-token": "bob@example.com",
}


class CountingVault:
    def __init__(self, *, locked: bool = False) -> None:
        self.locked = locked
        self.dek = b"\x42" * 32
        self.dek_accesses = 0

    def is_locked(self) -> bool:
        return self.locked

    def get_dek(self) -> bytes:
        self.dek_accesses += 1
        if self.locked:
            raise AssertionError("locked vault DEK access")
        return self.dek


def authenticate(token: str) -> str:
    try:
        return IDENTITIES[token]
    except (KeyError, TypeError) as exc:
        raise UnauthenticatedError() from exc


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def make_service(tmp_path):
    vault = CountingVault()
    repository = TransitKeyRepository(tmp_path / "transit_keys.json")
    log_path = tmp_path / "access_denied.jsonl"
    service = TransitService(
        vault,
        auth_validator=authenticate,
        repository=repository,
        access_log_path=log_path,
    )
    return service, repository, vault, log_path


@pytest.mark.parametrize(
    ("method_name", "arguments"),
    [
        ("encrypt", ("invalid-token", "bob-key", b64(b"data"))),
        ("decrypt", ("invalid-token", "vault:bob-key:AAAA")),
    ],
)
def test_locked_gate_precedes_authentication_and_authorization(
    tmp_path,
    method_name,
    arguments,
):
    auth_calls = []
    vault = CountingVault(locked=True)
    service = TransitService(
        vault,
        auth_validator=lambda token: auth_calls.append(token),
        repository=TransitKeyRepository(tmp_path / "keys.json"),
        access_log_path=tmp_path / "denied.jsonl",
    )

    with pytest.raises(VaultLockedError):
        getattr(service, method_name)(*arguments)

    assert auth_calls == []
    assert vault.dek_accesses == 0
    assert not (tmp_path / "denied.jsonl").exists()


@pytest.mark.parametrize(
    ("method_name", "arguments"),
    [
        ("encrypt", (None, "bob-key", b64(b"data"))),
        ("decrypt", ("expired-token", "vault:bob-key:AAAA")),
    ],
)
def test_missing_invalid_or_expired_token_never_reaches_permission_checks(
    tmp_path,
    method_name,
    arguments,
):
    repository_touches = []

    class UntouchedRepository:
        def get_key(self, *args):
            repository_touches.append(args)
            raise AssertionError("repository must not be touched")

    vault = CountingVault()
    log_path = tmp_path / "access_denied.jsonl"
    service = TransitService(
        vault,
        auth_validator=lambda token: (_ for _ in ()).throw(
            UnauthenticatedError()
        ),
        repository=UntouchedRepository(),
        access_log_path=log_path,
    )

    with pytest.raises(UnauthenticatedError):
        getattr(service, method_name)(*arguments)

    assert repository_touches == []
    assert vault.dek_accesses == 0
    assert not log_path.exists()


def test_foreign_owner_cannot_encrypt_or_decrypt_and_crypto_is_not_reached(
    tmp_path,
):
    service, _, vault, log_path = make_service(tmp_path)
    service.create_key("bob-token", "bob-key")
    ciphertext = service.encrypt("bob-token", "bob-key", b64(b"bob data"))
    accesses_before_denials = vault.dek_accesses

    for _ in range(5):
        with pytest.raises(PermissionDeniedError) as encrypt_error:
            service.encrypt("alice-token", "bob-key", b64(b"alice data"))
        with pytest.raises(PermissionDeniedError) as decrypt_error:
            service.decrypt("alice-token", ciphertext)
        assert encrypt_error.value.code == PERMISSION_DENIED
        assert decrypt_error.value.code == PERMISSION_DENIED

    assert vault.dek_accesses == accesses_before_denials
    assert len(log_path.read_text(encoding="utf-8").splitlines()) == 10


def test_every_denial_log_contains_only_requester_key_and_event(tmp_path):
    service, _, _, log_path = make_service(tmp_path)
    service.create_key("bob-token", "payroll-key")
    ciphertext = service.encrypt(
        "bob-token",
        "payroll-key",
        b64(b"highly sensitive payroll content"),
    )

    with pytest.raises(PermissionDeniedError):
        service.encrypt("alice-token", "payroll-key", b64(b"client plaintext"))
    with pytest.raises(PermissionDeniedError):
        service.decrypt("alice-token", ciphertext)

    entries = [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
    ]
    assert entries == [
        {
            "event": "TRANSIT_PERMISSION_DENIED",
            "key_name": "payroll-key",
            "requester_email": "alice@example.com",
        },
        {
            "event": "TRANSIT_PERMISSION_DENIED",
            "key_name": "payroll-key",
            "requester_email": "alice@example.com",
        },
    ]
    serialized_log = log_path.read_text(encoding="utf-8")
    assert "alice-token" not in serialized_log
    assert "bob-token" not in serialized_log
    assert "client plaintext" not in serialized_log
    assert ciphertext not in serialized_log


def test_foreign_missing_and_revoked_keys_have_identical_public_denial(tmp_path):
    service, _, _, log_path = make_service(tmp_path)
    service.create_key("bob-token", "foreign")
    service.create_key("alice-token", "revoked")
    service.revoke_key("alice-token", "revoked")

    errors = []
    for key_name in ("foreign", "missing", "revoked"):
        with pytest.raises(PermissionDeniedError) as error:
            service.encrypt("alice-token", key_name, b64(b"data"))
        errors.append(error.value)

    assert {type(error) for error in errors} == {PermissionDeniedError}
    assert {error.code for error in errors} == {PERMISSION_DENIED}
    assert {str(error) for error in errors} == {PERMISSION_DENIED}
    entries = [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
    ]
    assert [entry["key_name"] for entry in entries] == [
        "foreign",
        "missing",
        "revoked",
    ]


def test_owner_can_use_own_key_while_other_users_keys_remain_isolated(tmp_path):
    service, _, _, _ = make_service(tmp_path)
    service.create_key("alice-token", "alice-key")
    service.create_key("bob-token", "bob-key")

    alice_ciphertext = service.encrypt(
        "alice-token",
        "alice-key",
        b64(b"alice"),
    )
    bob_ciphertext = service.encrypt("bob-token", "bob-key", b64(b"bob"))

    assert service.decrypt("alice-token", alice_ciphertext) == b64(b"alice")
    assert service.decrypt("bob-token", bob_ciphertext) == b64(b"bob")
    with pytest.raises(PermissionDeniedError):
        service.decrypt("bob-token", alice_ciphertext)
    with pytest.raises(PermissionDeniedError):
        service.decrypt("alice-token", bob_ciphertext)


def test_list_keys_never_discloses_another_owners_key_names(tmp_path):
    service, _, _, _ = make_service(tmp_path)
    service.create_key("alice-token", "alice-visible")
    service.create_key("bob-token", "bob-private")

    alice_keys = service.list_keys("alice-token")
    bob_keys = service.list_keys("bob-token")

    assert [item["key_name"] for item in alice_keys] == ["alice-visible"]
    assert [item["key_name"] for item in bob_keys] == ["bob-private"]
    assert "bob-private" not in json.dumps(alice_keys)
    assert "alice-visible" not in json.dumps(bob_keys)
