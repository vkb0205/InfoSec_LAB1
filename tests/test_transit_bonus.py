"""Transit list/revoke (Feature 2.1) and key rotation bonus."""

from __future__ import annotations

import base64
import json

import pytest

from src.errors import InvalidInputError
from src.storage.repository import TransitKeyRepository
from src.transit.service import TransitService


class UnlockedVault:
    def __init__(self, dek: bytes | None = None) -> None:
        self._dek = dek if dek is not None else b"\x11" * 32

    def is_locked(self) -> bool:
        return False

    def get_dek(self) -> bytes:
        return self._dek


def _svc(tmp_path, owner: str = "alice@example.com") -> TransitService:
    repo = TransitKeyRepository(tmp_path / "transit_keys.json")
    return TransitService(
        UnlockedVault(),
        auth_validator=lambda token: owner if token == "tok-alice" else (_ for _ in ()).throw(InvalidInputError()),
        repository=repo,
    )


def test_list_keys_metadata_only(tmp_path) -> None:
    svc = _svc(tmp_path)
    svc.create_key("tok-alice", "aes-a")
    svc.create_signing_key("tok-alice", "sig-a")
    listed = svc.list_keys("tok-alice")
    assert listed == [
        {"key_name": "aes-a", "key_usage": "ENCRYPT_DECRYPT", "latest_version": 1},
        {"key_name": "sig-a", "key_usage": "SIGN_VERIFY", "latest_version": 1},
    ]
    blob = json.dumps(listed)
    assert "encrypted_key_material" not in blob
    raw = (tmp_path / "transit_keys.json").read_text(encoding="utf-8")
    assert "encrypted_key_material_b64" in raw


def test_list_keys_owner_isolation(tmp_path) -> None:
    repo = TransitKeyRepository(tmp_path / "transit_keys.json")
    alice = TransitService(UnlockedVault(), auth_validator=lambda t: "alice@example.com", repository=repo)
    bob = TransitService(UnlockedVault(), auth_validator=lambda t: "bob@example.com", repository=repo)
    alice.create_key("a", "alice-only")
    bob.create_key("b", "bob-only")
    assert alice.list_keys("a") == [{"key_name": "alice-only", "key_usage": "ENCRYPT_DECRYPT", "latest_version": 1}]
    assert bob.list_keys("b") == [{"key_name": "bob-only", "key_usage": "ENCRYPT_DECRYPT", "latest_version": 1}]


def test_revoke_key_removes_and_blocks_use(tmp_path) -> None:
    svc = _svc(tmp_path)
    svc.create_key("tok-alice", "doomed")
    pt = base64.b64encode(b"secret").decode("ascii")
    ct = svc.encrypt("tok-alice", "doomed", pt)
    assert svc.revoke_key("tok-alice", "doomed") == {"key_name": "doomed", "status": "revoked"}
    assert svc.list_keys("tok-alice") == []
    with pytest.raises(InvalidInputError):
        svc.encrypt("tok-alice", "doomed", pt)
    with pytest.raises(InvalidInputError):
        svc.decrypt("tok-alice", ct)


def test_rotate_encrypt_decrypt_keeps_old_ciphertext(tmp_path) -> None:
    svc = _svc(tmp_path)
    svc.create_key("tok-alice", "rot")
    pt = base64.b64encode(b"hello-v1").decode("ascii")
    ct_v1 = svc.encrypt("tok-alice", "rot", pt)
    assert ct_v1.startswith("vault:rot:1:")

    rotated = svc.rotate_key("tok-alice", "rot")
    assert rotated == {"key_name": "rot", "key_usage": "ENCRYPT_DECRYPT", "latest_version": 2}

    pt2 = base64.b64encode(b"hello-v2").decode("ascii")
    ct_v2 = svc.encrypt("tok-alice", "rot", pt2)
    assert ct_v2.startswith("vault:rot:2:")

    assert base64.b64decode(svc.decrypt("tok-alice", ct_v1)) == b"hello-v1"
    assert base64.b64decode(svc.decrypt("tok-alice", ct_v2)) == b"hello-v2"

    store = json.loads((tmp_path / "transit_keys.json").read_text(encoding="utf-8"))
    key = store["keys"]["rot"]
    assert key["latest_version"] == 2
    assert set(key["versions"]) == {"1", "2"}
    assert key["versions"]["1"]["encrypted_key_material_b64"] != key["versions"]["2"]["encrypted_key_material_b64"]


def test_rotate_signing_old_signature_still_verifies(tmp_path) -> None:
    svc = _svc(tmp_path)
    svc.create_signing_key("tok-alice", "sig")
    msg = base64.b64encode(b"contract").decode("ascii")
    sig_v1 = svc.sign("tok-alice", "sig", msg)
    assert svc.verify("tok-alice", "sig", msg, sig_v1)["signature_valid"] is True

    assert svc.rotate_key("tok-alice", "sig")["latest_version"] == 2
    # Old signature still valid against retained v1 public key.
    assert svc.verify("tok-alice", "sig", msg, sig_v1)["signature_valid"] is True
    sig_v2 = svc.sign("tok-alice", "sig", msg)
    assert svc.verify("tok-alice", "sig", msg, sig_v2)["signature_valid"] is True
    assert sig_v1 != sig_v2


def test_legacy_ciphertext_without_version_decrypts(tmp_path) -> None:
    """Pre-rotation format vault:name:payload still decrypts via version trial."""
    svc = _svc(tmp_path)
    svc.create_key("tok-alice", "legacy")
    # Force encrypt path material, then craft legacy (no version) ciphertext with v1 key.
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import os

    repo = TransitKeyRepository(tmp_path / "transit_keys.json")
    key = repo.read()["keys"]["legacy"]
    material = TransitService._decrypt_key_material(b"\x11" * 32, key["encrypted_key_material_b64"])
    nonce = os.urandom(12)
    ct = AESGCM(material).encrypt(nonce, b"old-format", None)
    payload = base64.b64encode(nonce + ct).decode("ascii")
    legacy_ct = f"vault:legacy:{payload}"
    assert base64.b64decode(svc.decrypt("tok-alice", legacy_ct)) == b"old-format"


def test_tampered_rotated_ciphertext_fails(tmp_path) -> None:
    svc = _svc(tmp_path)
    svc.create_key("tok-alice", "t")
    svc.rotate_key("tok-alice", "t")
    pt = base64.b64encode(b"x").decode("ascii")
    ct = svc.encrypt("tok-alice", "t", pt)
    # Flip last char of payload
    bad = ct[:-1] + ("A" if ct[-1] != "A" else "B")
    with pytest.raises(InvalidInputError):
        svc.decrypt("tok-alice", bad)
