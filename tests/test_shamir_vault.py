"""Advanced Feature 3: Shamir threshold initialization and unlock."""

from __future__ import annotations

import base64
import itertools
import json

import pytest

import main
from src.core.vault import Vault
from src.errors import (
    ALREADY_INITIALIZED,
    INVALID_INPUT,
    UNLOCK_FAILED,
    VAULT_LOCKED,
    AlreadyInitializedError,
    InvalidInputError,
    UnlockFailedError,
    VaultLockedError,
)
from src.shamir import combine_shares, split_secret
from src.storage.repository import MetadataRepository


def corrupt_share(encoded_share):
    padding = "=" * ((4 - len(encoded_share) % 4) % 4)
    raw = bytearray(base64.urlsafe_b64decode(encoded_share + padding))
    raw[-1] ^= 0x01
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def test_gf257_split_reconstructs_every_threshold_subset():
    secret = bytes(range(32))
    share_set_id = b"s" * 16
    shares = split_secret(secret, 3, 5, share_set_id)

    assert len(shares) == len(set(shares)) == 5
    for subset in itertools.combinations(shares, 3):
        assert combine_shares(subset, 3, 5, share_set_id) == secret


def test_shamir_initialization_persists_only_configuration_and_encrypted_dek(
    metadata_repository,
    metadata_path,
):
    vault = Vault(metadata_repository)
    shares = vault.initialize_shamir(3, 5)
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    raw_metadata = metadata_path.read_text(encoding="utf-8")

    assert len(shares) == len(set(shares)) == 5
    assert set(metadata) == {"schema_version", "shamir", "aead"}
    assert metadata["shamir"] == {
        "algorithm": "shamir-gf257",
        "threshold": 3,
        "total_shares": 5,
        "share_set_id_b64": metadata["shamir"]["share_set_id_b64"],
    }
    assert len(base64.b64decode(
        metadata["shamir"]["share_set_id_b64"],
        validate=True,
    )) == 16
    assert len(base64.b64decode(
        metadata["aead"]["nonce_b64"],
        validate=True,
    )) == 12
    assert len(base64.b64decode(
        metadata["aead"]["ciphertext_and_tag_b64"],
        validate=True,
    )) == 48
    assert "kdf" not in metadata
    assert all(share not in raw_metadata for share in shares)
    assert vault.shamir_config() == {"threshold": 3, "total_shares": 5}
    assert vault.is_locked() is True
    with pytest.raises(VaultLockedError) as locked:
        vault.get_dek()
    assert locked.value.code == VAULT_LOCKED


def test_every_three_of_five_subset_unlocks_the_same_dek_after_restart(
    metadata_repository,
    metadata_path,
):
    shares = Vault(metadata_repository).initialize_shamir(3, 5)
    original_metadata = metadata_path.read_bytes()
    expected_dek = None

    for subset in itertools.combinations(shares, 3):
        restarted = Vault(metadata_repository)
        assert restarted.is_locked() is True
        restarted.unlock_with_shares(subset)
        if expected_dek is None:
            expected_dek = restarted.get_dek()
        assert restarted.get_dek() == expected_dek
        assert metadata_path.read_bytes() == original_metadata

    assert len(expected_dek) == 32
    assert Vault(metadata_repository).is_locked() is True


@pytest.mark.parametrize(
    ("threshold", "total_shares"),
    [
        (1, 1),
        (0, 5),
        (4, 3),
        (2, 256),
        (True, 3),
        (2, False),
        ("2", 3),
    ],
)
def test_invalid_shamir_configuration_creates_no_metadata(
    metadata_repository,
    metadata_path,
    threshold,
    total_shares,
):
    with pytest.raises(InvalidInputError) as error:
        Vault(metadata_repository).initialize_shamir(threshold, total_shares)
    assert error.value.code == INVALID_INPUT
    assert not metadata_path.exists()


def test_insufficient_duplicate_corrupt_and_cross_vault_shares_fail_generically(
    tmp_path,
):
    first_repository = MetadataRepository(tmp_path / "first.json")
    second_repository = MetadataRepository(tmp_path / "second.json")
    first_shares = Vault(first_repository).initialize_shamir(3, 5)
    second_shares = Vault(second_repository).initialize_shamir(3, 5)
    invalid_sets = [
        first_shares[:2],
        [first_shares[0], first_shares[0], first_shares[1]],
        [first_shares[0], first_shares[1], corrupt_share(first_shares[2])],
        [first_shares[0], first_shares[1], second_shares[2]],
        [first_shares[0], first_shares[1], "not-a-share"],
    ]

    for supplied in invalid_sets:
        vault = Vault(first_repository)
        with pytest.raises(UnlockFailedError) as error:
            vault.unlock_with_shares(supplied)
        assert error.value.code == UNLOCK_FAILED
        assert str(error.value) == UNLOCK_FAILED
        assert vault.is_locked() is True

    extra_shares = Vault(first_repository)
    extra_shares.unlock_with_shares(first_shares)
    assert len(extra_shares.get_dek()) == 32


@pytest.mark.parametrize("field", ["threshold", "total_shares", "share_set", "ciphertext"])
def test_shamir_metadata_tampering_fails_generically(
    metadata_repository,
    metadata_path,
    field,
):
    shares = Vault(metadata_repository).initialize_shamir(3, 5)
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if field == "threshold":
        metadata["shamir"]["threshold"] = 2
    elif field == "total_shares":
        metadata["shamir"]["total_shares"] = 4
    elif field == "share_set":
        metadata["shamir"]["share_set_id_b64"] = base64.b64encode(
            b"x" * 16,
        ).decode("ascii")
    else:
        encrypted = bytearray(base64.b64decode(
            metadata["aead"]["ciphertext_and_tag_b64"],
            validate=True,
        ))
        encrypted[-1] ^= 0x01
        metadata["aead"]["ciphertext_and_tag_b64"] = base64.b64encode(
            encrypted,
        ).decode("ascii")
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    vault = Vault(metadata_repository)
    with pytest.raises(UnlockFailedError) as error:
        vault.unlock_with_shares(shares)
    assert error.value.code == UNLOCK_FAILED
    assert vault.is_locked() is True


def test_unlock_modes_cannot_be_crossed_and_initialization_is_create_only(
    tmp_path,
    valid_passphrase,
):
    passphrase_repository = MetadataRepository(tmp_path / "passphrase.json")
    Vault(passphrase_repository).initialize(valid_passphrase)
    with pytest.raises(UnlockFailedError):
        Vault(passphrase_repository).unlock_with_shares(["anything", "anything"])
    with pytest.raises(AlreadyInitializedError) as passphrase_collision:
        Vault(passphrase_repository).initialize_shamir(2, 3)
    assert passphrase_collision.value.code == ALREADY_INITIALIZED

    shamir_repository = MetadataRepository(tmp_path / "shamir.json")
    shares = Vault(shamir_repository).initialize_shamir(2, 3)
    with pytest.raises(UnlockFailedError):
        Vault(shamir_repository).unlock(valid_passphrase)
    with pytest.raises(AlreadyInitializedError):
        Vault(shamir_repository).initialize(valid_passphrase)

    unlocked = Vault(shamir_repository)
    unlocked.unlock_with_shares(shares[:2])
    assert len(unlocked.get_dek()) == 32


def test_cli_shamir_init_and_unlock_use_prompted_shares_only(
    monkeypatch,
    capsys,
    metadata_path,
):
    monkeypatch.setattr(
        main,
        "MetadataRepository",
        lambda: MetadataRepository(metadata_path),
    )
    configuration = iter(["5", "3"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(configuration))

    assert main.main(["init-shamir"]) == 0
    output = capsys.readouterr().out.strip().splitlines()
    assert output[0] == "initialized"
    assert output[-1] == "locked"
    shares = [line.split(": ", 1)[1] for line in output[1:-1]]
    assert len(shares) == 5

    prompted = iter(shares[:3])
    monkeypatch.setattr(main.getpass, "getpass", lambda prompt: next(prompted))
    assert main.main(["unlock-shamir"]) == 0
    assert capsys.readouterr().out.strip() == "unlocked"

    with pytest.raises(SystemExit):
        main.main(["unlock-shamir", shares[0]])
    assert "INVALID_INPUT" in capsys.readouterr().out
