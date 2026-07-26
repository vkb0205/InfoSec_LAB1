"""CLI tests for init, status, and unlock."""

from __future__ import annotations

import pytest

import main
from src.storage.repository import MetadataRepository


def _patch_repo(monkeypatch, metadata_path) -> None:
    monkeypatch.setattr(main, "MetadataRepository", lambda: MetadataRepository(metadata_path))


def test_cli_init_prompts_rejects_passphrase_argument_and_reports_locked(monkeypatch, capsys, metadata_path, valid_passphrase) -> None:
    _patch_repo(monkeypatch, metadata_path)

    with pytest.raises(SystemExit) as arg_exit:
        main.main(["init", valid_passphrase])
    assert arg_exit.value.code != 0
    assert "INVALID_INPUT" in capsys.readouterr().out
    assert not metadata_path.exists()

    monkeypatch.setattr(main.getpass, "getpass", lambda prompt: valid_passphrase)
    assert main.main(["init"]) == 0
    out = capsys.readouterr().out.strip().splitlines()
    assert out == ["initialized", "locked"]


def test_cli_status_outputs_only_uninitialized_locked_or_unlocked(monkeypatch, capsys, metadata_path, valid_passphrase) -> None:
    _patch_repo(monkeypatch, metadata_path)

    assert main.main(["status"]) == 0
    assert capsys.readouterr().out.strip() == "uninitialized"

    monkeypatch.setattr(main.getpass, "getpass", lambda prompt: valid_passphrase)
    assert main.main(["init"]) == 0
    capsys.readouterr()

    assert main.main(["status"]) == 0
    assert capsys.readouterr().out.strip() == "locked"


def test_cli_unlock_success_and_wrong_passphrase_outputs_public_code(monkeypatch, capsys, metadata_path, valid_passphrase, another_valid_passphrase) -> None:
    _patch_repo(monkeypatch, metadata_path)
    prompts = iter([valid_passphrase, another_valid_passphrase, valid_passphrase])
    monkeypatch.setattr(main.getpass, "getpass", lambda prompt: next(prompts))

    assert main.main(["init"]) == 0
    capsys.readouterr()

    exit_code = main.main(["unlock"])
    assert exit_code != 0
    wrong_out = capsys.readouterr().out.strip()
    assert wrong_out == "UNLOCK_FAILED"
    assert "Traceback" not in wrong_out

    assert main.main(["unlock"]) == 0
    assert capsys.readouterr().out.strip() == "unlocked"


def test_cli_unlock_rejects_passphrase_argument(monkeypatch, capsys, metadata_path, valid_passphrase) -> None:
    _patch_repo(monkeypatch, metadata_path)

    with pytest.raises(SystemExit) as exc_info:
        main.main(["unlock", valid_passphrase])

    assert exc_info.value.code != 0
    assert "INVALID_INPUT" in capsys.readouterr().out
