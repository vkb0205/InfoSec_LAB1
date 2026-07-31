from __future__ import annotations

import main
from src import CLI
from src.storage.repository import MetadataRepository, UserRepository


def test_cli_shows_menu_when_no_arguments(monkeypatch, capsys, tmp_path) -> None:
    metadata_path = tmp_path / "metadata.json"
    user_path = tmp_path / "users.json"
    monkeypatch.setattr(main, "MetadataRepository", lambda: MetadataRepository(metadata_path))
    monkeypatch.setattr(main, "UserRepository", lambda: UserRepository(user_path))

    prompts = iter(["3", "0"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(prompts))

    assert CLI.main() == 0
    output = capsys.readouterr().out
    assert "InfoSec Lab 1 Vault CLI" in output
    assert "Check status" in output
    assert "uninitialized" in output
