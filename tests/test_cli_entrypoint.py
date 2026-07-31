from __future__ import annotations

import main
from src import CLI
from src.storage.repository import MetadataRepository, UserRepository


def test_src_cli_status_uses_main_entrypoint(monkeypatch, capsys, tmp_path) -> None:
    metadata_path = tmp_path / "metadata.json"
    user_path = tmp_path / "users.json"
    monkeypatch.setattr(main, "MetadataRepository", lambda: MetadataRepository(metadata_path))
    monkeypatch.setattr(main, "UserRepository", lambda: UserRepository(user_path))
    monkeypatch.setattr("sys.argv", ["mini-vault", "status"])

    assert CLI.main() == 0
    assert capsys.readouterr().out.strip() == "uninitialized"
