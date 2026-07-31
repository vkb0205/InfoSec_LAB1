from __future__ import annotations

import main
from src import CLI
from src.auth.service import AuthService
from src.core.vault import Vault
from src.storage.repository import MetadataRepository, TransitKeyRepository, UserRepository
from src.transit.service import TransitService


def test_cli_allows_encrypt_after_registration(monkeypatch, capsys, tmp_path) -> None:
    metadata_path = tmp_path / "metadata.json"
    user_path = tmp_path / "users.json"
    transit_path = tmp_path / "transit_keys.json"

    monkeypatch.setattr(CLI, "MetadataRepository", lambda: MetadataRepository(metadata_path))
    monkeypatch.setattr(CLI, "UserRepository", lambda: UserRepository(user_path))
    monkeypatch.setattr(CLI, "TransitKeyRepository", lambda: TransitKeyRepository(transit_path))
    monkeypatch.setattr(CLI, "Vault", lambda repository=None: Vault(repository or MetadataRepository(metadata_path)))
    monkeypatch.setattr(CLI, "AuthService", lambda repository=None: AuthService(repository or UserRepository(user_path)))
    monkeypatch.setattr(CLI, "TransitService", lambda vault, auth_validator=None, repository=None: TransitService(vault, auth_validator=auth_validator, repository=repository or TransitKeyRepository(transit_path)))

    prompts = iter([
        "1",
        "2",
        "4",
        "user@example.com",
        "5",
        "user@example.com",
        "6",
        "demo-key",
        "hello world",
        "0",
    ])
    monkeypatch.setattr("builtins.input", lambda prompt: next(prompts))
    monkeypatch.setattr(main.getpass, "getpass", lambda prompt: "Str0ng!Passphrase123")
    monkeypatch.setattr(CLI.getpass, "getpass", lambda prompt: "Str0ng!Passphrase123")

    assert CLI.main() == 0
    output = capsys.readouterr().out
    assert "ciphertext" in output.lower()
    assert "demo-key" in output
