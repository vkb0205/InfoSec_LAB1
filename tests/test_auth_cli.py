"""Prompt-only CLI authentication tests."""

import pytest

import main
from src.storage.repository import UserRepository


def _patch_user_repo(monkeypatch, path):
    monkeypatch.setattr(main, "UserRepository", lambda: UserRepository(path))


def test_register_prompts_for_secrets_and_outputs_only_registered(monkeypatch, capsys, tmp_path):
    _patch_user_repo(monkeypatch, tmp_path / "users.json")
    monkeypatch.setattr("builtins.input", lambda prompt: "User@Example.com")
    monkeypatch.setattr(main.getpass, "getpass", lambda prompt: "Str0ng!Passphrase123")
    assert main.main(["register"]) == 0
    assert capsys.readouterr().out.strip() == "registered"


def test_register_and_login_reject_secret_arguments_and_hide_failed_passphrase(monkeypatch, capsys, tmp_path):
    _patch_user_repo(monkeypatch, tmp_path / "users.json")
    secret = "Str0ng!Passphrase123"
    with pytest.raises(SystemExit): main.main(["register", secret])
    assert "INVALID_INPUT" in capsys.readouterr().out
    prompts = iter(["user@example.com", secret, secret])
    monkeypatch.setattr("builtins.input", lambda prompt: next(prompts))
    monkeypatch.setattr(main.getpass, "getpass", lambda prompt: next(prompts))
    assert main.main(["register"]) == 0
    capsys.readouterr()
    prompts = iter(["user@example.com", "incorrect-secret"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(prompts))
    monkeypatch.setattr(main.getpass, "getpass", lambda prompt: next(prompts))
    assert main.main(["login"]) == 1
    output = capsys.readouterr().out.strip()
    assert output == "INVALID_CREDENTIALS"
    assert "incorrect-secret" not in output


def test_login_outputs_exactly_one_fresh_token(monkeypatch, capsys, tmp_path):
    _patch_user_repo(monkeypatch, tmp_path / "users.json")
    secret = "Str0ng!Passphrase123"
    values = iter(["user@example.com", secret, secret])
    monkeypatch.setattr("builtins.input", lambda prompt: next(values))
    monkeypatch.setattr(main.getpass, "getpass", lambda prompt: next(values))
    assert main.main(["register"]) == 0
    capsys.readouterr()
    values = iter(["user@example.com", secret])
    monkeypatch.setattr("builtins.input", lambda prompt: next(values))
    monkeypatch.setattr(main.getpass, "getpass", lambda prompt: next(values))
    assert main.main(["login"]) == 0
    assert len(capsys.readouterr().out.strip().splitlines()) == 1