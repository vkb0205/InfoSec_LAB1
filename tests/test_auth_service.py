"""Authentication behavior tests with a deterministic clock and token issuer."""
from datetime import datetime, timedelta, timezone

import pytest

from src.auth.service import AuthService
from src.errors import ACCOUNT_LOCKED, DUPLICATE_USER, INVALID_CREDENTIALS, INVALID_INPUT, UNAUTHENTICATED, VaultError
from src.storage.repository import UserRepository


class Clock:
    def __init__(self): self.now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    def __call__(self): return self.now


def service(tmp_path, clock=None):
    tokens = iter(["token-one", "token-two"])
    return AuthService(UserRepository(tmp_path / "users.json"), clock=clock or Clock(), token_factory=lambda: next(tokens))


def test_registration_normalizes_and_never_persists_plaintext(tmp_path):
    auth = service(tmp_path)
    auth.register(" User@Example.COM ", "Str0ng!Passphrase123", "Str0ng!Passphrase123")
    account = auth._repository.read()["users"]["user@example.com"]
    assert account["failed_attempts"] == 0 and account["locked_until"] is None
    assert account["password_hash"] != "Str0ng!Passphrase123"
    with pytest.raises(VaultError, match=DUPLICATE_USER): auth.register("user@example.com", "Str0ng!Passphrase123", "Str0ng!Passphrase123")


@pytest.mark.parametrize("email,password,confirmation", [("bad", "Str0ng!Passphrase123", "Str0ng!Passphrase123"), ("a@b.com", "weak", "weak"), ("a@b.com", "Str0ng!Passphrase123", "different")])
def test_registration_rejects_invalid_inputs(tmp_path, email, password, confirmation):
    with pytest.raises(VaultError, match=INVALID_INPUT): service(tmp_path).register(email, password, confirmation)


def test_login_sessions_expire_and_restart_invalidates(tmp_path):
    clock = Clock(); auth = service(tmp_path, clock)
    auth.register("a@b.com", "Str0ng!Passphrase123", "Str0ng!Passphrase123")
    token = auth.login("a@b.com", "Str0ng!Passphrase123")
    assert auth.validate_session(token) == "a@b.com"
    clock.now += timedelta(minutes=30)
    with pytest.raises(VaultError, match=UNAUTHENTICATED): auth.validate_session(token)
    with pytest.raises(VaultError, match=UNAUTHENTICATED): service(tmp_path, clock).validate_session("token-two")


def test_invalid_login_and_exact_per_account_lockout(tmp_path):
    clock = Clock(); auth = service(tmp_path, clock)
    for email in ("a@b.com", "other@b.com"): auth.register(email, "Str0ng!Passphrase123", "Str0ng!Passphrase123")
    for _ in range(5):
        with pytest.raises(VaultError, match=INVALID_CREDENTIALS): auth.login("a@b.com", "wrong")
    with pytest.raises(VaultError, match=ACCOUNT_LOCKED): auth.login("a@b.com", "Str0ng!Passphrase123")
    assert auth.login("other@b.com", "Str0ng!Passphrase123") == "token-one"
    clock.now += timedelta(minutes=5)
    assert auth.login("a@b.com", "Str0ng!Passphrase123") == "token-two"