"""Advanced Feature 2: TOTP MFA enrollment and login."""

from __future__ import annotations

import base64
import itertools
from datetime import datetime, timedelta, timezone

import pytest

import main
from src.auth.service import AuthService
from src.auth.totp import decode_seed, decrypt_seed, totp_code
from src.errors import (
    ACCOUNT_LOCKED,
    INVALID_CREDENTIALS,
    AccountLockedError,
    InvalidCredentialsError,
)
from src.storage.repository import UserRepository

PASSPHRASE = "Str0ng!Passphrase123"
EMAIL = "alice@example.com"


class Clock:
    def __init__(self):
        self.now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self):
        return self.now


def make_service(tmp_path, clock=None):
    counter = itertools.count(1)
    return AuthService(
        UserRepository(tmp_path / "users.json"),
        clock=clock or Clock(),
        token_factory=lambda: f"token-{next(counter)}",
    )


def enroll(auth):
    auth.register(EMAIL, PASSPHRASE, PASSPHRASE)
    return auth.enable_mfa(EMAIL, PASSPHRASE)


def test_rfc6238_sha1_six_digit_vector():
    secret = base64.b32encode(b"12345678901234567890").decode("ascii")
    at_time = datetime.fromtimestamp(59, timezone.utc)
    assert totp_code(secret, at_time) == "287082"


def test_enrollment_encrypts_seed_and_returns_authenticator_contract(tmp_path):
    auth = make_service(tmp_path)
    enrollment = enroll(auth)
    account = auth._repository.read()["users"][EMAIL]
    persisted = auth._repository.user_path.read_text()

    assert len(enrollment["secret"]) == 32
    assert enrollment["provisioning_uri"].startswith("otpauth://totp/")
    assert f"secret={enrollment['secret']}" in enrollment["provisioning_uri"]
    assert enrollment["secret"] not in persisted
    assert account["mfa"]["type"] == "TOTP"
    assert decrypt_seed(
        account["mfa"]["encrypted_seed_b64"],
        PASSPHRASE,
        EMAIL,
    ) == decode_seed(enrollment["secret"])
    assert auth.mfa_required(EMAIL) is True


def test_mfa_login_requires_both_factors_and_issues_session(tmp_path):
    clock = Clock()
    auth = make_service(tmp_path, clock)
    enrollment = enroll(auth)
    correct_otp = totp_code(enrollment["secret"], clock.now)

    with pytest.raises(InvalidCredentialsError) as missing:
        auth.login(EMAIL, PASSPHRASE)
    assert missing.value.code == INVALID_CREDENTIALS
    with pytest.raises(InvalidCredentialsError):
        auth.login(EMAIL, PASSPHRASE, "not-six-digits")

    token = auth.login(EMAIL, PASSPHRASE, correct_otp)
    assert auth.validate_session(token) == EMAIL
    account = auth._repository.read()["users"][EMAIL]
    assert account["failed_attempts"] == 0
    assert account["locked_until"] is None


def test_totp_allows_one_step_clock_drift_but_not_two(tmp_path):
    clock = Clock()
    auth = make_service(tmp_path, clock)
    enrollment = enroll(auth)

    adjacent_code = totp_code(
        enrollment["secret"],
        clock.now + timedelta(seconds=30),
    )
    assert auth.login(EMAIL, PASSPHRASE, adjacent_code).startswith("token-")

    accepted_codes = {
        totp_code(enrollment["secret"], clock.now + timedelta(seconds=offset))
        for offset in (-30, 0, 30)
    }
    outside_seconds = 60
    outside_code = totp_code(
        enrollment["secret"],
        clock.now + timedelta(seconds=outside_seconds),
    )
    while outside_code in accepted_codes:
        outside_seconds += 30
        outside_code = totp_code(
            enrollment["secret"],
            clock.now + timedelta(seconds=outside_seconds),
        )
    with pytest.raises(InvalidCredentialsError):
        auth.login(EMAIL, PASSPHRASE, outside_code)


def test_five_bad_totp_attempts_use_existing_exact_lockout(tmp_path):
    clock = Clock()
    auth = make_service(tmp_path, clock)
    enrollment = enroll(auth)
    correct = totp_code(enrollment["secret"], clock.now)
    wrong = "000000" if correct != "000000" else "000001"

    for _ in range(5):
        with pytest.raises(InvalidCredentialsError):
            auth.login(EMAIL, PASSPHRASE, wrong)
    with pytest.raises(AccountLockedError) as locked:
        auth.login(EMAIL, PASSPHRASE, correct)
    assert locked.value.code == ACCOUNT_LOCKED

    clock.now += timedelta(minutes=5)
    new_code = totp_code(enrollment["secret"], clock.now)
    assert auth.login(EMAIL, PASSPHRASE, new_code).startswith("token-")


def test_wrong_password_skips_totp_and_tampered_seed_fails_generically(
    tmp_path,
    monkeypatch,
):
    clock = Clock()
    auth = make_service(tmp_path, clock)
    enrollment = enroll(auth)

    monkeypatch.setattr(
        "src.auth.service.decrypt_seed",
        lambda *args: (_ for _ in ()).throw(AssertionError("TOTP was reached")),
    )
    with pytest.raises(InvalidCredentialsError):
        auth.login(EMAIL, "wrong-passphrase", "000000")
    monkeypatch.undo()

    document = auth._repository.read()
    encrypted = bytearray(base64.b64decode(
        document["users"][EMAIL]["mfa"]["encrypted_seed_b64"],
        validate=True,
    ))
    encrypted[-1] ^= 0x01
    document["users"][EMAIL]["mfa"]["encrypted_seed_b64"] = base64.b64encode(
        encrypted,
    ).decode("ascii")
    auth._repository._replace(document)

    with pytest.raises(InvalidCredentialsError):
        auth.login(
            EMAIL,
            PASSPHRASE,
            totp_code(enrollment["secret"], clock.now),
        )


def test_legacy_account_without_mfa_field_keeps_original_login(tmp_path):
    auth = make_service(tmp_path)
    auth.register(EMAIL, PASSPHRASE, PASSPHRASE)
    document = auth._repository.read()
    document["users"][EMAIL].pop("mfa")
    auth._repository._replace(document)

    restarted = make_service(tmp_path)
    assert restarted.mfa_required(EMAIL) is False
    assert restarted.login(EMAIL, PASSPHRASE).startswith("token-")


def test_cli_enables_mfa_and_prompts_for_totp_only_when_required(
    tmp_path,
    monkeypatch,
    capsys,
):
    user_path = tmp_path / "users.json"
    monkeypatch.setattr(main, "UserRepository", lambda: UserRepository(user_path))
    monkeypatch.setattr("builtins.input", lambda prompt: EMAIL)
    monkeypatch.setattr(main.getpass, "getpass", lambda prompt: PASSPHRASE)
    assert main.main(["register"]) == 0
    capsys.readouterr()

    assert main.main(["enable-mfa"]) == 0
    enrollment_output = capsys.readouterr().out.strip().splitlines()
    secret = enrollment_output[0].split(": ", 1)[1]
    assert enrollment_output[1].startswith("provisioning_uri: otpauth://")

    otp = totp_code(secret, datetime.now(timezone.utc))
    monkeypatch.setattr(
        main.getpass,
        "getpass",
        lambda prompt: otp if "TOTP" in prompt else PASSPHRASE,
    )
    assert main.main(["login"]) == 0
    assert len(capsys.readouterr().out.strip().splitlines()) == 1
