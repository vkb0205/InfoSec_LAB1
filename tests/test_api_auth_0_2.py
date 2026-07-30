"""REST API tests for Feature 0.2 (register / login / session)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app


@pytest.fixture
def client(metadata_path, tmp_path):
    app = create_app(metadata_path=metadata_path, users_path=tmp_path / "users.json")
    with TestClient(app) as test_client:
        yield test_client


def test_register_login_session(client: TestClient, valid_passphrase: str) -> None:
    reg = client.post(
        "/v1/auth/register",
        json={
            "email": " User@Example.COM ",
            "passphrase": valid_passphrase,
            "confirmation": valid_passphrase,
        },
    )
    assert reg.status_code == 200
    assert reg.json() == {"result": "registered"}

    login = client.post(
        "/v1/auth/login",
        json={"email": "user@example.com", "passphrase": valid_passphrase},
    )
    assert login.status_code == 200
    token = login.json()["token"]
    assert isinstance(token, str) and token

    session = client.get("/v1/auth/session", headers={"Authorization": f"Bearer {token}"})
    assert session.status_code == 200
    assert session.json() == {"email": "user@example.com"}


def test_duplicate_register(client: TestClient, valid_passphrase: str) -> None:
    body = {
        "email": "a@b.com",
        "passphrase": valid_passphrase,
        "confirmation": valid_passphrase,
    }
    assert client.post("/v1/auth/register", json=body).status_code == 200
    again = client.post("/v1/auth/register", json=body)
    assert again.status_code == 409
    assert again.json() == {"code": "DUPLICATE_USER"}


def test_login_invalid_credentials(client: TestClient, valid_passphrase: str) -> None:
    client.post(
        "/v1/auth/register",
        json={"email": "a@b.com", "passphrase": valid_passphrase, "confirmation": valid_passphrase},
    )
    bad = client.post("/v1/auth/login", json={"email": "a@b.com", "passphrase": "Wrong!Pass99xx"})
    assert bad.status_code == 401
    assert bad.json() == {"code": "INVALID_CREDENTIALS"}
    assert "Wrong" not in bad.text


def test_session_missing_or_bad_token(client: TestClient) -> None:
    missing = client.get("/v1/auth/session")
    assert missing.status_code == 401
    assert missing.json() == {"code": "UNAUTHENTICATED"}

    bad = client.get("/v1/auth/session", headers={"Authorization": "Bearer not-a-real-token"})
    assert bad.status_code == 401
    assert bad.json() == {"code": "UNAUTHENTICATED"}


def test_lockout_after_five_failures(client: TestClient, valid_passphrase: str) -> None:
    client.post(
        "/v1/auth/register",
        json={"email": "a@b.com", "passphrase": valid_passphrase, "confirmation": valid_passphrase},
    )
    for _ in range(5):
        r = client.post("/v1/auth/login", json={"email": "a@b.com", "passphrase": "Wrong!Pass99xx"})
        assert r.status_code == 401
        assert r.json() == {"code": "INVALID_CREDENTIALS"}

    locked = client.post("/v1/auth/login", json={"email": "a@b.com", "passphrase": valid_passphrase})
    assert locked.status_code == 403
    assert locked.json() == {"code": "ACCOUNT_LOCKED"}
