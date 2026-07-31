"""REST API tests for Feature 1 (KV write / read / delete)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app


@pytest.fixture
def client(metadata_path, tmp_path):
    app = create_app(
        metadata_path=metadata_path,
        users_path=tmp_path / "users.json",
        kv_store_path=tmp_path / "kv_store.json",
    )
    with TestClient(app) as test_client:
        yield test_client


def _unlock_and_login(
    client: TestClient,
    *,
    master: str,
    email: str,
    user_pass: str,
) -> str:
    assert client.post("/v1/init", json={"passphrase": master}).status_code == 200
    assert client.post("/v1/unlock", json={"passphrase": master}).status_code == 200
    assert (
        client.post(
            "/v1/auth/register",
            json={"email": email, "passphrase": user_pass, "confirmation": user_pass},
        ).status_code
        == 200
    )
    login = client.post("/v1/auth/login", json={"email": email, "passphrase": user_pass})
    assert login.status_code == 200
    return login.json()["token"]


def test_kv_write_read_delete_roundtrip(client: TestClient, valid_passphrase: str) -> None:
    email = "alice@example.com"
    token = _unlock_and_login(
        client, master=valid_passphrase, email=email, user_pass=valid_passphrase
    )
    path = f"secret/{email}/demo"
    headers = {"Authorization": f"Bearer {token}"}
    secret = '{"db_password":"s3cret"}'

    write = client.post("/v1/kv/write", headers=headers, json={"path": path, "data": secret})
    assert write.status_code == 200
    body = write.json()
    assert body["version"] == 1
    assert "created_at" in body and "updated_at" in body

    read = client.get("/v1/kv/read", headers=headers, params={"path": path})
    assert read.status_code == 200
    assert read.json() == {"path": path, "data": secret}

    deleted = client.delete("/v1/kv/delete", headers=headers, params={"path": path})
    assert deleted.status_code == 200
    assert deleted.json() == {"result": "DELETED_SUCCESSFULLY"}

    missing = client.get("/v1/kv/read", headers=headers, params={"path": path})
    assert missing.status_code == 404
    assert missing.json() == {"code": "NOT_FOUND"}


def test_kv_locked_vault(client: TestClient, valid_passphrase: str) -> None:
    email = "alice@example.com"
    assert client.post("/v1/init", json={"passphrase": valid_passphrase}).status_code == 200
    # locked — no unlock
    client.post(
        "/v1/auth/register",
        json={"email": email, "passphrase": valid_passphrase, "confirmation": valid_passphrase},
    )
    # login does not need unlock in current auth design
    login = client.post(
        "/v1/auth/login", json={"email": email, "passphrase": valid_passphrase}
    )
    token = login.json()["token"]
    r = client.post(
        "/v1/kv/write",
        headers={"Authorization": f"Bearer {token}"},
        json={"path": f"secret/{email}/x", "data": "nope"},
    )
    assert r.status_code == 403
    assert r.json() == {"code": "VAULT_LOCKED"}


def test_kv_permission_denied_no_existence_leak(
    client: TestClient, valid_passphrase: str
) -> None:
    alice = "alice@example.com"
    bob = "bob@example.com"
    master = valid_passphrase
    assert client.post("/v1/init", json={"passphrase": master}).status_code == 200
    assert client.post("/v1/unlock", json={"passphrase": master}).status_code == 200

    for email in (alice, bob):
        assert (
            client.post(
                "/v1/auth/register",
                json={
                    "email": email,
                    "passphrase": valid_passphrase,
                    "confirmation": valid_passphrase,
                },
            ).status_code
            == 200
        )

    alice_token = client.post(
        "/v1/auth/login", json={"email": alice, "passphrase": valid_passphrase}
    ).json()["token"]
    bob_token = client.post(
        "/v1/auth/login", json={"email": bob, "passphrase": valid_passphrase}
    ).json()["token"]

    path = f"secret/{alice}/private"
    assert (
        client.post(
            "/v1/kv/write",
            headers={"Authorization": f"Bearer {alice_token}"},
            json={"path": path, "data": "top-secret"},
        ).status_code
        == 200
    )

    denied = client.get(
        "/v1/kv/read",
        headers={"Authorization": f"Bearer {bob_token}"},
        params={"path": path},
    )
    assert denied.status_code == 403
    assert denied.json() == {"code": "PERMISSION_DENIED"}
    assert "top-secret" not in denied.text

    # Bob also denied for path that does not exist under alice (no NOT_FOUND leak)
    ghost = client.get(
        "/v1/kv/read",
        headers={"Authorization": f"Bearer {bob_token}"},
        params={"path": f"secret/{alice}/does-not-exist"},
    )
    assert ghost.status_code == 403
    assert ghost.json() == {"code": "PERMISSION_DENIED"}


def test_kv_unauthenticated(client: TestClient, valid_passphrase: str) -> None:
    token = _unlock_and_login(
        client,
        master=valid_passphrase,
        email="alice@example.com",
        user_pass=valid_passphrase,
    )
    path = "secret/alice@example.com/x"
    client.post(
        "/v1/kv/write",
        headers={"Authorization": f"Bearer {token}"},
        json={"path": path, "data": "s"},
    )

    missing = client.get("/v1/kv/read", params={"path": path})
    assert missing.status_code == 401
    assert missing.json() == {"code": "UNAUTHENTICATED"}

    bad = client.get(
        "/v1/kv/read",
        headers={"Authorization": "Bearer not-real"},
        params={"path": path},
    )
    assert bad.status_code == 401
    assert bad.json() == {"code": "UNAUTHENTICATED"}


def test_kv_invalid_path(client: TestClient, valid_passphrase: str) -> None:
    token = _unlock_and_login(
        client,
        master=valid_passphrase,
        email="alice@example.com",
        user_pass=valid_passphrase,
    )
    r = client.post(
        "/v1/kv/write",
        headers={"Authorization": f"Bearer {token}"},
        json={"path": "not-a-secret-path", "data": "x"},
    )
    assert r.status_code == 400
    assert r.json() == {"code": "INVALID_INPUT"}


def test_kv_version_read(client: TestClient, valid_passphrase: str) -> None:
    email = "alice@example.com"
    token = _unlock_and_login(
        client, master=valid_passphrase, email=email, user_pass=valid_passphrase
    )
    headers = {"Authorization": f"Bearer {token}"}
    path = f"secret/{email}/ver"
    assert (
        client.post("/v1/kv/write", headers=headers, json={"path": path, "data": "v1"}).status_code
        == 200
    )
    assert (
        client.post("/v1/kv/write", headers=headers, json={"path": path, "data": "v2"}).status_code
        == 200
    )
    latest = client.get("/v1/kv/read", headers=headers, params={"path": path})
    assert latest.json()["data"] == "v2"
    old = client.get("/v1/kv/read", headers=headers, params={"path": path, "version": 1})
    assert old.status_code == 200
    assert old.json()["data"] == "v1"
