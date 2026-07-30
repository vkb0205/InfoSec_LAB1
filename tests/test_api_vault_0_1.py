"""REST API tests for Feature 0.1 (status / init / unlock)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app


@pytest.fixture
def client(metadata_path):
    app = create_app(metadata_path=metadata_path)
    with TestClient(app) as test_client:
        yield test_client


def test_status_uninitialized(client: TestClient) -> None:
    response = client.get("/v1/status")
    assert response.status_code == 200
    assert response.json() == {"status": "uninitialized"}


def test_init_then_status_locked(client: TestClient, valid_passphrase: str) -> None:
    response = client.post("/v1/init", json={"passphrase": valid_passphrase})
    assert response.status_code == 200
    assert response.json() == {"result": "initialized", "status": "locked"}

    status = client.get("/v1/status")
    assert status.status_code == 200
    assert status.json() == {"status": "locked"}


def test_init_second_time_already_initialized(client: TestClient, valid_passphrase: str) -> None:
    assert client.post("/v1/init", json={"passphrase": valid_passphrase}).status_code == 200
    again = client.post("/v1/init", json={"passphrase": valid_passphrase})
    assert again.status_code == 409
    assert again.json() == {"code": "ALREADY_INITIALIZED"}


def test_init_weak_passphrase_invalid_input(client: TestClient) -> None:
    response = client.post("/v1/init", json={"passphrase": "short"})
    assert response.status_code == 400
    assert response.json() == {"code": "INVALID_INPUT"}


def test_unlock_wrong_then_right_keeps_status_in_process(
    client: TestClient,
    valid_passphrase: str,
    another_valid_passphrase: str,
) -> None:
    assert client.post("/v1/init", json={"passphrase": valid_passphrase}).status_code == 200

    wrong = client.post("/v1/unlock", json={"passphrase": another_valid_passphrase})
    assert wrong.status_code == 401
    assert wrong.json() == {"code": "UNLOCK_FAILED"}
    assert "Traceback" not in wrong.text
    assert client.get("/v1/status").json() == {"status": "locked"}

    ok = client.post("/v1/unlock", json={"passphrase": valid_passphrase})
    assert ok.status_code == 200
    assert ok.json() == {"status": "unlocked"}

    # Same long-lived Vault: status stays unlocked across HTTP calls.
    assert client.get("/v1/status").json() == {"status": "unlocked"}


def test_passphrase_not_reflected_in_error_body(client: TestClient, valid_passphrase: str) -> None:
    secret = "N0tTheRight!Pass99"
    client.post("/v1/init", json={"passphrase": valid_passphrase})
    response = client.post("/v1/unlock", json={"passphrase": secret})
    assert response.status_code == 401
    assert secret not in response.text
    assert valid_passphrase not in response.text
