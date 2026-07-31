"""Storage helpers for vault metadata and account persistence."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from src.crypto_utils import (
    DEK_LEN,
    GCM_TAG_LEN,
    NONCE_LEN,
    DEFAULT_METADATA_PATH,
    MetadataValidationError,
    b64_decode,
    validate_metadata,
)
from src.errors import AlreadyInitializedError, DuplicateKeyError, InvalidInputError, KeyNotFoundError

USER_STORE_SCHEMA_VERSION = 1
TRANSIT_KEY_STORE_SCHEMA_VERSION = 1
MFA_TYPE = "TOTP"
MFA_ENCRYPTED_SEED_ENVELOPE_LEN = 64


class UserStoreValidationError(ValueError):
    """Internal validation failure for the versioned user-store document."""


class TransitKeyStoreValidationError(ValueError):
    """Internal validation failure for the named-key store."""


def validate_user_store(store: Any) -> dict[str, Any]:
    """Return a strict account store or reject malformed/unexpected fields."""
    if not isinstance(store, dict) or set(store) != {"schema_version", "users"}:
        raise UserStoreValidationError()
    if store["schema_version"] != USER_STORE_SCHEMA_VERSION or not isinstance(store["users"], dict):
        raise UserStoreValidationError()
    for email, account in store["users"].items():
        if not isinstance(email, str) or not isinstance(account, dict):
            raise UserStoreValidationError()
        required_fields = {"email", "password_hash", "failed_attempts", "locked_until"}
        if not required_fields.issubset(account) or not set(account).issubset(required_fields | {"mfa"}):
            raise UserStoreValidationError()
        if account["email"] != email or not email or not isinstance(account["password_hash"], str) or not account["password_hash"]:
            raise UserStoreValidationError()
        if isinstance(account["failed_attempts"], bool) or not isinstance(account["failed_attempts"], int) or account["failed_attempts"] < 0:
            raise UserStoreValidationError()
        if account["locked_until"] is not None:
            if not isinstance(account["locked_until"], str):
                raise UserStoreValidationError()
            try:
                lock_time = datetime.fromisoformat(account["locked_until"])
            except ValueError as exc:
                raise UserStoreValidationError() from exc
            if lock_time.tzinfo is None:
                raise UserStoreValidationError()
        mfa = account.get("mfa")
        if mfa is not None:
            if (
                not isinstance(mfa, dict)
                or set(mfa) != {"type", "encrypted_seed_b64"}
                or mfa["type"] != MFA_TYPE
            ):
                raise UserStoreValidationError()
            try:
                encrypted_seed = b64_decode(mfa["encrypted_seed_b64"])
            except MetadataValidationError as exc:
                raise UserStoreValidationError() from exc
            if len(encrypted_seed) != MFA_ENCRYPTED_SEED_ENVELOPE_LEN:
                raise UserStoreValidationError()
    return store


class MetadataRepository:
    """Create-only repository for the vault metadata envelope."""

    def __init__(self, metadata_path: str | os.PathLike[str] | None = None) -> None:
        if metadata_path is None:
            metadata_path = Path(__file__).resolve().parents[2] / DEFAULT_METADATA_PATH
        self.metadata_path = Path(metadata_path)

    def exists(self) -> bool:
        return self.metadata_path.exists()

    def read(self) -> dict[str, Any]:
        with self.metadata_path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        return validate_metadata(data)

    def read_bytes(self) -> bytes:
        return self.metadata_path.read_bytes()

    def create(self, metadata: dict[str, Any]) -> None:
        try:
            validate_metadata(metadata)
        except Exception as exc:
            raise InvalidInputError() from exc

        payload = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")
        directory = self.metadata_path.parent
        temp_path: Path | None = None

        try:
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            if self.metadata_path.exists():
                raise AlreadyInitializedError()

            fd, temp_name = tempfile.mkstemp(prefix=f".{self.metadata_path.name}.", suffix=".tmp", dir=directory)
            temp_path = Path(temp_name)
            try:
                os.fchmod(fd, 0o600)
            except (AttributeError, OSError):
                pass

            with os.fdopen(fd, "wb") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())

            try:
                os.link(temp_path, self.metadata_path)
            except FileExistsError as exc:
                raise AlreadyInitializedError() from exc

            self._fsync_directory(directory)
        except AlreadyInitializedError:
            raise
        except OSError as exc:
            raise InvalidInputError() from exc
        finally:
            if temp_path is not None:
                try:
                    temp_path.unlink()
                except FileNotFoundError:
                    pass

    @staticmethod
    def _fsync_directory(directory: Path) -> None:
        try:
            fd = os.open(directory, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


class UserRepository:
    """Mutable, atomically-replaced versioned account store; never stores sessions."""

    def __init__(self, user_path: str | os.PathLike[str] | None = None) -> None:
        if user_path is None:
            user_path = Path(__file__).resolve().parents[2] / "data/users.json"
        self.user_path = Path(user_path)

    def read(self) -> dict[str, Any]:
        if not self.user_path.exists():
            return {"schema_version": USER_STORE_SCHEMA_VERSION, "users": {}}
        try:
            with self.user_path.open("r", encoding="utf-8") as fh:
                return validate_user_store(json.load(fh))
        except (OSError, json.JSONDecodeError, UserStoreValidationError) as exc:
            raise InvalidInputError() from exc

    def create_account(self, account: dict[str, Any]) -> None:
        store = self.read()
        try:
            email = account["email"]
            if email in store["users"]:
                from src.errors import DuplicateUserError
                raise DuplicateUserError()
            store["users"][email] = account
            validate_user_store(store)
        except DuplicateUserError:
            raise
        except (KeyError, UserStoreValidationError) as exc:
            raise InvalidInputError() from exc
        self._replace(store)

    def replace_account(self, account: dict[str, Any]) -> None:
        store = self.read()
        try:
            email = account["email"]
            if email not in store["users"]:
                raise UserStoreValidationError()
            store["users"][email] = account
            validate_user_store(store)
        except (KeyError, UserStoreValidationError) as exc:
            raise InvalidInputError() from exc
        self._replace(store)

    def _replace(self, store: dict[str, Any]) -> None:
        _replace_json(self.user_path, store)


def validate_transit_key_store(store: Any) -> dict[str, Any]:
    if not isinstance(store, dict) or set(store) != {"schema_version", "keys"}:
        raise TransitKeyStoreValidationError()
    if store["schema_version"] != TRANSIT_KEY_STORE_SCHEMA_VERSION or not isinstance(store["keys"], list):
        raise TransitKeyStoreValidationError()

    identities: set[tuple[str, str]] = set()
    for record in store["keys"]:
        if not isinstance(record, dict):
            raise TransitKeyStoreValidationError()
        common = {"key_name", "owner_email", "key_usage"}
        if not common.issubset(record) or not all(isinstance(record[field], str) and record[field] for field in common):
            raise TransitKeyStoreValidationError()

        try:
            if record["key_usage"] == "ENCRYPT_DECRYPT":
                if set(record) != common | {"encrypted_key_material_b64"}:
                    raise TransitKeyStoreValidationError()
                envelope = b64_decode(record["encrypted_key_material_b64"])
                if len(envelope) != NONCE_LEN + DEK_LEN + GCM_TAG_LEN:
                    raise TransitKeyStoreValidationError()
            elif record["key_usage"] == "SIGN_VERIFY":
                signing_fields = {"signing_algorithm", "encrypted_private_key_b64", "public_key_b64"}
                if set(record) != common | signing_fields or record["signing_algorithm"] != "ED25519":
                    raise TransitKeyStoreValidationError()
                envelope = b64_decode(record["encrypted_private_key_b64"])
                public_key = b64_decode(record["public_key_b64"])
                if len(envelope) != NONCE_LEN + DEK_LEN + GCM_TAG_LEN or len(public_key) != DEK_LEN:
                    raise TransitKeyStoreValidationError()
            else:
                raise TransitKeyStoreValidationError()
        except (KeyError, MetadataValidationError) as exc:
            raise TransitKeyStoreValidationError() from exc

        identity = (record["owner_email"], record["key_name"])
        if identity in identities:
            raise TransitKeyStoreValidationError()
        identities.add(identity)
    return store


class TransitKeyRepository:
    """Atomic JSON persistence for DEK-wrapped Transit keys."""

    def __init__(self, key_path: str | os.PathLike[str] | None = None) -> None:
        if key_path is None:
            key_path = Path(__file__).resolve().parents[2] / "data/transit_keys.json"
        self.key_path = Path(key_path)

    def read(self) -> dict[str, Any]:
        if not self.key_path.exists():
            return {"schema_version": TRANSIT_KEY_STORE_SCHEMA_VERSION, "keys": []}
        try:
            with self.key_path.open("r", encoding="utf-8") as fh:
                return validate_transit_key_store(json.load(fh))
        except (OSError, json.JSONDecodeError, TransitKeyStoreValidationError) as exc:
            raise InvalidInputError() from exc

    def create_key(self, record: dict[str, str]) -> None:
        store = self.read()
        identity = (record.get("owner_email"), record.get("key_name"))
        if any((item["owner_email"], item["key_name"]) == identity for item in store["keys"]):
            raise DuplicateKeyError()
        store["keys"].append(record)
        try:
            validate_transit_key_store(store)
        except TransitKeyStoreValidationError as exc:
            raise InvalidInputError() from exc
        _replace_json(self.key_path, store)

    def list_keys(self, owner_email: str) -> list[dict[str, Any]]:
        return [
            record
            for record in self.read()["keys"]
            if record["owner_email"] == owner_email
        ]

    def get_key(self, owner_email: str, key_name: str) -> dict[str, Any]:
        for record in self.read()["keys"]:
            if (record["owner_email"], record["key_name"]) == (owner_email, key_name):
                return record
        raise KeyNotFoundError()

    def delete_key(self, owner_email: str, key_name: str) -> None:
        store = self.read()
        remaining = [
            record
            for record in store["keys"]
            if (record["owner_email"], record["key_name"]) != (owner_email, key_name)
        ]
        if len(remaining) == len(store["keys"]):
            raise KeyNotFoundError()
        store["keys"] = remaining
        _replace_json(self.key_path, store)


def _replace_json(path: Path, document: dict[str, Any]) -> None:
    """Atomically replace a JSON document without leaving temporary files."""
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    directory = path.parent
    temp_path: Path | None = None
    try:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=directory)
        temp_path = Path(temp_name)
        try:
            os.fchmod(fd, 0o600)
        except (AttributeError, OSError):
            pass
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temp_path, path)
        MetadataRepository._fsync_directory(directory)
    except OSError as exc:
        raise InvalidInputError() from exc
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass
