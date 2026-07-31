"""Storage helpers for vault metadata and account persistence."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from src.crypto_utils import DEFAULT_METADATA_PATH, validate_metadata
from src.errors import AlreadyInitializedError, InvalidInputError

USER_STORE_SCHEMA_VERSION = 1


class UserStoreValidationError(ValueError):
    """Internal validation failure for the versioned user-store document."""


def validate_user_store(store: Any) -> dict[str, Any]:
    """Return a strict account store or reject malformed/unexpected fields."""
    if not isinstance(store, dict) or set(store) != {"schema_version", "users"}:
        raise UserStoreValidationError()
    if store["schema_version"] != USER_STORE_SCHEMA_VERSION or not isinstance(store["users"], dict):
        raise UserStoreValidationError()
    for email, account in store["users"].items():
        if not isinstance(email, str) or not isinstance(account, dict):
            raise UserStoreValidationError()
        if set(account) != {"email", "password_hash", "failed_attempts", "locked_until"}:
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

    @staticmethod
    def _set_private_permissions(path: Path) -> None:
        try:
            os.chmod(path, 0o600)
        except (AttributeError, OSError):
            pass

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

            self._set_private_permissions(self.metadata_path)
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
        payload = json.dumps(store, sort_keys=True, separators=(",", ":")).encode("utf-8")
        directory = self.user_path.parent
        temp_path: Path | None = None
        try:
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd, temp_name = tempfile.mkstemp(prefix=f".{self.user_path.name}.", suffix=".tmp", dir=directory)
            temp_path = Path(temp_name)
            try:
                os.fchmod(fd, 0o600)
            except (AttributeError, OSError):
                pass
            with os.fdopen(fd, "wb") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(temp_path, self.user_path)
            MetadataRepository._set_private_permissions(self.user_path)
            MetadataRepository._fsync_directory(directory)
        except OSError as exc:
            raise InvalidInputError() from exc
        finally:
            if temp_path is not None:
                try:
                    temp_path.unlink()
                except FileNotFoundError:
                    pass


TRANSIT_KEY_STORE_SCHEMA_VERSION = 1


class TransitKeyStoreValidationError(ValueError):
    """Internal validation failure for the transit key store document."""


def validate_transit_key_store(store: Any) -> dict[str, Any]:
    if not isinstance(store, dict) or set(store) != {"schema_version", "keys"}:
        raise TransitKeyStoreValidationError()
    if store["schema_version"] != TRANSIT_KEY_STORE_SCHEMA_VERSION or not isinstance(store["keys"], dict):
        raise TransitKeyStoreValidationError()
    for name, key in store["keys"].items():
        if not isinstance(name, str) or not name or not isinstance(key, dict):
            raise TransitKeyStoreValidationError()
        if set(key) != {"name", "owner_email", "key_usage", "algorithm", "encrypted_key_material_b64", "public_key_b64", "created_at"}:
            raise TransitKeyStoreValidationError()
        if key["name"] != name or not isinstance(key["owner_email"], str) or not key["owner_email"]:
            raise TransitKeyStoreValidationError()
        if key["key_usage"] not in {"ENCRYPT_DECRYPT", "SIGN_VERIFY"}:
            raise TransitKeyStoreValidationError()
        if not isinstance(key["algorithm"], str) or not key["algorithm"]:
            raise TransitKeyStoreValidationError()
        if not isinstance(key["encrypted_key_material_b64"], str) or not key["encrypted_key_material_b64"]:
            raise TransitKeyStoreValidationError()
        if key["public_key_b64"] is not None and not isinstance(key["public_key_b64"], str):
            raise TransitKeyStoreValidationError()
        if not isinstance(key["created_at"], str) or not key["created_at"]:
            raise TransitKeyStoreValidationError()
    return store


class TransitKeyRepository:
    def __init__(self, transit_path: str | os.PathLike[str] | None = None) -> None:
        if transit_path is None:
            transit_path = Path(__file__).resolve().parents[2] / "data" / "transit_keys.json"
        self.transit_path = Path(transit_path)

    def read(self) -> dict[str, Any]:
        if not self.transit_path.exists():
            return {"schema_version": TRANSIT_KEY_STORE_SCHEMA_VERSION, "keys": {}}
        try:
            with self.transit_path.open("r", encoding="utf-8") as fh:
                return validate_transit_key_store(json.load(fh))
        except (OSError, json.JSONDecodeError, TransitKeyStoreValidationError) as exc:
            raise InvalidInputError() from exc

    def create_key(self, key: dict[str, Any]) -> None:
        store = self.read()
        try:
            name = key["name"]
            if name in store["keys"]:
                raise InvalidInputError()
            store["keys"][name] = key
            validate_transit_key_store(store)
        except (KeyError, TransitKeyStoreValidationError) as exc:
            raise InvalidInputError() from exc
        self._replace(store)

    def replace_key(self, key: dict[str, Any]) -> None:
        store = self.read()
        try:
            name = key["name"]
            if name not in store["keys"]:
                raise TransitKeyStoreValidationError()
            store["keys"][name] = key
            validate_transit_key_store(store)
        except (KeyError, TransitKeyStoreValidationError) as exc:
            raise InvalidInputError() from exc
        self._replace(store)

    def _replace(self, store: dict[str, Any]) -> None:
        payload = json.dumps(store, sort_keys=True, separators=(",", ":")).encode("utf-8")
        directory = self.transit_path.parent
        temp_path: Path | None = None
        try:
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd, temp_name = tempfile.mkstemp(prefix=f".{self.transit_path.name}.", suffix=".tmp", dir=directory)
            temp_path = Path(temp_name)
            try:
                os.fchmod(fd, 0o600)
            except (AttributeError, OSError):
                pass
            with os.fdopen(fd, "wb") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(temp_path, self.transit_path)
            MetadataRepository._set_private_permissions(self.transit_path)
            MetadataRepository._fsync_directory(directory)
        except OSError as exc:
            raise InvalidInputError() from exc
        finally:
            if temp_path is not None:
                try:
                    temp_path.unlink()
                except FileNotFoundError:
                    pass
