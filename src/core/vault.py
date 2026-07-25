"""Core Vault state and DEK management."""

from __future__ import annotations

from typing import Any

from src.crypto_utils import (
    CryptoOperationError,
    MetadataValidationError,
    construct_metadata,
    derive_wrapping_key,
    extract_metadata_fields,
    random_dek,
    random_nonce,
    random_salt,
    unwrap_dek,
    validate_master_passphrase,
    wrap_dek,
)
from src.errors import AlreadyInitializedError, InvalidInputError, UnlockFailedError, VaultLockedError
from src.storage.repository import MetadataRepository


class Vault:
    """Runtime vault state machine.

    A new instance never contains a plaintext DEK. Metadata existence determines
    initialized vs. uninitialized, while the in-memory DEK determines unlocked
    state for the current process only.
    """

    def __init__(self, repository: MetadataRepository | None = None) -> None:
        self._repository = repository if repository is not None else MetadataRepository()
        self._dek: bytes | None = None

    def is_initialized(self) -> bool:
        return self._repository.exists()

    def is_locked(self) -> bool:
        return self._dek is None

    def initialize(self, passphrase: str) -> None:
        if self.is_initialized():
            raise AlreadyInitializedError()
        validate_master_passphrase(passphrase)

        dek: bytes | None = None
        wrapping_key: bytes | None = None
        try:
            salt = random_salt()
            dek = random_dek()
            nonce = random_nonce()
            wrapping_key = derive_wrapping_key(passphrase, salt)
            ciphertext_and_tag = wrap_dek(wrapping_key, dek, nonce)
            metadata = construct_metadata(salt=salt, nonce=nonce, ciphertext_and_tag=ciphertext_and_tag)
            self._repository.create(metadata)
            self._dek = None
        except AlreadyInitializedError:
            self._dek = None
            raise
        except InvalidInputError:
            self._dek = None
            raise
        except Exception as exc:
            self._dek = None
            raise InvalidInputError() from exc
        finally:
            dek = None
            wrapping_key = None

    def unlock(self, passphrase: str) -> None:
        self._dek = None
        wrapping_key: bytes | None = None
        dek: bytes | None = None
        try:
            metadata = self._repository.read()
            salt, nonce, ciphertext_and_tag, memory_cost, time_cost, parallelism, hash_len = extract_metadata_fields(metadata)
            wrapping_key = derive_wrapping_key(
                passphrase,
                salt,
                memory_cost_kib=memory_cost,
                time_cost=time_cost,
                parallelism=parallelism,
                hash_len=hash_len,
            )
            dek = unwrap_dek(wrapping_key, nonce, ciphertext_and_tag)
            if len(dek) != 32:
                raise CryptoOperationError()
            self._dek = bytes(dek)
        except (MetadataValidationError, CryptoOperationError, OSError, ValueError, TypeError, KeyError) as exc:
            self._dek = None
            raise UnlockFailedError() from exc
        except Exception as exc:
            self._dek = None
            raise UnlockFailedError() from exc
        finally:
            wrapping_key = None
            dek = None

    def get_dek(self) -> bytes:
        if self._dek is None:
            raise VaultLockedError()
        return bytes(self._dek)

    @property
    def repository(self) -> MetadataRepository:
        return self._repository
