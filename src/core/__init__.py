"""Core vault initialization and process-local lock state."""

from src.core.vault import Vault, VaultMetadata, validate_master_passphrase

__all__ = ["Vault", "VaultMetadata", "validate_master_passphrase"]
