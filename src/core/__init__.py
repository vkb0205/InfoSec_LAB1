"""Core vault initialization and process-local lock state."""

from src.core.vault import Vault, VaultMetadata, validate_master_passphrase
from src.crypto_utils import AesGcmEnvelope

__all__ = [
    "AesGcmEnvelope",
    "Vault",
    "VaultMetadata",
    "validate_master_passphrase",
]
