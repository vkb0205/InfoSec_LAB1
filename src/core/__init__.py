"""Core vault initialization and process-local lock state."""

from src.core.access_control import RequestGuard
from src.core.vault import Vault, VaultMetadata, validate_master_passphrase
from src.crypto_utils import AesGcmEnvelope

__all__ = [
    "AesGcmEnvelope",
    "RequestGuard",
    "Vault",
    "VaultMetadata",
    "validate_master_passphrase",
]
