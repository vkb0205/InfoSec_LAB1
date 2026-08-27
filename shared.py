import base64
from src.core.vault import Vault
from src.auth.service import AuthService
from src.storage.repository import MetadataRepository, UserRepository, TransitKeyRepository
from src.transit.service import TransitService


vault = Vault(MetadataRepository())
vault.unlock("SuperVault123@")

auth = AuthService(UserRepository())
alice = auth.login("alice@example.com", "DemoVault!2026")
bob = auth.login("bob@gmail.com", "DemoVault!2026")

transit = TransitService(vault, auth_validator=auth.validate_session, repository=TransitKeyRepository())

# ====================================================================================================

transit.create_signing_key(alice, "shared-signer", "ED25519")

message = base64.b64encode(b"Release manifest").decode()
signed = transit.sign(alice, "shared-signer", message, "RAW")

# transit.verify(bob, "shared-signer", message, "RAW", signed["signature_b64"], key_owner_email="alice@example.com")

transit.grant_verify_access(alice, "shared-signer", "bob@gmail.com")
transit.list_shared_keys(bob)

print(transit.verify(bob, "alice@example.com/shared-signer", message, "RAW", signed["signature_b64"]))
