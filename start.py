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

# # print("# Feature 2.1")
# transit.create_key(alice, "alice-aes-demo")
# transit.create_key(bob, "alice-aes-demo")


# # print("# Feature 2.2")
# plaintext = base64.b64encode(b"Hello Vault").decode()
# ciphertext = transit.encrypt(alice, "alice-aes-demo", plaintext)

# print(base64.b64decode(transit.decrypt(alice, ciphertext)).decode())


# # print("# Feature 2.3")
# transit.encrypt(bob, "alice-aes-demo", plaintext)


# print("# Feature 2.4")
transit.create_signing_key(alice, "alice-sign-demo", "ED25519")

message = base64.b64encode(b"Important document").decode()
tampered = base64.b64encode(b"Important document modified").decode()

signed = transit.sign(alice, "alice-sign-demo", message, "RAW")

print(transit.verify(alice, "alice-sign-demo", message, "RAW", signed["signature_b64"]))
print(transit.verify(alice, "alice-sign-demo", tampered, "RAW", signed["signature_b64"]))
