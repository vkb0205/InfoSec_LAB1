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

key = "rotation-demo"
transit.create_key(alice, key)

p1 = base64.b64encode(b"My documentation ver 1").decode()
ct1 = transit.encrypt(alice, key, p1)

transit.rotate_key(alice, key)
print(transit.list_key_versions(alice, key))

p2 = base64.b64encode(b"My documentation ver 2").decode()
ct2 = transit.encrypt(alice, key, p2)

print(base64.b64decode(transit.decrypt(alice, ct1)).decode())
print(base64.b64decode(transit.decrypt(alice, ct2)).decode())
