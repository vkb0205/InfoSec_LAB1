"""Authentication ordering at KV's public boundary."""
import pytest
from src.errors import UnauthenticatedError, VaultLockedError
from src.kv.service import KVService

class Vault:
    def __init__(self, locked=False): self.locked = locked
    def is_locked(self): return self.locked

def test_kv_preserves_lock_precedence_and_propagates_identity():
    calls = []
    with pytest.raises(VaultLockedError): KVService(Vault(True), lambda *v: calls.append(v), lambda t: (_ for _ in ()).throw(AssertionError())).read("bad", "p")
    with pytest.raises(UnauthenticatedError): KVService(Vault(), lambda *v: calls.append(v), lambda t: (_ for _ in ()).throw(UnauthenticatedError())).read("bad", "p")
    assert KVService(Vault(), lambda *v: v, lambda t: "user@example.com").read("token", "p") == ("read", "user@example.com", "p")