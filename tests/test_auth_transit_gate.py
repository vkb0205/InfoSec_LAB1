"""Authentication ordering at Transit public boundary."""
import pytest
from src.errors import UnauthenticatedError, VaultLockedError
from src.transit.service import TransitService

class Vault:
    def __init__(self, locked=False): self.locked = locked
    def is_locked(self): return self.locked

def test_transit_preserves_lock_precedence_and_propagates_identity():
    calls = []
    with pytest.raises(VaultLockedError): TransitService(Vault(True), lambda *v: calls.append(v), lambda t: (_ for _ in ()).throw(AssertionError())).list_keys("bad")
    with pytest.raises(UnauthenticatedError): TransitService(Vault(), lambda *v: calls.append(v), lambda t: (_ for _ in ()).throw(UnauthenticatedError())).list_keys("bad")
    assert TransitService(Vault(), lambda *v: v, lambda t: "user@example.com").list_keys("token") == ("list_keys", "user@example.com")