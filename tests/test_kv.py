import sys
import os
import base64
import pytest

# ==========================================
# CẤU HÌNH IMPORT
# ==========================================
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.insert(0, project_root)

from src.kv.crypto_utils import CryptoEngine
from src.kv.kv_engine import KVEngine

# ==========================================
# MOCKS & FIXTURES
# ==========================================
class DummyAuth:
    def verify_token(self, token: str) -> str:
        if token == "token_alice": return "alice@example.com"
        if token == "token_bob": return "bob@example.com"
        raise ValueError("Token không hợp lệ")

class DummyStorage:
    def __init__(self): self.data = {}
    def set(self, path, record): self.data[path] = record
    def get(self, path): return self.data.get(path)
    def exists(self, path): return path in self.data
    def delete(self, path):
        if path in self.data: del self.data[path]

@pytest.fixture
def engine():
    """
    Fixture này sẽ tự động khởi tạo KVEngine mới cho mỗi hàm test
    để đảm bảo trạng thái các bài test không bị ảnh hưởng lẫn nhau.
    """
    master_key = os.urandom(32)
    return KVEngine(CryptoEngine(master_key), DummyStorage(), DummyAuth())

# ==========================================
# CÁC BÀI KIỂM THỬ (PYTEST)
# ==========================================

def test_nonce_freshness(engine):
    path = "secret/alice@example.com/data"
    
    engine.write(path, "MySecret", "token_alice")
    record_1 = engine.store.get(path)
    latest_v1 = record_1["history"][-1] 
    
    engine.write(path, "MySecret", "token_alice")
    record_2 = engine.store.get(path)
    latest_v2 = record_2["history"][-1]
    
    assert latest_v1["nonce_b64"] != latest_v2["nonce_b64"], "Lỗi: Nonce không được làm mới!"
    assert latest_v1["ciphertext_b64"] != latest_v2["ciphertext_b64"], "Lỗi: Ciphertext giống nhau!"

def test_access_denied_logging(engine):
    path = "secret/alice@example.com/notes"
    engine.write(path, "Alice's secrets", "token_alice")

    # Bob cố đọc data của Alice - Mong đợi lỗi PermissionError
    with pytest.raises(PermissionError, match="PERMISSION_DENIED"):
        engine.read(path, "token_bob")

    # Bob cố ghi đè - Mong đợi lỗi PermissionError
    with pytest.raises(PermissionError, match="PERMISSION_DENIED"):
        engine.write(path, "Hacked", "token_bob")

    # Kiểm tra token không tồn tại - Mong đợi lỗi UNAUTHENTICATED
    with pytest.raises(PermissionError, match="UNAUTHENTICATED"):
        engine.read(path, "token_invalid")

def test_kv_versioning(engine):
    path = "secret/alice@example.com/api_keys"
    token = "token_alice"

    # Ghi 3 phiên bản
    assert engine.write(path, "key_v1", token)["version"] == 1
    assert engine.write(path, "key_v2", token)["version"] == 2
    assert engine.write(path, "key_v3", token)["version"] == 3

    # Kiểm tra đọc mặc định (phải là version mới nhất)
    assert engine.read(path, token) == "key_v3"

    # Kiểm tra đọc lại lịch sử cũ
    assert engine.read(path, token, version=1) == "key_v1"
    assert engine.read(path, token, version=2) == "key_v2"

    # Đọc version không tồn tại - Mong đợi KeyError
    with pytest.raises(KeyError, match="VERSION_NOT_FOUND"):
        engine.read(path, token, version=99)

def test_tampering_detection(engine):
    path = "secret/alice@example.com/bank_pin"
    engine.write(path, "1234", "token_alice")

    # Cố tình sửa đổi 1 byte trong Ciphertext của version mới nhất
    record = engine.store.get(path)
    latest_v = record["history"][-1]
    raw_bytes = bytearray(base64.b64decode(latest_v["ciphertext_b64"]))
    raw_bytes[0] ^= 0xFF # Lật 1 bit ngẫu nhiên
    latest_v["ciphertext_b64"] = base64.b64encode(raw_bytes).decode('utf-8')
    engine.store.set(path, record)

    # Đọc dữ liệu đã bị can thiệp - Mong đợi ValueError
    with pytest.raises(ValueError, match="AUTHENTICATION_TAG_MISMATCH"):
        engine.read(path, "token_alice")

def test_valid_crud_operations(engine):
    path = "secret/alice@example.com/test_crud"
    token = "token_alice"
    
    # Ghi dữ liệu
    engine.write(path, "Hello KV", token)
    
    # Xóa dữ liệu
    delete_result = engine.delete(path, token)
    assert delete_result == "DELETED_SUCCESSFULLY"
    
    # Cố gắng đọc lại dữ liệu đã xóa - Mong đợi KeyError
    with pytest.raises(KeyError, match="NOT_FOUND"):
        engine.read(path, token)