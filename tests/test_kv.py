import sys
import os
import base64

# ==========================================
# FIX LỖI IMPORT (Tự động thêm thư mục gốc vào sys.path)
# ==========================================
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.insert(0, project_root)

from src.kv.crypto_utils import CryptoEngine
from src.kv.kv_engine import KVEngine

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

def get_engine():
    master_key = os.urandom(32)
    return KVEngine(CryptoEngine(master_key), DummyStorage(), DummyAuth())

def test_nonce_freshness():
    engine = get_engine()
    path = "secret/alice@example.com/data"
    
    engine.write(path, "MySecret", "token_alice")
    cipher_1 = engine.store.get(path)["payload"]
    
    engine.write(path, "MySecret", "token_alice")
    cipher_2 = engine.store.get(path)["payload"]
    
    assert cipher_1 != cipher_2, "Lỗi: Ciphertext giống nhau, Nonce không được làm mới!"
    print("[PASSED] Nonce Freshness: Cùng data nhưng sinh ra 2 ciphertext khác nhau.")

def test_access_denied_logging():
    engine = get_engine()
    path = "secret/alice@example.com/notes"
    engine.write(path, "Alice's secrets", "token_alice")

    # Bob cố đọc data của Alice
    try:
        engine.read(path, "token_bob")
        assert False, "Lỗi: Bob đọc được data của Alice!"
    except PermissionError:
        pass

    # Bob cố ghi đè
    try:
        engine.write(path, "Hacked", "token_bob")
        assert False, "Lỗi: Bob ghi đè được data của Alice!"
    except PermissionError:
        pass

    # Kiểm tra file log bằng đường dẫn tuyệt đối (FIX)
    log_file_path = os.path.join(project_root, "data", "logs", "access_denied.log")
    assert os.path.exists(log_file_path), f"Lỗi: Không tìm thấy file log tại {log_file_path}"
    print("[PASSED] Access Control & Logging: Đã chặn Bob và ghi log thành công.")

def test_tampering_detection():
    engine = get_engine()
    path = "secret/alice@example.com/bank_pin"
    engine.write(path, "1234", "token_alice")

    record = engine.store.get(path)
    raw_bytes = bytearray(base64.b64decode(record["payload"]))
    raw_bytes[15] ^= 0xFF # Lật 1 bit ngẫu nhiên
    record["payload"] = base64.b64encode(raw_bytes).decode('utf-8')
    engine.store.set(path, record)

    try:
        engine.read(path, "token_alice")
        assert False, "Lỗi: Đọc thành công dù dữ liệu đã bị sửa đổi!"
    except ValueError as e:
        assert "Tampering" in str(e), "Lỗi không đúng loại Tampering"
    
    print("[PASSED] Tampering Detection: Phát hiện dữ liệu bị can thiệp (Invalid Auth Tag).")

def test_valid_crud_operations():
    engine = get_engine()
    path = "secret/alice@example.com/test_crud"
    token = "token_alice"
    
    engine.write(path, "Hello KV", token)
    assert engine.read(path, token) == "Hello KV", "Lỗi: Đọc sai dữ liệu!"
    
    engine.delete(path, token)
    try:
        engine.read(path, token)
        assert False, "Lỗi: Dữ liệu chưa bị xóa!"
    except KeyError:
        pass

    print("[PASSED] CRUD Operations: Ghi, Đọc, Xóa hoạt động chính xác.")

if __name__ == "__main__":
    print("=== BẮT ĐẦU KIỂM THỬ KV ENGINE ===")
    test_nonce_freshness()
    test_access_denied_logging()
    test_tampering_detection()
    test_valid_crud_operations()
    print("==================================")
    print("TẤT CẢ BÀI TEST ĐÃ VƯỢT QUA (SUCCESS)!")