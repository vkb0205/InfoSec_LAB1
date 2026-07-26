import sys
import os
import base64

# ==========================================
# CẤU HÌNH IMPORT
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

# ==========================================
# CÁC BÀI KIỂM THỬ
# ==========================================

def test_nonce_freshness():
    engine = get_engine()
    path = "secret/alice@example.com/data"
    
    engine.write(path, "MySecret", "token_alice")
    record_1 = engine.store.get(path)
    # Lấy dữ liệu từ mảng history của version 1
    latest_v1 = record_1["history"][-1] 
    
    engine.write(path, "MySecret", "token_alice")
    record_2 = engine.store.get(path)
    # Lấy dữ liệu từ mảng history của version 2
    latest_v2 = record_2["history"][-1]
    
    assert latest_v1["nonce_b64"] != latest_v2["nonce_b64"], "Lỗi: Nonce không được làm mới!"
    assert latest_v1["ciphertext_b64"] != latest_v2["ciphertext_b64"], "Lỗi: Ciphertext giống nhau!"
    print("[PASSED] Nonce Freshness: Cùng data nhưng sinh ra Nonce và Ciphertext khác nhau.")

def test_access_denied_logging():
    engine = get_engine()
    path = "secret/alice@example.com/notes"
    engine.write(path, "Alice's secrets", "token_alice")

    # Bob cố đọc data của Alice
    try:
        engine.read(path, "token_bob")
        assert False, "Lỗi: Bob đọc được data của Alice!"
    except PermissionError as e:
        assert "PERMISSION_DENIED" in str(e)

    # Bob cố ghi đè
    try:
        engine.write(path, "Hacked", "token_bob")
        assert False, "Lỗi: Bob ghi đè được data của Alice!"
    except PermissionError as e:
        assert "PERMISSION_DENIED" in str(e)

    # Kiểm tra token không tồn tại
    try:
        engine.read(path, "token_invalid")
        assert False, "Lỗi: Token không hợp lệ vẫn lọt qua!"
    except PermissionError as e:
        assert "UNAUTHENTICATED" in str(e)

    print("[PASSED] Access Control & Logging: Đã chặn truy cập trái phép và xử lý Auth thành công.")

def test_kv_versioning():
    engine = get_engine()
    path = "secret/alice@example.com/api_keys"
    token = "token_alice"

    # Lần ghi 1 (Version 1)
    res_v1 = engine.write(path, "key_v1", token)
    assert res_v1["version"] == 1, "Lỗi: Version đầu tiên phải là 1"

    # Lần ghi 2 (Version 2)
    res_v2 = engine.write(path, "key_v2", token)
    assert res_v2["version"] == 2, "Lỗi: Version tiếp theo phải là 2"

    # Lần ghi 3 (Version 3)
    res_v3 = engine.write(path, "key_v3", token)
    assert res_v3["version"] == 3, "Lỗi: Version tiếp theo phải là 3"

    # Kiểm tra đọc mặc định (phải là version mới nhất)
    assert engine.read(path, token) == "key_v3", "Lỗi: Đọc mặc định không ra version mới nhất"

    # Kiểm tra đọc lại lịch sử cũ
    assert engine.read(path, token, version=1) == "key_v1", "Lỗi: Đọc version 1 sai"
    assert engine.read(path, token, version=2) == "key_v2", "Lỗi: Đọc version 2 sai"

    # Đọc version không tồn tại
    try:
        engine.read(path, token, version=99)
        assert False, "Lỗi: Không văng lỗi khi đọc version không tồn tại"
    except KeyError as e:
        assert "VERSION_NOT_FOUND" in str(e)

    print("[PASSED] KV Versioning: Đã lưu trữ và truy xuất thành công lịch sử ghi đè.")

def test_tampering_detection():
    engine = get_engine()
    path = "secret/alice@example.com/bank_pin"
    engine.write(path, "1234", "token_alice")

    # Cố tình sửa đổi 1 byte trong Ciphertext của version mới nhất
    record = engine.store.get(path)
    latest_v = record["history"][-1]
    raw_bytes = bytearray(base64.b64decode(latest_v["ciphertext_b64"]))
    raw_bytes[0] ^= 0xFF # Lật 1 bit ngẫu nhiên
    latest_v["ciphertext_b64"] = base64.b64encode(raw_bytes).decode('utf-8')
    engine.store.set(path, record)

    try:
        engine.read(path, "token_alice")
        assert False, "Lỗi: Đọc thành công dù dữ liệu đã bị sửa đổi!"
    except ValueError as e:
        assert "AUTHENTICATION_TAG_MISMATCH" in str(e), "Lỗi: Không đúng loại Tampering (Tag Mismatch)"
    
    print("[PASSED] Tampering Detection: Phát hiện dữ liệu bị can thiệp thành công.")

def test_valid_crud_operations():
    engine = get_engine()
    path = "secret/alice@example.com/test_crud"
    token = "token_alice"
    
    # Ghi dữ liệu
    engine.write(path, "Hello KV", token)
    
    # Kiểm tra format trả về của Delete
    delete_result = engine.delete(path, token)
    assert delete_result == "DELETED_SUCCESSFULLY", "Lỗi: Delete API trả về sai format."
    
    try:
        engine.read(path, token)
        assert False, "Lỗi: Dữ liệu chưa bị xóa!"
    except KeyError as e:
        assert "NOT_FOUND" in str(e)

    print("[PASSED] CRUD Operations: Xóa (Delete) hoạt động chính xác và khớp API Contract.")

if __name__ == "__main__":
    print("=== BẮT ĐẦU KIỂM THỬ KV ENGINE ===")
    test_nonce_freshness()
    test_access_denied_logging()
    test_kv_versioning()
    test_tampering_detection()
    test_valid_crud_operations()
    print("==================================")
    print("TẤT CẢ BÀI TEST ĐÃ VƯỢT QUA (SUCCESS)!")