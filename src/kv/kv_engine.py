import base64
import time
import logging
import os

# 1. TÌM ĐƯỜNG DẪN GỐC VÀ TẠO THƯ MỤC LOG
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(CURRENT_DIR))

LOG_DIR = os.path.join(PROJECT_ROOT, "data", "logs")
os.makedirs(LOG_DIR, exist_ok=True)  # Tạo thư mục nếu chưa tồn tại
LOG_FILE = os.path.join(LOG_DIR, "access_denied.log")

# 2. CẤU HÌNH LOGGER GHI VÀO FILE
kv_logger = logging.getLogger("KVEngineLogger")
kv_logger.setLevel(logging.WARNING)

# Ép logger ghi log xuống file (FileHandler) thay vì in ra màn hình
if not kv_logger.handlers:
    fh = logging.FileHandler(LOG_FILE, encoding='utf-8')
    fh.setFormatter(logging.Formatter('%(asctime)s | %(levelname)s | %(message)s'))
    kv_logger.addHandler(fh)

class KVEngine:
    def __init__(self, crypto_engine, storage_backend, auth_module):
        """
        :param crypto_engine: Instance của CryptoEngine (chứa AES-GCM)
        :param storage_backend: Interface lưu trữ đĩa từ src/storage/
        :param auth_module: Interface xác thực từ src/auth/
        """
        self.crypto = crypto_engine
        self.store = storage_backend 
        self.auth = auth_module

    def _log_denied(self, operation: str, path: str, caller: str, owner: str):
        msg = f"ACCESS DENIED | Op: {operation} | Path: {path} | Caller: {caller} | Owner: {owner}"
        kv_logger.warning(msg)

    def _verify_path_rule(self, path: str) -> str:
        """
        Kiểm tra tính hợp lệ của path và trích xuất email chủ sở hữu.
        Quy tắc: secret/<email>/...
        """
        parts = path.split('/')
        if len(parts) < 3 or parts[0] != 'secret':
            raise ValueError("Định dạng path không hợp lệ. Phải tuân thủ: 'secret/<email>/...'")
        
        owner_email = parts[1]
        return owner_email

    def _authorize(self, operation: str, path: str, token: str) -> str:
        """
        Xác minh token và đối chiếu quyền sở hữu với đường dẫn.
        """
        owner_email = self._verify_path_rule(path)
        
        # Gọi sang src/auth/ để lấy email thực sự của user đang giữ token
        caller_email = self.auth.verify_token(token)

        if caller_email != owner_email:
            self._log_denied(operation, path, caller_email, owner_email)
            raise PermissionError(f"Access Denied: Token không có quyền truy cập vào path của {owner_email}")

        return owner_email

    # ==========================================
    # KV MODULE INTERFACES
    # ==========================================

    def write(self, path: str, data: str, token: str) -> bool:
        """Mã hóa và lưu trữ dữ liệu tại path chỉ định."""
        owner_email = self._authorize("WRITE", path, token)

        # 1. Mã hóa dữ liệu (sinh ra bytes)
        encrypted_bytes = self.crypto.encrypt(data.encode('utf-8'))
        
        # 2. Encode sang Base64 để lưu trữ an toàn dưới dạng text/JSON
        b64_payload = base64.b64encode(encrypted_bytes).decode('utf-8')

        # 3. Đóng gói record
        record = {
            "owner": owner_email,
            "created_at": int(time.time()),
            "payload": b64_payload
        }

        # 4. Lưu xuống storage backend
        self.store.set(path, record)
        return True

    def read(self, path: str, token: str) -> str:
        """Đọc và giải mã dữ liệu từ path chỉ định."""
        owner_email = self._authorize("READ", path, token)

        # 1. Lấy record từ storage
        record = self.store.get(path)
        if not record:
            raise KeyError(f"Path không tồn tại: {path}")

        # 2. Decode Base64 lấy lại bytes thô
        encrypted_bytes = base64.b64decode(record["payload"])

        # 3. Giải mã và kiểm tra tính toàn vẹn (Tampering check)
        decrypted_bytes = self.crypto.decrypt(encrypted_bytes)
        
        return decrypted_bytes.decode('utf-8')

    def delete(self, path: str, token: str) -> bool:
        """Xóa vĩnh viễn dữ liệu tại path chỉ định."""
        self._authorize("DELETE", path, token)

        # Kiểm tra tồn tại trước khi xóa
        if not self.store.exists(path):
            return False

        self.store.delete(path)
        return True