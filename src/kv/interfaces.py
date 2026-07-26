import json
import os

class StorageBackend:
    """Lưu trữ dữ liệu xuống file JSON vật lý"""
    def __init__(self, data_dir="data/secrets"):
        self.data_dir = data_dir
        os.makedirs(self.data_dir, exist_ok=True)

    def _get_file_path(self, path_key: str) -> str:
        # Biến "secret/alice@example.com/db" thành file name hợp lệ
        safe_filename = path_key.replace('/', '_') + ".json"
        return os.path.join(self.data_dir, safe_filename)

    def set(self, path_key: str, record: dict):
        file_path = self._get_file_path(path_key)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(record, f, indent=4)

    def get(self, path_key: str) -> dict:
        file_path = self._get_file_path(path_key)
        if not os.path.exists(file_path):
            return None
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def exists(self, path_key: str) -> bool:
        return os.path.exists(self._get_file_path(path_key))

    def delete(self, path_key: str):
        file_path = self._get_file_path(path_key)
        if os.path.exists(file_path):
            os.remove(file_path)

class AuthModule:
    """Mock Auth module để kiểm tra token"""
    def __init__(self):
        # Giả lập database chứa token
        self.tokens = {
            "token-alice-123": "alice@example.com",
            "token-bob-456": "bob@example.com"
        }

    def verify_token(self, token: str) -> str:
        if token not in self.tokens:
            raise ValueError("Token không hợp lệ hoặc đã hết hạn")
        return self.tokens[token]