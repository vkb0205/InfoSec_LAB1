import base64
import time
import logging
import os

from src.policy import (
    KV_SECRET,
    PolicyRepository,
    canonical_email,
)

# Cấu hình logging
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(CURRENT_DIR))
LOG_DIR = os.path.join(PROJECT_ROOT, "data", "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "access_denied.log")

kv_logger = logging.getLogger("KVEngineLogger")
kv_logger.setLevel(logging.WARNING)
if not kv_logger.handlers:
    fh = logging.FileHandler(LOG_FILE, encoding='utf-8')
    fh.setFormatter(logging.Formatter('%(asctime)s | %(levelname)s | %(message)s'))
    kv_logger.addHandler(fh)

class KVEngine:
    def __init__(self, crypto_engine, storage_backend, auth_module, policy_repository=None):
        self.crypto = crypto_engine
        self.store = storage_backend
        self.auth = auth_module
        self.policies = policy_repository if policy_repository is not None else PolicyRepository()

    def _log_denied(self, operation: str, path: str, caller: str, owner: str):
        msg = f"ACCESS DENIED | Op: {operation} | Path: {path} | Caller: {caller} | Owner: {owner}"
        kv_logger.warning(msg)

    def _verify_path_rule(self, path: str) -> str:
        if not isinstance(path, str):
            raise ValueError("INVALID_INPUT")
        parts = path.split('/')
        if len(parts) < 3 or parts[0] != 'secret':
            raise ValueError("Định dạng path không hợp lệ. Phải tuân thủ: 'secret/<email>/...'")
        return parts[1]

    def _authorize(self, operation: str, path: str, token: str) -> str:
        try:
            caller_email = self.auth.verify_token(token)
        except Exception:
            raise PermissionError("UNAUTHENTICATED")
        owner_email = self._verify_path_rule(path)

        if caller_email != owner_email and not self.policies.allows(
            KV_SECRET,
            owner_email,
            path,
            caller_email,
            operation,
        ):
            self._log_denied(operation, path, caller_email, owner_email)
            raise PermissionError("PERMISSION_DENIED")

        return owner_email

    def _require_owner(self, operation: str, path: str, token: str) -> str:
        try:
            caller_email = self.auth.verify_token(token)
        except Exception:
            raise PermissionError("UNAUTHENTICATED")
        owner_email = self._verify_path_rule(path)
        if caller_email != owner_email:
            self._log_denied(operation, path, caller_email, owner_email)
            raise PermissionError("PERMISSION_DENIED")
        return owner_email

    def grant_access(
        self,
        path: str,
        grantee_email: str,
        permissions,
        token: str,
    ) -> dict:
        owner_email = self._require_owner("MANAGE_POLICY", path, token)
        if not self.store.exists(path):
            raise KeyError("NOT_FOUND")
        grantee = canonical_email(grantee_email)
        granted = self.policies.grant(
            KV_SECRET,
            owner_email,
            path,
            grantee,
            permissions,
        )
        return {
            "path": path,
            "grantee_email": grantee,
            "permissions": granted,
        }

    def revoke_access(
        self,
        path: str,
        grantee_email: str,
        token: str,
        permissions=None,
    ) -> dict:
        owner_email = self._require_owner("MANAGE_POLICY", path, token)
        if not self.store.exists(path):
            raise KeyError("NOT_FOUND")
        grantee = canonical_email(grantee_email)
        remaining = self.policies.revoke(
            KV_SECRET,
            owner_email,
            path,
            grantee,
            permissions,
        )
        return {
            "path": path,
            "grantee_email": grantee,
            "permissions": remaining,
        }

    def get_acl(self, path: str, token: str) -> dict:
        owner_email = self._require_owner("READ_POLICY", path, token)
        if not self.store.exists(path):
            raise KeyError("NOT_FOUND")
        return {
            "path": path,
            "owner_email": owner_email,
            "grants": self.policies.get_acl(KV_SECRET, owner_email, path),
        }

    def list_shared(self, token: str) -> list[dict]:
        try:
            caller_email = self.auth.verify_token(token)
        except Exception:
            raise PermissionError("UNAUTHENTICATED")
        return [
            {
                "path": policy["resource_id"],
                "owner_email": policy["owner_email"],
                "permissions": policy["permissions"],
            }
            for policy in self.policies.list_shared(KV_SECRET, caller_email)
        ]

    # ==========================================
    # API CONTRACT IMPLEMENTATION (VERSIONING)
    # ==========================================

    def write(self, path: str, data: str, token: str) -> dict:
        owner_email = self._authorize("WRITE", path, token)

        # 1. Mã hóa dữ liệu
        nonce, ciphertext, tag = self.crypto.encrypt(data.encode('utf-8'))
        
        # 2. Base64 Encode
        nonce_b64 = base64.b64encode(nonce).decode('utf-8')
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
        tag_b64 = base64.b64encode(tag).decode('utf-8')
        current_time = int(time.time())

        # 3. Lấy record cũ để xử lý Versioning
        record = self.store.get(path)
        if not record or "history" not in record:
            record = {
                "path": path,
                "latest_version": 0,
                "history": []
            }

        new_version = record["latest_version"] + 1

        # 4. Đóng gói phiên bản mới
        version_data = {
            "version": new_version,
            "nonce_b64": nonce_b64,
            "ciphertext_b64": ciphertext_b64,
            "tag_b64": tag_b64,
            "created_at": current_time
        }

        # 5. Cập nhật record và lưu trữ
        record["history"].append(version_data)
        record["latest_version"] = new_version
        self.store.set(path, record)
        
        return {
            "version": new_version,
            "created_at": current_time,
            "updated_at": current_time
        }

    def read(self, path: str, token: str, version: int = None) -> str:
        self._authorize("READ", path, token)

        record = self.store.get(path)
        if not record or "history" not in record:
            raise KeyError("NOT_FOUND")

        # Xác định phiên bản cần đọc (mặc định là mới nhất)
        target_version = version if version is not None else record["latest_version"]
        
        # Tìm dữ liệu của phiên bản tương ứng
        version_data = next((v for v in record["history"] if v["version"] == target_version), None)
        if not version_data:
            raise KeyError(f"VERSION_NOT_FOUND: {target_version}")

        # Giải mã Base64
        nonce = base64.b64decode(version_data["nonce_b64"])
        ciphertext = base64.b64decode(version_data["ciphertext_b64"])
        tag = base64.b64decode(version_data["tag_b64"])

        # Giải mã và kiểm tra tính toàn vẹn
        decrypted_bytes = self.crypto.decrypt(nonce, ciphertext, tag)
        
        return decrypted_bytes.decode('utf-8')

    def delete(self, path: str, token: str) -> str:
        owner_email = self._authorize("DELETE", path, token)

        if not self.store.exists(path):
            raise KeyError("NOT_FOUND")

        # Xóa vĩnh viễn toàn bộ lịch sử
        self.store.delete(path)
        self.policies.delete_resource(KV_SECRET, owner_email, path)
        return "DELETED_SUCCESSFULLY"
