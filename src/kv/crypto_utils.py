import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

class CryptoEngine:
    def __init__(self, encryption_key: bytes):
        """
        Khởi tạo Engine với Master Key 256-bit (32 bytes).
        """
        if len(encryption_key) != 32:
            raise ValueError("VAULT_LOCKED: Encryption key phải có độ dài đúng 32 bytes (256-bit).")
        self.aesgcm = AESGCM(encryption_key)

    def encrypt(self, plaintext: bytes) -> tuple:
        """
        Mã hóa dữ liệu. Sinh fresh nonce cho mỗi lần gọi.
        Trả về tuple: (nonce, ciphertext, tag)
        """
        # Generate fresh 12-byte (96-bit) nonce per write
        nonce = os.urandom(12)
        
        # Mã hóa (AESGCM tự động đính kèm 16 bytes auth tag ở cuối)
        encrypted_payload = self.aesgcm.encrypt(nonce, plaintext, None)
        
        # Tách Ciphertext và Tag (16 bytes cuối cùng)
        ciphertext = encrypted_payload[:-16]
        tag = encrypted_payload[-16:]
        
        return nonce, ciphertext, tag

    def decrypt(self, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
        """
        Giải mã dữ liệu với Nonce, Ciphertext và Tag riêng biệt.
        """
        try:
            # Nối lại ciphertext và tag để thư viện xử lý
            payload = ciphertext + tag
            return self.aesgcm.decrypt(nonce, payload, None)
        except InvalidTag:
            # Bắt lỗi tag mismatch
            raise ValueError("AUTHENTICATION_TAG_MISMATCH: Dữ liệu đã bị can thiệp!")