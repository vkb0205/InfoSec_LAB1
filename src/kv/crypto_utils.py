import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class CryptoEngine:
    def __init__(self, encryption_key: bytes):
        """
        Khởi tạo Engine với Master Key 256-bit (32 bytes).
        """
        if len(encryption_key) != 32:
            raise ValueError("Encryption key phải có độ dài đúng 32 bytes (256-bit).")
        self.aesgcm = AESGCM(encryption_key)

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Mã hóa dữ liệu. Sinh fresh nonce cho mỗi lần gọi.
        Format trả về: Nonce (12B) + Ciphertext + Auth Tag (16B)
        """
        # Generate fresh 12-byte (96-bit) nonce per write
        nonce = os.urandom(12)
        
        # Mã hóa và tự động đính kèm Authentication Tag (16 bytes) ở cuối
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, None)
        
        return nonce + ciphertext

    def decrypt(self, encrypted_payload: bytes) -> bytes:
        """
        Giải mã dữ liệu. Tự động kiểm tra tính toàn vẹn (Tampering).
        """
        # Tách Nonce (12 bytes đầu) và Ciphertext + Tag (phần còn lại)
        nonce = encrypted_payload[:12]
        ciphertext = encrypted_payload[12:]
        
        try:
            # Giải mã và xác minh Tag. Nếu sai sẽ raise InvalidTag
            return self.aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise ValueError("Giải mã thất bại: Dữ liệu đã bị can thiệp (Tampering Detected!)") from e