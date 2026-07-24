from fastapi import status
class VaultBaseException(Exception):
    """Exception class for Vault-related errors"""
    def __init__(self, error_code: str, message: str, status_code: int = status.HTTP_400_BAD_REQUEST):
        self.error_code = error_code
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)