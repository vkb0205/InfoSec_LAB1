from fastapi import status
from __init__ import VaultBaseException

# Reference about error codes: https://helpdesk.inet.vn/knowledgebase/tong-hop-cac-ma-loi-duoc-hien-thi-tren-website

class VaultLockedException(VaultBaseException):
    """Exception raised when the Vault is locked"""
    def __init__(self, message: str = "Vault is locked. Unlock required."):
        super().__init__(
            error_code="VAULT_LOCKED",
            message=message,
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE
        )


class UnauthenticatedException(VaultBaseException):
    """Exception raised when the session token is invalid or expired"""
    def __init__(self, message: str = "Authentication required or session expired."):
        super().__init__(
            error_code="UNAUTHENTICATED",
            message=message,
            status_code=status.HTTP_401_UNAUTHORIZED
        )


class PermissionDeniedException(VaultBaseException):
    """Exception raised when accessing a resource that is not owned (to prevent information leakage)"""
    def __init__(self, message: str = "Access denied."):
        super().__init__(
            error_code="PERMISSION_DENIED",
            message=message,
            status_code=status.HTTP_403_FORBIDDEN
        )


class NotFoundException(VaultBaseException):
    """Exception raised when a requested resource is not found"""
    def __init__(self, message: str = "Requested resource not found."):
        super().__init__(
            error_code="NOT_FOUND",
            message=message,
            status_code=status.HTTP_404_NOT_FOUND
        )


class InvalidKeyUsageException(VaultBaseException):
    """Exception raised when a key is used in an invalid context or operation"""
    def __init__(self, message: str = "Invalid key usage for the requested operation."):
        super().__init__(
            error_code="INVALID_KEY_USAGE",
            message=message,
            status_code=status.HTTP_400_BAD_REQUEST
        )