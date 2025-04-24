"""
Custom exceptions for the InboxGuard application
"""
from fastapi import status


class InboxGuardException(Exception):
    """Base exception for the application"""
    
    def __init__(self, detail: str, status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR):
        self.detail = detail
        self.status_code = status_code
        super().__init__(self.detail)


class DNSLookupError(InboxGuardException):
    """Exception raised when DNS lookup fails"""
    
    def __init__(self, detail: str):
        super().__init__(detail, status_code=status.HTTP_503_SERVICE_UNAVAILABLE)


class ValidationError(InboxGuardException):
    """Exception raised when validation fails"""
    
    def __init__(self, detail: str):
        super().__init__(detail, status_code=status.HTTP_400_BAD_REQUEST)