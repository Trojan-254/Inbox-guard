"""
Validation utilities for the application
"""
import re
import logging
from typing import Optional
from app.core.exceptions import ValidationError

logger = logging.getLogger(__name__)

DOMAIN_REGEX = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$'
)


def validate_domain(domain: str) -> str:
    """
    Validate that a string is a valid domain name
    
    Args:
        domain: Domain name to validate
        
    Returns:
        The validated domain name
        
    Raises:
        ValidationError: If the domain is invalid
    """
    # Strip whitespace and convert to lowercase
    domain = domain.strip().lower()
    
    # Remove any protocol prefixes
    if domain.startswith(('http://', 'https://')):
        domain = re.sub(r'^https?://', '', domain)
    
    # Remove any path components
    domain = domain.split('/')[0]
    
    # Remove any port numbers
    domain = domain.split(':')[0]
    
    # Validate the domain format
    if not DOMAIN_REGEX.match(domain):
        logger.warning(f"Invalid domain format: {domain}")
        raise ValidationError(f"Invalid domain format: {domain}")
    
    # Validate the domain doesn't use invalid TLDs
    tld = domain.split('.')[-1]
    if len(tld) < 2:
        logger.warning(f"Invalid TLD in domain: {domain}")
        raise ValidationError(f"Invalid TLD in domain: {domain}")
    
    return domain


def validate_email_selector(selector: str) -> str:
    """
    Validate that a string is a valid DKIM selector
    
    Args:
        selector: DKIM selector to validate
        
    Returns:
        The validated selector
        
    Raises:
        ValidationError: If the selector is invalid
    """
    # Strip whitespace
    selector = selector.strip()
    
    # Validate the selector format (alphanumeric, dashes, and underscores)
    if not re.match(r'^[a-zA-Z0-9_-]+$', selector):
        logger.warning(f"Invalid DKIM selector format: {selector}")
        raise ValidationError(f"Invalid DKIM selector format: {selector}")
    
    return selector