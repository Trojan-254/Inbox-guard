"""
Enhanced validation utilities for the application
"""
import re
import logging
from typing import Optional, Tuple, Dict
from app.core.exceptions import ValidationError

logger = logging.getLogger(__name__)

DOMAIN_REGEX = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$'
)

EMAIL_REGEX = re.compile(
    r'^[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$'
)


def parse_input(input_value: str) -> Dict:
    """
    Parse an input string to determine if it's an email or domain
    and extract relevant information
    
    Args:
        input_value: String that could be a domain, email, or URL
        
    Returns:
        Dictionary containing:
        - input_type: "email" or "domain"
        - domain: The extracted domain
        - original: The original input value
        - email_prefix: Only present for email inputs
    """
    # Strip whitespace
    cleaned_value = input_value.strip().lower()
    
    # Check if it's an email address
    email_match = EMAIL_REGEX.match(cleaned_value)
    if email_match:
        domain = email_match.group(1)
        return {
            "input_type": "email",
            "domain": domain,
            "original": cleaned_value,
            "email_prefix": cleaned_value.split('@')[0]
        }
    
    # Otherwise process it as a domain
    # Remove any protocol prefixes
    if cleaned_value.startswith(('http://', 'https://')):
        cleaned_value = re.sub(r'^https?://', '', cleaned_value)
    
    # Remove any path components
    cleaned_value = cleaned_value.split('/')[0]
    
    # Remove any port numbers
    cleaned_value = cleaned_value.split(':')[0]
    
    return {
        "input_type": "domain",
        "domain": cleaned_value,
        "original": input_value
    }


def validate_domain(input_value: str) -> str:
    """
    Validate that a string is a valid domain name or extract domain from email
    
    Args:
        input_value: Domain or email to validate
        
    Returns:
        The validated domain name
        
    Raises:
        ValidationError: If the domain is invalid
    """
    # Parse the input to determine if it's an email or domain
    parsed = parse_input(input_value)
    domain = parsed["domain"]
    
    # Validate the domain format
    if not DOMAIN_REGEX.match(domain):
        logger.warning(f"Invalid domain format: {domain} (from input: {input_value})")
        raise ValidationError(f"Invalid domain format: {domain}")
    
    # Validate the domain doesn't use invalid TLDs
    tld = domain.split('.')[-1]
    if len(tld) < 2:
        logger.warning(f"Invalid TLD in domain: {domain} (from input: {input_value})")
        raise ValidationError(f"Invalid TLD in domain: {domain}")
    
    return domain


def extract_original_input(input_value: str) -> Dict:
    """
    Extract both the domain for validation and preserve the original input
    
    Args:
        input_value: Domain or email to process
        
    Returns:
        Dictionary with parsed information including domain and original value
    """
    return parse_input(input_value)


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