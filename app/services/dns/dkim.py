"""
DKIM (DomainKeys Identified Mail) record analysis
"""
import logging
import re
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


def analyze_dkim_record(dkim_value: str, selector: str) -> Dict[str, Any]:
    """
    Analyze a DKIM record for common issues and best practices
    
    Args:
        dkim_value: The DKIM record value
        selector: The DKIM selector used
        
    Returns:
        Dict containing analysis results
    """
    result = {
        "record_type": "DKIM",
        "status": "valid",  # Default status
        "value": dkim_value,
        "issues": [],
        "recommendations": []
    }
    
    # Check if the record starts with the DKIM version
    if not "v=DKIM1" in dkim_value:
        result["status"] = "invalid"
        result["issues"].append("DKIM record does not contain 'v=DKIM1' version tag")
        result["recommendations"].append("Ensure your DKIM record includes the version tag 'v=DKIM1'")
    
    # Check for public key (p= tag)
    if not re.search(r'p=', dkim_value):
        result["status"] = "invalid"
        result["issues"].append("DKIM record is missing 'p=' (public key) tag")
        result["recommendations"].append("The 'p=' tag containing the public key is required in DKIM records")
    
    # Check for revoked public key
    if re.search(r'p=', dkim_value) and re.search(r'p=;', dkim_value):
        result["status"] = "invalid"
        result["issues"].append("DKIM public key is revoked (p=;)")
        result["recommendations"].append("Generate a new DKIM key pair and update the DNS record")
    
    # Check for key type (k= tag)
    k_match = re.search(r'k=([^;]+)', dkim_value)
    if k_match:
        key_type = k_match.group(1)
        if key_type not in ["rsa", "ed25519"]:
            result["status"] = "warning"
            result["issues"].append(f"DKIM uses unsupported key type '{key_type}'")
            result["recommendations"].append("Use 'rsa' or 'ed25519' for the key type (k= tag)")
    
    # Check for hash algorithms (h= tag)
    h_match = re.search(r'h=([^;]+)', dkim_value)
    if h_match:
        hash_algs = h_match.group(1).split(':')
        if any(alg not in ["sha1", "sha256"] for alg in hash_algs):
            result["status"] = "warning"
            result["issues"].append("DKIM uses unsupported hash algorithm(s)")
            result["recommendations"].append("Use 'sha1' and/or 'sha256' for hash algorithms (h= tag)")
        
        if "sha1" in hash_algs and "sha256" not in hash_algs:
            result["status"] = "warning"
            result["issues"].append("DKIM uses only SHA-1 which is deprecated")
            result["recommendations"].append("Add SHA-256 to your hash algorithms (h=sha1:sha256)")
    
    # Check for service type (s= tag)
    s_match = re.search(r's=([^;]+)', dkim_value)
    if s_match:
        service_types = s_match.group(1).split(':')
        if any(stype not in ["email", "*"] for stype in service_types):
            result["status"] = "warning"
            result["issues"].append(f"DKIM has unknown service type(s)")
            result["recommendations"].append("Use 'email' or '*' for service type (s= tag)")
    
    # Check record length (max 255 characters per TXT record)
    if len(dkim_value) > 255:
        result["status"] = "warning"
        result["issues"].append(f"DKIM record length ({len(dkim_value)} chars) exceeds 255 character limit for a single TXT record")
        result["recommendations"].append("Your DNS provider may need to split this record across multiple TXT records")
    
    # Add general recommendations if no issues found
    if not result["issues"]:
        result["recommendations"].append("Your DKIM record looks good!")
    
    return result