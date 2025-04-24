"""
SPF (Sender Policy Framework) record analysis
"""
import logging
import re
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


def analyze_spf_record(spf_value: str) -> Dict[str, Any]:
    """
    Analyze an SPF record for common issues and best practices
    
    Args:
        spf_value: The SPF record value
        
    Returns:
        Dict containing analysis results
    """
    result = {
        "record_type": "SPF",
        "status": "valid",  # Default status
        "value": spf_value,
        "issues": [],
        "recommendations": []
    }
    
    # Check if the record starts with the SPF version
    if not spf_value.startswith("v=spf1"):
        result["status"] = "invalid"
        result["issues"].append("SPF record does not start with 'v=spf1'")
        result["recommendations"].append("Ensure SPF record starts with 'v=spf1'")
    
    # Check for missing all mechanism at the end
    if not re.search(r'\s[~?+-]all\s*$', spf_value + ' '):
        result["status"] = "warning"
        result["issues"].append("SPF record does not end with an 'all' mechanism")
        result["recommendations"].append("Add '~all' or '-all' at the end of your SPF record")
    
    # Check for +all (which allows anyone to send from the domain)
    if "+all" in spf_value:
        result["status"] = "invalid"
        result["issues"].append("SPF record contains '+all' which allows any server to send mail as your domain")
        result["recommendations"].append("Replace '+all' with '~all' (soft fail) or '-all' (hard fail)")
    
    # Check for too many DNS lookups (max 10 allowed by the SPF RFC)
    lookups = 0
    
    # Count include: mechanisms
    lookups += len(re.findall(r'include:', spf_value))
    
    # Count a: mechanisms
    lookups += len(re.findall(r'(?:^|\s)a(?::[^\s]+)?(?:\s|$)', spf_value))
    
    # Count mx: mechanisms
    lookups += len(re.findall(r'(?:^|\s)mx(?::[^\s]+)?(?:\s|$)', spf_value))
    
    # Count ptr: mechanisms
    lookups += len(re.findall(r'ptr:', spf_value))
    
    # Count exists: mechanisms
    lookups += len(re.findall(r'exists:', spf_value))
    
    if lookups > 10:
        result["status"] = "invalid"
        result["issues"].append(f"SPF record has too many DNS lookups ({lookups}). Maximum allowed is 10.")
        result["recommendations"].append("Simplify your SPF record or use flattening services")
    
    # Check for deprecated or obsolete mechanisms
    if "ptr" in spf_value:
        result["status"] = "warning"
        result["issues"].append("SPF record uses deprecated 'ptr' mechanism")
        result["recommendations"].append("Remove 'ptr' mechanism as it's inefficient and deprecated")
    
    # Check for overly permissive IP ranges
    if re.search(r'ip4:0\.0\.0\.0/0', spf_value):
        result["status"] = "invalid"
        result["issues"].append("SPF record allows all IPv4 addresses")
        result["recommendations"].append("Specify only the IP ranges that should be allowed to send email")
    
    # Check record length (max 255 characters per TXT record)
    if len(spf_value) > 255:
        result["status"] = "warning"
        result["issues"].append(f"SPF record length ({len(spf_value)} chars) exceeds 255 character limit for a single TXT record")
        result["recommendations"].append("Consider using SPF record flattening services or reducing the number of mechanisms")
    
    # Add general recommendations if no issues found
    if not result["issues"]:
        result["recommendations"].append("Your SPF record looks good!")
    
    return result