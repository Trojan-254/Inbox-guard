"""
DMARC (Domain-based Message Authentication, Reporting and Conformance) record analysis
"""
import logging
import re
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


def analyze_dmarc_record(dmarc_value: str) -> Dict[str, Any]:
    """
    Analyze a DMARC record for common issues and best practices
    
    Args:
        dmarc_value: The DMARC record value
        
    Returns:
        Dict containing analysis results
    """
    result = {
        "record_type": "DMARC",
        "status": "valid",  # Default status
        "value": dmarc_value,
        "issues": [],
        "recommendations": []
    }
    
    # Check if the record starts with the DMARC version
    if not dmarc_value.startswith("v=DMARC1"):
        result["status"] = "invalid"
        result["issues"].append("DMARC record does not start with 'v=DMARC1'")
        result["recommendations"].append("Ensure DMARC record starts with 'v=DMARC1'")
    
    # Check for policy (p= tag)
    p_match = re.search(r'p=([^;]+)', dmarc_value)
    if not p_match:
        result["status"] = "invalid"
        result["issues"].append("DMARC record is missing 'p=' (policy) tag")
        result["recommendations"].append("Add a policy tag (p=none, p=quarantine, or p=reject)")
    else:
        policy = p_match.group(1).lower()
        if policy not in ["none", "quarantine", "reject"]:
            result["status"] = "invalid"
            result["issues"].append(f"DMARC has invalid policy value: '{policy}'")
            result["recommendations"].append("Use 'none', 'quarantine', or 'reject' for the policy (p= tag)")
        elif policy == "none":
            result["status"] = "warning"
            result["issues"].append("DMARC policy is set to 'none' which only monitors and doesn't protect against spoofing")
            result["recommendations"].append("Consider moving to 'p=quarantine' or 'p=reject' after monitoring period")
    
    # Check for subdomain policy (sp= tag)
    sp_match = re.search(r'sp=([^;]+)', dmarc_value)
    if sp_match:
        sp_policy = sp_match.group(1).lower()
        if sp_policy not in ["none", "quarantine", "reject"]:
            result["status"] = "invalid"
            result["issues"].append(f"DMARC has invalid subdomain policy value: '{sp_policy}'")
            result["recommendations"].append("Use 'none', 'quarantine', or 'reject' for the subdomain policy (sp= tag)")
        elif sp_policy == "none" and p_match and p_match.group(1).lower() != "none":
            result["status"] = "warning"
            result["issues"].append("Subdomain policy is weaker than domain policy")
            result["recommendations"].append("Consider using the same policy for subdomains as the main domain")
    
    # Check for reporting address (rua= tag)
    if not re.search(r'rua=', dmarc_value):
        result["status"] = "warning"
        result["issues"].append("DMARC record has no aggregate report address (rua=)")
        result["recommendations"].append("Add an aggregate report address (rua=mailto:dmarc-reports@yourdomain.com)")
    
    # Check for percent value (pct= tag)
    pct_match = re.search(r'pct=([0-9]+)', dmarc_value)
    if pct_match:
        pct = int(pct_match.group(1))
        if pct < 100:
            result["status"] = "warning"
            result["issues"].append(f"DMARC policy applies to only {pct}% of emails")
            result["recommendations"].append("Consider increasing pct to 100 for full protection")
    
    # Check for failure reporting options (rf= tag)
    rf_match = re.search(r'rf=([^;]+)', dmarc_value)
    if rf_match:
        rf_value = rf_match.group(1).lower()
        valid_rf_values = ["afrf", "iodef"]
        for val in rf_value.split(':'):
            if val not in valid_rf_values:
                result["status"] = "warning"
                result["issues"].append(f"DMARC has invalid failure reporting format: '{val}'")
                result["recommendations"].append("Use 'afrf' and/or 'iodef' for failure reporting (rf= tag)")
    
    # Check record length (max 255 characters per TXT record)
    if len(dmarc_value) > 255:
        result["status"] = "warning"
        result["issues"].append(f"DMARC record length ({len(dmarc_value)} chars) exceeds 255 character limit for a single TXT record")
        result["recommendations"].append("Your DNS provider may need to split this record across multiple TXT records")
    
    # Add general recommendations if no issues found
    if not result["issues"]:
        result["recommendations"].append("Your DMARC record looks good!")
    
    return result