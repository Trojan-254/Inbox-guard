import logging
import json
from typing import Dict, List, Optional, Any
from datetime import datetime

# Import the scanner module with DomainScanner class
from app.services.dns.scanner import DomainScanner

logger = logging.getLogger(__name__)

async def verify_domain_with_scanner(
    domain: str,
    check_spf: bool = True,
    check_dkim: bool = True,
    check_dmarc: bool = True,
    dkim_selector: Optional[str] = None,
    dkim_selectors: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Bridge function that uses scanner.py's DomainScanner class to verify domain DNS settings
    and returns results in the format expected by the existing API
    """
    try:
        # Initialize the domain scanner
        scanner = DomainScanner(domain)
        
        # If a specific DKIM selector was provided, we'll check it specifically
        specific_dkim_selector = None
        if dkim_selector and dkim_selector != "default":
            specific_dkim_selector = dkim_selector
        
        # Perform full domain scan
        scan_results = await scanner.scan_all()
        
        # If a specific selector was provided but not found in the automatic scan,
        # check it separately
        if check_dkim and specific_dkim_selector and scanner.detected_dkim_selector != specific_dkim_selector:
            dkim_result = await scanner.scan_dkim(specific_dkim_selector)
            
            # If we found a valid DKIM record with the specified selector, use that instead
            if dkim_result["status"] == "valid":
                scan_results["dkim"] = dkim_result
                scan_results["dkim_selector"] = specific_dkim_selector
        
        # If additional DKIM selectors were provided, check them too and use the best result
        if check_dkim and dkim_selectors and len(dkim_selectors) > 0:
            best_dkim_result = None
            
            for selector in dkim_selectors:
                # Skip if we already checked this selector
                if (specific_dkim_selector and selector == specific_dkim_selector) or \
                   (scanner.detected_dkim_selector and selector == scanner.detected_dkim_selector):
                    continue
                
                dkim_result = await scanner.scan_dkim(selector)
                
                # Keep track of the best result (valid > other statuses)
                if dkim_result["status"] == "valid":
                    best_dkim_result = dkim_result
                    break
                elif dkim_result["status"] != "missing" and not best_dkim_result:
                    best_dkim_result = dkim_result
            
            # Use the best result found if better than current
            if best_dkim_result and (
                "dkim" not in scan_results or 
                scan_results["dkim"]["status"] != "valid" or
                best_dkim_result["status"] == "valid"
            ):
                scan_results["dkim"] = best_dkim_result
                scan_results["dkim_selector"] = best_dkim_result.get("selector")
        
        # Transform scanner.py results to expected format
        transformed_results = {
            "domain": domain,
            "overall_status": _map_overall_status(scan_results.get("overall_status", {}).get("status", "poor")),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Process SPF results
        if check_spf and "spf" in scan_results:
            transformed_results["spf_analysis"] = {
                "record_type": "SPF",
                "status": _map_status(scan_results["spf"].get("status", "unknown")),
                "value": scan_results["spf"].get("value"),
                "issues": scan_results["spf"].get("issues", []),
                "recommendations": _generate_recommendations(scan_results["spf"].get("issues", []), "SPF"),
                "last_checked": datetime.utcnow().isoformat()
            }
        
        # Process DKIM results
        if check_dkim and "dkim" in scan_results:
            transformed_results["dkim_analysis"] = {
                "record_type": "DKIM",
                "status": _map_status(scan_results["dkim"].get("status", "unknown")),
                "value": scan_results["dkim"].get("value"),
                "selector": scan_results["dkim"].get("selector", "default"),
                "issues": scan_results["dkim"].get("issues", []),
                "recommendations": _generate_recommendations(scan_results["dkim"].get("issues", []), "DKIM"),
                "last_checked": datetime.utcnow().isoformat()
            }
        
        # Process DMARC results
        if check_dmarc and "dmarc" in scan_results:
            transformed_results["dmarc_analysis"] = {
                "record_type": "DMARC",
                "status": _map_status(scan_results["dmarc"].get("status", "unknown")),
                "value": scan_results["dmarc"].get("value"),
                "issues": scan_results["dmarc"].get("issues", []),
                "recommendations": _generate_recommendations(scan_results["dmarc"].get("issues", []), "DMARC"),
                "last_checked": datetime.utcnow().isoformat()
            }
        
        # Add email provider information if available
        if "email_provider" in scan_results:
            transformed_results["email_provider"] = scan_results["email_provider"]
        
        # Add MX records if available
        if "mx" in scan_results:
            transformed_results["mx_records"] = scan_results["mx"]
        
        return transformed_results
        
    except Exception as e:
        logger.error(f"Error in verify_domain_with_scanner: {str(e)}")
        # Return error response in expected format
        return {
            "domain": domain,
            "overall_status": "error",
            "error_message": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }

def _map_status(scanner_status: str) -> str:
    """Map scanner status values to the expected API response status values"""
    status_map = {
        "valid": "valid",
        "missing": "critical",
        "error": "warning",
        "unknown": "pending"
    }
    return status_map.get(scanner_status, "pending")

def _map_overall_status(scanner_overall: str) -> str:
    """Map scanner overall status to the expected API response overall status"""
    status_map = {
        "excellent": "healthy",
        "good": "healthy",
        "fair": "issues",
        "poor": "critical"
    }
    return status_map.get(scanner_overall, "issues")

def _generate_recommendations(issues: List[str], record_type: str) -> List[str]:
    """Generate recommendations based on detected issues"""
    recommendations = []
    
    if not issues:
        return recommendations
    
    # Generic recommendation maps for common issues
    spf_recommendations = {
        "Missing 'all' mechanism": 
            "Add an 'all' mechanism to the end of your SPF record (e.g., -all for strict, ~all for soft fail)",
        "Using '+all'": 
            "Replace '+all' with '-all' to prevent unauthorized servers from sending email as your domain",
        "SPF record has too many DNS lookups": 
            "Reduce the number of DNS lookups in your SPF record to 10 or fewer",
        "Using 'ptr' mechanism": 
            "Remove 'ptr' mechanisms from your SPF record and use 'ip4:' or 'ip6:' instead"
    }
    
    dkim_recommendations = {
        "Missing required 'v=DKIM1'": 
            "Ensure your DKIM record begins with 'v=DKIM1'",
        "Missing required 'p='": 
            "Add a public key to your DKIM record with the 'p=' tag",
        "Empty public key detected": 
            "Update your DKIM record with a valid public key",
        "DKIM is in testing mode": 
            "Remove the 't=y' flag from your DKIM record when ready for production"
    }
    
    dmarc_recommendations = {
        "Missing required 'p='": 
            "Add a policy tag (p=) to your DMARC record",
        "DMARC policy is set to 'none'": 
            "Consider upgrading your DMARC policy from 'none' to 'quarantine' or 'reject' after monitoring",
        "Missing 'rua='": 
            "Add an 'rua=' tag with an email address to receive aggregate reports",
        "Subdomain policy": 
            "Adjust your subdomain policy (sp=) to match your main domain policy for consistent protection"
    }
    
    # Select the appropriate recommendation map
    recommendation_map = {
        "SPF": spf_recommendations,
        "DKIM": dkim_recommendations,
        "DMARC": dmarc_recommendations
    }.get(record_type, {})
    
    # Generate recommendations based on issues
    for issue in issues:
        for issue_pattern, recommendation in recommendation_map.items():
            if issue_pattern in issue:
                recommendations.append(recommendation)
                break
        else:
            # If no specific recommendation found, add a generic one
            if "missing" in issue.lower():
                if record_type == "SPF":
                    recommendations.append("Create an SPF record for your domain")
                elif record_type == "DKIM":
                    recommendations.append("Set up DKIM for your domain")
                elif record_type == "DMARC":
                    recommendations.append("Create a DMARC record for your domain")
    
    return recommendations