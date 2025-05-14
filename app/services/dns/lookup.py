"""
DNS lookup service for verifying email DNS records
"""
import logging
import asyncio
import time
import dns.resolver
import dns.exception
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

from app.core.config import settings
from app.core.exceptions import DNSLookupError
from app.services.dns.spf import analyze_spf_record
from app.services.dns.dkim import analyze_dkim_record
from app.services.dns.dmarc import analyze_dmarc_record

logger = logging.getLogger(__name__)

# Create a resolver with custom settings
resolver = dns.resolver.Resolver()
resolver.timeout = settings.DNS_RESOLVER_TIMEOUT
resolver.lifetime = settings.DNS_RESOLVER_LIFETIME


async def verify_domain_dns(
    domain: str,
    check_spf: bool = True,
    check_dkim: bool = True,
    check_dmarc: bool = True,
    email_selector: str = "_domainkey"
) -> Dict[str, Any]:
    """
    Verify SPF, DKIM, and DMARC records for a domain
    
    Args:
        domain: Domain to verify
        check_spf: Whether to check SPF records
        check_dkim: Whether to check DKIM records
        check_dmarc: Whether to check DMARC records
        email_selector: DKIM selector to use
        
    Returns:
        Dict containing verification results
    """
    result = {
        "domain": domain,
        "overall_status": "healthy",  # Default status
        "timestamp": datetime.utcnow().isoformat()
    }
    
    # Create tasks for each record type to check
    tasks = []
    
    if check_spf:
        tasks.append(lookup_and_analyze_spf(domain))
    
    if check_dkim:
        tasks.append(lookup_and_analyze_dkim(domain, email_selector))
    
    if check_dmarc:
        tasks.append(lookup_and_analyze_dmarc(domain))
    
    # Run all tasks concurrently
    spf_result, dkim_result, dmarc_result = None, None, None
    
    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        index = 0
        if check_spf:
            spf_result = results[index]
            index += 1
        
        if check_dkim:
            dkim_result = results[index]
            index += 1
        
        if check_dmarc:
            dmarc_result = results[index]
    
    # Add results to response
    if check_spf:
        if isinstance(spf_result, Exception):
            logger.error(f"Error analyzing SPF for {domain}: {str(spf_result)}")
            result["spf_analysis"] = {
                "record_type": "SPF",
                "status": "error",
                "issues": [f"Error analyzing SPF: {str(spf_result)}"],
                "recommendations": ["Check DNS configuration or try again later"]
            }
            result["overall_status"] = "issues"
        else:
            result["spf_analysis"] = spf_result
            # Update overall status if needed
            if spf_result["status"] in ["invalid", "missing"]:
                result["overall_status"] = "critical"
            elif spf_result["status"] == "warning" and result["overall_status"] == "healthy":
                result["overall_status"] = "issues"
    
    if check_dkim:
        if isinstance(dkim_result, Exception):
            logger.error(f"Error analyzing DKIM for {domain}: {str(dkim_result)}")
            result["dkim_analysis"] = {
                "record_type": "DKIM",
                "status": "error",
                "issues": [f"Error analyzing DKIM: {str(dkim_result)}"],
                "recommendations": ["Check DNS configuration or try again later"]
            }
            result["overall_status"] = "issues"
        else:
            result["dkim_analysis"] = dkim_result
            # Update overall status if needed
            if dkim_result["status"] in ["invalid", "missing"]:
                result["overall_status"] = "critical"
            elif dkim_result["status"] == "warning" and result["overall_status"] == "healthy":
                result["overall_status"] = "issues"
    
    if check_dmarc:
        if isinstance(dmarc_result, Exception):
            logger.error(f"Error analyzing DMARC for {domain}: {str(dmarc_result)}")
            result["dmarc_analysis"] = {
                "record_type": "DMARC",
                "status": "error",
                "issues": [f"Error analyzing DMARC: {str(dmarc_result)}"],
                "recommendations": ["Check DNS configuration or try again later"]
            }
            result["overall_status"] = "issues"
        else:
            result["dmarc_analysis"] = dmarc_result
            # Update overall status if needed
            if dmarc_result["status"] in ["invalid", "missing"]:
                result["overall_status"] = "critical"
            elif dmarc_result["status"] == "warning" and result["overall_status"] == "healthy":
                result["overall_status"] = "issues"
    
    return result


async def lookup_and_analyze_spf(domain: str) -> Dict[str, Any]:
    """Lookup and analyze SPF record for a domain"""
    try:
        spf_record = await lookup_txt_record(domain)
        spf_entries = [record for record in spf_record if record.startswith("v=spf1")]
        
        if not spf_entries:
            return {
                "record_type": "SPF",
                "status": "missing",
                "value": None,
                "issues": ["No SPF record found"],
                "recommendations": [
                    "Create an SPF record with your authorized email servers",
                    "Example: v=spf1 include:_spf.google.com ~all"
                ]
            }
        
        # Use the first SPF record found
        spf_value = spf_entries[0]
        return analyze_spf_record(spf_value)
    
    except Exception as e:
        logger.exception(f"Error looking up SPF record for {domain}: {str(e)}")
        raise DNSLookupError(f"Error looking up SPF record: {str(e)}")


async def lookup_and_analyze_dkim(domain: str, selector: str = "_domainkey") -> Dict[str, Any]:
    """Lookup and analyze DKIM record for a domain"""
    try:
        dkim_domain = f"{selector}.{domain}"
        dkim_record = await lookup_txt_record(dkim_domain)
        
        if not dkim_record:
            return {
                "record_type": "DKIM",
                "status": "missing",
                "value": None,
                "issues": [f"No DKIM record found for selector '{selector}'"],
                "recommendations": [
                    "Configure DKIM for your domain with your email provider",
                    f"Create a TXT record for {selector}.{domain}"
                ]
            }
        
        # Use the first DKIM record found (there should only be one)
        dkim_value = dkim_record[0]
        return analyze_dkim_record(dkim_value, selector)
    
    except Exception as e:
        logger.exception(f"Error looking up DKIM record for {domain} with selector {selector}: {str(e)}")
        raise DNSLookupError(f"Error looking up DKIM record: {str(e)}")


async def lookup_and_analyze_dmarc(domain: str) -> Dict[str, Any]:
    """Lookup and analyze DMARC record for a domain"""
    try:
        dmarc_domain = f"_dmarc.{domain}"
        dmarc_record = await lookup_txt_record(dmarc_domain)
        
        if not dmarc_record:
            return {
                "record_type": "DMARC",
                "status": "missing",
                "value": None,
                "issues": ["No DMARC record found"],
                "recommendations": [
                    "Create a DMARC record to protect your domain from spoofing",
                    "Example: v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com"
                ]
            }
        
        # Use the first DMARC record found (there should only be one)
        dmarc_value = dmarc_record[0]
        return analyze_dmarc_record(dmarc_value)
    
    except Exception as e:
        logger.exception(f"Error looking up DMARC record for {domain}: {str(e)}")
        raise DNSLookupError(f"Error looking up DMARC record: {str(e)}")


async def lookup_txt_record(domain: str) -> List[str]:
    """
    Lookup TXT records for a domain
    
    Args:
        domain: Domain to lookup
        
    Returns:
        List of TXT records found
    """
    try:
        # Use asyncio to make the DNS request non-blocking
        loop = asyncio.get_event_loop()
        txt_records = await loop.run_in_executor(
            None,
            lambda: resolver.resolve(domain, 'TXT')
        )

        print("TXT record captured", txt_records)
        
        # Extract the strings from the TXT records
        return [txt_record.to_text().strip('"') for txt_record in txt_records]
    
    except dns.resolver.NXDOMAIN:
        logger.info(f"No TXT records found for {domain}")
        return []
    except dns.resolver.NoAnswer:
        logger.info(f"No TXT records found for {domain}")
        return []
    except dns.exception.DNSException as e:
        logger.error(f"DNS error looking up TXT record for {domain}: {str(e)}")
        raise DNSLookupError(f"DNS error: {str(e)}")
    except Exception as e:
        logger.exception(f"Error looking up TXT record for {domain}: {str(e)}")
        raise DNSLookupError(f"Error: {str(e)}")


async def check_dns_resolver_health() -> bool:
    """
    Check if the DNS resolver is working properly by querying a known domain
    
    Returns:
        True if healthy, False otherwise
    """
    try:
        # Try to lookup a TXT record for google.com (which should always exist)
        test_records = await lookup_txt_record("google.com")
        return len(test_records) > 0
    except Exception as e:
        logger.error(f"DNS resolver health check failed: {str(e)}")
        return False
