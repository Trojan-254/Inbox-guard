"""
Background tasks for the application
"""
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from celery import shared_task

from app.services.dns.lookup import verify_domain_dns
from app.utils.validators import validate_domain, validate_email_selector
from app.worker.celery_app import celery_app

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def run_verification_task(
    self,
    domain: str,
    check_spf: bool = True,
    check_dkim: bool = True,
    check_dmarc: bool = True,
    email_selector: str = "_domainkey"
) -> Dict[str, Any]:
    """
    Background task to verify email DNS records for a domain
    
    Args:
        domain: Domain to verify
        check_spf: Whether to check SPF records
        check_dkim: Whether to check DKIM records
        check_dmarc: Whether to check DMARC records
        email_selector: DKIM selector to use
        
    Returns:
        Verification results
    """
    logger.info(f"Running background verification for domain {domain}")
    
    try:
        # Validate inputs
        domain = validate_domain(domain)
        email_selector = validate_email_selector(email_selector)
        
        # Run the verification
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(
                verify_domain_dns(
                    domain,
                    check_spf=check_spf,
                    check_dkim=check_dkim,
                    check_dmarc=check_dmarc,
                    email_selector=email_selector
                )
            )
        finally:
            loop.close()
        
        # Here you would typically save the result to a database
        # For now we just log it
        logger.info(f"Background verification completed for {domain}: {result['overall_status']}")
        
        return result
    
    except Exception as exc:
        logger.exception(f"Error in background verification for {domain}")
        raise self.retry(exc=exc)


# Function to trigger the background task from API
def run_scheduled_verification(
    domain: str,
    check_spf: bool = True,
    check_dkim: bool = True,
    check_dmarc: bool = True,
    email_selector: str = "_domainkey"
) -> None:
    """
    Trigger a scheduled verification in the background
    
    Args:
        domain: Domain to verify
        check_spf: Whether to check SPF records
        check_dkim: Whether to check DKIM records
        check_dmarc: Whether to check DMARC records
        email_selector: DKIM selector to use
    """
    run_verification_task.delay(
        domain=domain,
        check_spf=check_spf,
        check_dkim=check_dkim,
        check_dmarc=check_dmarc,
        email_selector=email_selector
    )