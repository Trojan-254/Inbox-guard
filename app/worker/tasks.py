"""
Background tasks for the application
"""
import logging
from typing import Dict, Any

import asyncio
from celery import shared_task
from sqlalchemy.orm import Session

from app.db.database import SessionLocal
from app.services.dns.lookup import verify_domain_dns
from app.utils.validators import validate_domain, validate_email_selector

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def run_verification_task(
    self,
    user_id: int,
    domain: str,
    check_spf: bool = True,
    check_dkim: bool = True,
    check_dmarc: bool = True,
    email_selector: str = "_domainkey"
) -> Dict[str, Any]:
    """
    Background task to verify email DNS records for a domain for a specific user.

    Args:
        user_id: ID of the user who requested verification
        domain: Domain to verify
        check_spf: Whether to check SPF records
        check_dkim: Whether to check DKIM records
        check_dmarc: Whether to check DMARC records
        email_selector: DKIM selector to use

    Returns:
        Verification results
    """
    logger.info(f"Running background verification for domain {domain} (User ID: {user_id})")

    try:
        # Validate inputs
        domain = validate_domain(domain)
        email_selector = validate_email_selector(email_selector)

        # Run the DNS verification
        result = asyncio.run(
            verify_domain_dns(
                domain,
                check_spf=check_spf,
                check_dkim=check_dkim,
                check_dmarc=check_dmarc,
                email_selector=email_selector
            )
        )

        # Example: Save to database (with user ID)
        db: Session = SessionLocal()
        try:
            from app.models.domain_verification import DomainVerificationResult

            verification = DomainVerificationResult(
                user_id=user_id,
                domain=domain,
                overall_status=result["overall_status"],
                details=result["details"],  # Customize depending on your structure
            )
            db.add(verification)
            db.commit()
            db.refresh(verification)
        finally:
            db.close()

        logger.info(f"Background verification completed for {domain} (User ID: {user_id}): {result['overall_status']}")
        return result

    except Exception as exc:
        logger.exception(f"Error during background verification for {domain} (User ID: {user_id})")
        raise self.retry(exc=exc)


def run_scheduled_verification(
    user_id: int,
    domain: str,
    check_spf: bool = True,
    check_dkim: bool = True,
    check_dmarc: bool = True,
    email_selector: str = "_domainkey"
) -> None:
    """
    Trigger a scheduled verification via Celery for a specific user.

    Args:
        user_id: ID of the user who requested verification
        domain: Domain to verify
        check_spf: Whether to check SPF records
        check_dkim: Whether to check DKIM records
        check_dmarc: Whether to check DMARC records
        email_selector: DKIM selector to use
    """
    run_verification_task.delay(
        user_id,
        domain,
        check_spf,
        check_dkim,
        check_dmarc,
        email_selector
    )
