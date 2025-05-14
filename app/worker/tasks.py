"""
Background tasks for the application
"""
import logging
from typing import Dict, Any

import asyncio
from celery import shared_task
from sqlalchemy.orm import Session

from . import celery_app

from app.db.database import SessionLocal
from app.services.dns.lookup import verify_domain_dns
from app.utils.validators import validate_domain, validate_email_selector
from app.core.config import settings
from app.db.models import RecordType, RecordStatus
from app.services.dns.scanner import DomainScanner
from app.users.crud import (
    get_domain_by_id,
    update_domain_last_checked,
    create_or_update_dns_record
)

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


async def run_scheduled_verification(
    job_id: str,
    domain: str,
    check_spf: bool = True,
    check_dkim: bool = True,
    check_dmarc: bool = True,
    dkim_selector: str = "default",
    user_id: int = None,
    dkim_selectors: list = None
) -> None:
    """
    Run a DNS verification job for a domain.
    This function is designed to be run as a background task.

    Args:
        job_id: ID of the scan job
        domain: Domain to verify
        check_spf: Whether to check SPF records
        check_dkim: Whether to check DKIM records
        check_dmarc: Whether to check DMARC records
        dkim_selector: DKIM selector to use
        user_id: ID of the user who requested verification
        dkim_selectors: List of DKIM selectors to try
    """
    from app.db.redis_client import redis_client
    import json
    from app.db.database import get_db
    from app.services.dns.scanner_bridge import verify_domain_with_scanner
    from app.users.crud import (
        update_job_status,
        get_domain_by_name, 
        update_domain_last_checked,
        create_or_update_dns_record
    )
    from app.db.models import RecordType, RecordStatus

    try:
        # Get database session
        db = next(get_db())
        
        # Update status to processing
        job_status = {
            "status": "processing", 
            "progress": 10, 
            "message": "Starting DNS verification"
        }
        redis_client.set(f"job_status:{job_id}", json.dumps(job_status), ex=3600)
        
        # Update job status in database
        update_job_status(
            db, 
            job_id=job_id, 
            status="processing", 
            progress=10, 
            message="Starting DNS verification"
        )
        
        # Initialize DKIM selectors list if needed
        if dkim_selectors is None:
            dkim_selectors = [dkim_selector] if dkim_selector and dkim_selector != "default" else []
            
            # Add common selectors for the domain if using scanner.py
            from app.services.dns.scanner import DomainScanner
            # Look for matches in known providers
            for provider_domain, provider_selectors in DomainScanner.COMMON_SELECTORS.items():
                if provider_domain != "generic" and domain.lower().endswith(provider_domain):
                    # Add all selectors for this provider
                    dkim_selectors.extend([s for s in provider_selectors if s not in dkim_selectors])
                    break
        
        # Update status to checking DNS
        job_status = {
            "status": "processing", 
            "progress": 30, 
            "message": "Checking DNS records"
        }
        redis_client.set(f"job_status:{job_id}", json.dumps(job_status), ex=3600)
        update_job_status(
            db, 
            job_id=job_id, 
            status="processing", 
            progress=30, 
            message="Checking DNS records"
        )
        
        # Run verification using scanner bridge
        logger.info(f"Starting DNS verification for domain {domain} with job ID {job_id}")
        results = await verify_domain_with_scanner(
            domain=domain,
            check_spf=check_spf,
            check_dkim=check_dkim,
            check_dmarc=check_dmarc,
            dkim_selector=dkim_selector,
            dkim_selectors=dkim_selectors
        )
        
        # Update status to processing results
        job_status = {
            "status": "processing", 
            "progress": 70, 
            "message": "Processing verification results"
        }
        redis_client.set(f"job_status:{job_id}", json.dumps(job_status), ex=3600)
        update_job_status(
            db, 
            job_id=job_id, 
            status="processing", 
            progress=70, 
            message="Processing verification results"
        )
        
        # Get domain from database
        domain_db = get_domain_by_name(db, domain_name=domain, user_id=user_id)
        if domain_db:
            # Update domain last checked time
            update_domain_last_checked(db, domain_id=domain_db.id)
            
            # Save DNS records to database
            if check_spf and "spf_analysis" in results:
                spf_data = results["spf_analysis"]
                create_or_update_dns_record(
                    db,
                    domain_id=domain_db.id,
                    record_type=RecordType.SPF,
                    status=parse_status(spf_data["status"]),
                    record_value=spf_data.get("value"),
                    issues=spf_data.get("issues", []),
                    recommendations=spf_data.get("recommendations", [])
                )
                
            if check_dkim and "dkim_analysis" in results:
                dkim_data = results["dkim_analysis"]
                create_or_update_dns_record(
                    db,
                    domain_id=domain_db.id,
                    record_type=RecordType.DKIM,
                    status=parse_status(dkim_data["status"]),
                    record_value=dkim_data.get("value"),
                    issues=dkim_data.get("issues", []),
                    recommendations=dkim_data.get("recommendations", []),
                    selector=dkim_data.get("selector", "default")
                )
                
            if check_dmarc and "dmarc_analysis" in results:
                dmarc_data = results["dmarc_analysis"]
                create_or_update_dns_record(
                    db,
                    domain_id=domain_db.id,
                    record_type=RecordType.DMARC,
                    status=parse_status(dmarc_data["status"]),
                    record_value=dmarc_data.get("value"),
                    issues=dmarc_data.get("issues", []),
                    recommendations=dmarc_data.get("recommendations", [])
                )
        
        # Update job status to completed
        job_status = {
            "status": "completed", 
            "progress": 100, 
            "message": "DNS verification completed successfully"
        }
        redis_client.set(f"job_status:{job_id}", json.dumps(job_status), ex=3600)
        redis_client.set(f"job_results:{job_id}", json.dumps(results), ex=3600)
        
        update_job_status(
            db, 
            job_id=job_id, 
            status="completed", 
            progress=100, 
            message="DNS verification completed successfully",
            results=results
        )
        
        # Store in history
        if domain_db:
            history_key = f"domain_history:{domain_db.id}"
            redis_client.lpush(history_key, json.dumps(results))
            redis_client.ltrim(history_key, 0, 99)  # Keep last 100 records
            
        logger.info(f"Completed DNS verification for domain {domain} with job ID {job_id}")
            
    except Exception as e:
        logger.error(f"Error in verification job {job_id} for domain {domain}: {str(e)}")
        
        # Update job status to failed
        error_message = f"DNS verification failed: {str(e)}"
        job_status = {
            "status": "failed", 
            "progress": 0, 
            "message": error_message
        }
        
        try:
            redis_client.set(f"job_status:{job_id}", json.dumps(job_status), ex=3600)
            
            # Update database
            db = next(get_db())
            update_job_status(
                db, 
                job_id=job_id, 
                status="failed", 
                progress=0, 
                message=error_message
            )
        except Exception as inner_error:
            logger.error(f"Failed to update error status: {str(inner_error)}")

# Helper function to parse status
def parse_status(status_str: str) -> RecordStatus:
    """Convert status string to RecordStatus enum"""
    status_map = {
        "valid": RecordStatus.VALID,
        "warning": RecordStatus.WARNING,
        "critical": RecordStatus.CRITICAL,
        "pending": RecordStatus.PENDING
    }
    return status_map.get(status_str.lower(), RecordStatus.PENDING)

async def scan_domain_task(self, domain_id: int):
    """
    Celery task to scan a domain for email deliverability
    This runs asynchronously to prevent blocking the API
    """
    # Task updates
    self.update_state(state=states.STARTED, meta={'current_step': 'Starting scan'})
    
    try:
        # Get database session
        db = SessionLocal()
        
        # Get domain from database
        domain = get_domain_by_id(db, domain_id)
        if not domain:
            self.update_state(
                state=states.FAILURE,
                meta={'error': f'Domain with ID {domain_id} not found'}
            )
            raise Ignore()
        
        # Initialize scanner
        scanner = DomainScanner(domain.domain_name)
        
        # Override status update method to update Celery task state
        def update_task_status(message):
            self.update_state(
                state=states.STARTED,
                meta={'current_step': message}
            )
        
        # Attach status update method to scanner
        scanner.update_status = update_task_status
        
        # Run the scan
        results = await scanner.scan_all()
        
        # Update domain record with detected information
        if 'email_provider' in results and results['email_provider']:
            domain.email_provider = results['email_provider']
        
        if 'dkim_selector' in results and results['dkim_selector']:
            domain.dkim_selector = results['dkim_selector']
        
        # Update last checked timestamp
        update_domain_last_checked(db, domain_id)
        
        # Save DNS records to database
        if 'spf' in results and results['spf']:
            status = RecordStatus.ERROR if results['spf'].get('issues') else RecordStatus.VALID
            value = results['spf'].get('value', '')
            create_or_update_dns_record(
                db, domain_id, RecordType.SPF, status, value
            )
        
        if 'dkim' in results and results['dkim']:
            status = RecordStatus.ERROR if results['dkim'].get('issues') else RecordStatus.VALID
            value = results['dkim'].get('value', '')
            create_or_update_dns_record(
                db, domain_id, RecordType.DKIM, status, value
            )
        
        if 'dmarc' in results and results['dmarc']:
            status = RecordStatus.ERROR if results['dmarc'].get('issues') else RecordStatus.VALID
            value = results['dmarc'].get('value', '')
            create_or_update_dns_record(
                db, domain_id, RecordType.DMARC, status, value
            )
        
        # Save MX records
        if 'mx' in results and results['mx']:
            for mx_record in results['mx']:
                create_or_update_dns_record(
                    db, domain_id, RecordType.MX, RecordStatus.VALID, mx_record['value']
                )
        
        # Commit changes
        db.commit()
        
        # Close database connection
        db.close()
        
        # Return results
        return results
        
    except Exception as e:
        logger.exception(f"Error during domain scan: {str(e)}")
        if 'db' in locals() and db:
            db.close()
        
        self.update_state(
            state=states.FAILURE,
            meta={'error': str(e)}
        )
        raise Ignore()


@shared_task(bind=True)
def scheduled_domain_monitoring():
    """
    Periodic task to monitor domains for paid tiers
    Checks for changes in DNS records and sends alerts
    """
    try:
        # Get database session
        db = SessionLocal()
        
        # Get domains configured for monitoring (premium/standard tiers)
        # Implement this function to get domains for monitoring
        domains_to_monitor = get_domains_for_monitoring(db)
        
        for domain in domains_to_monitor:
            # Queue individual scan task for each domain
            scan_domain_task.delay(domain.id)
        
        db.close()
        
    except Exception as e:
        logger.exception(f"Error in scheduled monitoring: {str(e)}")
        if 'db' in locals() and db:
            db.close()

# Helper function to get domains for monitoring
def get_domains_for_monitoring(db: Session):
    """Get domains configured for monitoring (paid tiers)"""
    # This is a placeholder - implement based on your user tier model
    return []
