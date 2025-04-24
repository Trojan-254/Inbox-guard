"""
DNS verification endpoints
"""
import logging
from typing import Dict, List, Optional
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Path
from pydantic import BaseModel, EmailStr, HttpUrl

from app.services.dns.lookup import verify_domain_dns
from app.worker.tasks import run_scheduled_verification
from app.utils.validators import validate_domain

logger = logging.getLogger(__name__)
router = APIRouter()


class DomainVerificationRequest(BaseModel):
    """Request model for domain verification"""
    domain: str
    check_spf: bool = True
    check_dkim: bool = True
    check_dmarc: bool = True
    email_selector: Optional[str] = "_domainkey"


class RecordAnalysis(BaseModel):
    """Analysis results for a single DNS record"""
    record_type: str
    status: str  # "valid", "invalid", "missing", "warning"
    value: Optional[str] = None
    issues: List[str] = []
    recommendations: List[str] = []


class DomainVerificationResponse(BaseModel):
    """Response model for domain verification results"""
    domain: str
    overall_status: str  # "healthy", "issues", "critical"
    spf_analysis: Optional[RecordAnalysis] = None
    dkim_analysis: Optional[RecordAnalysis] = None
    dmarc_analysis: Optional[RecordAnalysis] = None
    timestamp: str


@router.post("/verify", response_model=DomainVerificationResponse)
async def verify_domain(
    domain_request: DomainVerificationRequest,
    background_tasks: BackgroundTasks
):
    """Verify SPF, DKIM, and DMARC records for a domain"""
    domain = domain_request.domain
    
    try:
        # Validate domain
        validated_domain = validate_domain(domain)
        
        # Process the verification in the request context
        verification_result = await verify_domain_dns(
            validated_domain,
            check_spf=domain_request.check_spf,
            check_dkim=domain_request.check_dkim,
            check_dmarc=domain_request.check_dmarc,
            email_selector=domain_request.email_selector
        )
        
        # Schedule a follow-up check in the background for metrics collection
        background_tasks.add_task(
            run_scheduled_verification,
            validated_domain,
            domain_request.check_spf,
            domain_request.check_dkim,
            domain_request.check_dmarc,
            domain_request.email_selector
        )
        
        return verification_result
    
    except ValueError as e:
        logger.error(f"Domain validation error: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception(f"Error verifying domain {domain}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error during domain verification")


@router.get("/history/{domain}", response_model=List[DomainVerificationResponse])
async def get_domain_history(
    domain: str = Path(..., description="Domain to retrieve verification history for"),
    limit: int = Query(10, ge=1, le=100, description="Number of history records to return")
):
    """Get verification history for a domain"""
    try:
        # Validate domain
        validated_domain = validate_domain(domain)
        
        # This is a placeholder - in a real implementation, you would retrieve from a database
        # For now, we'll return an empty list
        return []
    
    except ValueError as e:
        logger.error(f"Domain validation error: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception(f"Error retrieving history for domain {domain}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error retrieving domain history")