"""
DNS verification endpoints with database integration
"""
import logging
from typing import Dict, List, Optional
from datetime import datetime
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Path, Depends
from pydantic import BaseModel, EmailStr, HttpUrl
from sqlalchemy.orm import Session

from app.services.dns.lookup import verify_domain_dns
from app.worker.tasks import run_scheduled_verification
from app.utils.validators import validate_domain
from app.db.session import get_db
from app.models.user import User
from app.models.domain import Domain
from app.models.dns_record import DNSRecord, RecordType, RecordStatus
from app.crud.domain import create_domain, get_domain_by_id, get_domain_by_name, update_domain_last_checked
from app.crud.dns_record import create_or_update_dns_record, get_domain_dns_records
from app.crud.audit_log import create_audit_log
from app.api.deps import get_current_user

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
    status: str  # "valid", "warning", "critical", "pending"
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
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Verify SPF, DKIM, and DMARC records for a domain and save results to the database"""
    domain_name = domain_request.domain
    
    try:
        # Validate domain
        validated_domain = validate_domain(domain_name)
        
        # Check if domain exists in database, if not create it
        domain_db = get_domain_by_name(db, domain_name=validated_domain, user_id=current_user.id)
        if not domain_db:
            domain_db = create_domain(db, user_id=current_user.id, domain_name=validated_domain)
            
            # Create audit log for domain creation
            create_audit_log(
                db, 
                current_user.id, 
                "domain_created", 
                {"domain_id": domain_db.id, "domain_name": validated_domain}
            )
        
        # Process the verification in the request context
        verification_result = await verify_domain_dns(
            validated_domain,
            check_spf=domain_request.check_spf,
            check_dkim=domain_request.check_dkim,
            check_dmarc=domain_request.check_dmarc,
            email_selector=domain_request.email_selector
        )
        
        # Update domain last checked timestamp
        update_domain_last_checked(db, domain_db.id)
        
        # Store DNS record results in database
        if domain_request.check_spf and verification_result.spf_analysis:
            create_or_update_dns_record(
                db,
                domain_id=domain_db.id,
                record_type=RecordType.SPF,
                status=parse_status(verification_result.spf_analysis.status),
                record_value=verification_result.spf_analysis.value
            )
        
        if domain_request.check_dkim and verification_result.dkim_analysis:
            create_or_update_dns_record(
                db,
                domain_id=domain_db.id,
                record_type=RecordType.DKIM,
                status=parse_status(verification_result.dkim_analysis.status),
                record_value=verification_result.dkim_analysis.value
            )
        
        if domain_request.check_dmarc and verification_result.dmarc_analysis:
            create_or_update_dns_record(
                db,
                domain_id=domain_db.id,
                record_type=RecordType.DMARC,
                status=parse_status(verification_result.dmarc_analysis.status),
                record_value=verification_result.dmarc_analysis.value
            )
        
        # Create audit log for domain verification
        create_audit_log(
            db, 
            current_user.id, 
            "domain_verified", 
            {
                "domain_id": domain_db.id, 
                "domain_name": validated_domain,
                "overall_status": verification_result.overall_status
            }
        )
        
        # Schedule a follow-up check in the background for metrics collection
        background_tasks.add_task(
            run_scheduled_verification,
            validated_domain,
            domain_request.check_spf,
            domain_request.check_dkim,
            domain_request.check_dmarc,
            domain_request.email_selector,
            current_user.id  # Pass user_id to the background task
        )
        
        return verification_result
    
    except ValueError as e:
        logger.error(f"Domain validation error: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception(f"Error verifying domain {domain_name}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error during domain verification")


@router.get("/history/{domain}", response_model=List[DomainVerificationResponse])
async def get_domain_history(
    domain: str = Path(..., description="Domain to retrieve verification history for"),
    limit: int = Query(10, ge=1, le=100, description="Number of history records to return"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get verification history for a domain from the database"""
    try:
        # Validate domain
        validated_domain = validate_domain(domain)
        
        # Find domain in database
        domain_db = get_domain_by_name(db, domain_name=validated_domain, user_id=current_user.id)
        if not domain_db:
            return []
        
        # Get DNS records for domain
        records = get_domain_dns_records(db, domain_id=domain_db.id, limit=limit)
        
        # Group records by timestamp to construct verification responses
        # This is a simplification - in a real implementation you'd have a dedicated table for verification history
        history_records = {}
        for record in records:
            timestamp = record.last_checked.isoformat()
            if timestamp not in history_records:
                history_records[timestamp] = {
                    "domain": validated_domain,
                    "overall_status": "pending",
                    "timestamp": timestamp
                }
            
            # Add record analysis
            record_analysis = RecordAnalysis(
                record_type=record.type.value,
                status=record.status.value,
                value=record.record_value,
                issues=[],  # These would need to be stored in the database
                recommendations=[]  # These would need to be stored in the database
            )
            
            if record.type == RecordType.SPF:
                history_records[timestamp]["spf_analysis"] = record_analysis
            elif record.type == RecordType.DKIM:
                history_records[timestamp]["dkim_analysis"] = record_analysis
            elif record.type == RecordType.DMARC:
                history_records[timestamp]["dmarc_analysis"] = record_analysis
            
            # Determine overall status (worst of any record)
            if record.status == RecordStatus.CRITICAL:
                history_records[timestamp]["overall_status"] = "critical"
            elif record.status == RecordStatus.WARNING and history_records[timestamp]["overall_status"] != "critical":
                history_records[timestamp]["overall_status"] = "issues"
            elif record.status == RecordStatus.VALID and history_records[timestamp]["overall_status"] == "pending":
                history_records[timestamp]["overall_status"] = "healthy"
        
        # Convert to list of verification responses
        result = [DomainVerificationResponse(**record) for record in history_records.values()]
        result.sort(key=lambda x: x.timestamp, reverse=True)  # Sort by timestamp, newest first
        
        return result[:limit]  # Apply limit
    
    except ValueError as e:
        logger.error(f"Domain validation error: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception(f"Error retrieving history for domain {domain}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error retrieving domain history")


@router.get("/domains", response_model=List[Dict])
async def get_user_domains(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all domains for the current user with their latest verification status"""
    from app.crud.domain import get_user_domains
    
    domains = get_user_domains(db, user_id=current_user.id)
    results = []
    
    for domain in domains:
        # Get the latest record for each type
        records = get_domain_dns_records(db, domain_id=domain.id, limit=3)  # Limit to 3 (SPF, DKIM, DMARC)
        
        spf_record = next((r for r in records if r.type == RecordType.SPF), None)
        dkim_record = next((r for r in records if r.type == RecordType.DKIM), None)
        dmarc_record = next((r for r in records if r.type == RecordType.DMARC), None)
        
        # Determine overall status
        overall_status = "pending"
        if any(r for r in records if r.status == RecordStatus.CRITICAL):
            overall_status = "critical"
        elif any(r for r in records if r.status == RecordStatus.WARNING):
            overall_status = "issues"
        elif all(r.status == RecordStatus.VALID for r in records if r):
            overall_status = "healthy"
        
        results.append({
            "id": domain.id,
            "domain": domain.domain_name,
            "created_at": domain.created_at.isoformat(),
            "last_checked": domain.last_checked.isoformat() if domain.last_checked else None,
            "overall_status": overall_status,
            "spf_status": spf_record.status.value if spf_record else "pending",
            "dkim_status": dkim_record.status.value if dkim_record else "pending",
            "dmarc_status": dmarc_record.status.value if dmarc_record else "pending",
        })
    
    return results


# Helper function to parse status string to enum
def parse_status(status: str) -> RecordStatus:
    """Parse status string to RecordStatus enum"""
    if status == "valid":
        return RecordStatus.VALID
    elif status == "warning":
        return RecordStatus.WARNING
    elif status == "critical" or status == "invalid" or status == "missing":
        return RecordStatus.CRITICAL
    else:
        return RecordStatus.PENDING