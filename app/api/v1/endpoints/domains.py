"""
DNS verification endpoints with database integration
and background processing
"""
import logging
import uuid
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Path, Depends
from pydantic import BaseModel, EmailStr, HttpUrl, Field, ValidationError
from sqlalchemy.orm import Session
from fastapi.responses import JSONResponse

from app.services.dns.scanner import DomainScanner
from app.services.dns.lookup import verify_domain_dns
from app.worker.tasks import run_scheduled_verification
from app.utils.validators import validate_domain, extract_original_input
from app.db.database import get_db
from app.db.models import User, Domain, ScanJob, JobStatus
from app.db.models import DNSRecord, RecordType, RecordStatus
from app.users.crud import create_domain, get_domain_by_id, get_domain_by_name, update_domain_last_checked
from app.users.crud import create_or_update_dns_record, get_domain_dns_records
from app.users.crud import create_audit_log
from app.users.crud import create_scan_job, get_scan_job, update_job_status
from .auth import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter()

from app.db.redis_client import redis_client

class RecordAnalysis(BaseModel):
    """Analysis results for a single DNS record"""
    record_type: str
    status: str  # "valid", "warning", "critical", "pending"
    value: Optional[str] = None
    issues: List[str] = []
    recommendations: List[str] = []
    last_checked: Optional[datetime] = None


class DomainVerificationRequest(BaseModel):
    """Request model for domain verification"""
    domain: str
    check_spf: bool = True
    check_dkim: bool = True
    check_dmarc: bool = True
    dkim_selector: str = "default"

class DomainVerificationResponse(BaseModel):
    """Response model for domain verification results"""
    domain: str
    overall_status: str  # "healthy", "issues", "critical"
    spf_analysis: Optional[RecordAnalysis] = None
    dkim_analysis: Optional[RecordAnalysis] = None
    dmarc_analysis: Optional[RecordAnalysis] = None
    timestamp: str


class DomainAddRequest(BaseModel):
    """Request model for adding a domain or email"""
    domain_or_email: str = Field(..., description="Domain name (e.g. example.com) or email address (e.g. noreply@example.com)")
    notes: Optional[str] = Field(None, description="Optional notes about this domain")

class DomainAddResponse(BaseModel):
    """Response model for domain addition"""
    domain: str
    original_input: str
    input_type: str
    id: int
    success: bool
    message: str
    email_prefix: Optional[str] = None


class BulkDomainAddRequest(BaseModel):
    """Request model for adding multiple domains"""
    domains_or_emails: List[str]
    notes: Optional[str] = None


class BulkDomainAddResponse(BaseModel):
    """Response model for bulk domain addition"""
    results: List[DomainAddResponse]
    success_count: int
    failure_count: int

class DomainDeleteRequest(BaseModel):
    """Request model for deleting a domain"""
    domain: str
    notes: Optional[str] = Field(None, description="Optional notes about this domain deletion")

class DomainDeleteResponse(BaseModel):
    """Response model for domain deletion"""
    domain: str
    success: bool
    message: str


class DomainModel(BaseModel):
    """Model for domain creation with additional metadata"""
    domain_name: str
    original_input: str
    input_type: str
    email_prefix: Optional[str] = None
    notes: Optional[str] = None

class DnsRecommendation(BaseModel):
    """Model for DNS record recommendations"""
    record_type: str
    current_value: Optional[str] = None
    issues: List[str]
    recommendations: List[str] = []
    recommendation_value: str

class DnsRecommendationResponse(BaseModel):
    """Response model for DNS record recommendations"""
    domain: str
    spf_recommendation: Optional[DnsRecommendation] = None
    dkim_recommendation: Optional[DnsRecommendation] = None
    dmarc_recommendation: Optional[DnsRecommendation] = None


class ScanJobRequest(BaseModel):
    """request model for scan job creation"""
    domain: str
    check_spf: bool = True
    check_dkim: bool = True
    check_dmarc: bool = True
    dkim_selector: str = "default"

class ScanJobResponse(BaseModel):
    """response model for scan job creation"""
    job_id: str
    status: str  # "pending", "in_progress", "completed", "failed"
    domain: str
    created_at: str
    updated_at: str
    message: Optional[str] = None

class JobStatusResponse(BaseModel):
    """Response model for job status check"""
    job_id: str
    status: str
    progress: int
    message: Optional[str] = None
    results: Optional[DomainVerificationResponse] = None

"""Helper functions"""
# Add these helper functions before the endpoints

def generate_spf_recommendations(domain: str, result: Dict) -> List[str]:
    """Generate recommendations for improving SPF records"""
    recommendations = []
    status = result.get("status", "unknown")
    issues = result.get("issues", [])
    value = result.get("value", "")
    
    if status == "missing":
        recommendations.append(f"Add an SPF record with: v=spf1 include:_spf.{domain} ~all")
        recommendations.append("This basic SPF record will help protect your domain from being spoofed.")
        return recommendations
    
    if not value:
        return recommendations
    
    # Check for common issues and provide recommendations
    if "No mechanism found" in str(issues):
        recommendations.append("Your SPF record should include email sending sources.")
        recommendations.append(f"Consider adding: v=spf1 include:_spf.{domain} ~all")
    
    if "Missing ~all or -all" in str(issues) or "SPF record too permissive" in str(issues):
        recommendations.append("Your SPF record should end with ~all (soft fail) or -all (hard fail) to properly protect against spoofing.")
    
    if "Multiple SPF records" in str(issues):
        recommendations.append("Consolidate multiple SPF records into a single record to avoid conflicts.")
    
    if "SPF record too long" in str(issues) or "lookup limit" in str(issues).lower():
        recommendations.append("Your SPF record has too many lookups. Simplify by consolidating includes or using a flattening service.")
    
    # If no specific recommendations were generated but there are issues
    if not recommendations and issues:
        recommendations.append("Review your SPF record for syntax errors and missing mechanisms.")
        
    return recommendations


def generate_dkim_recommendations(domain: str, result: Dict) -> List[str]:
    """Generate recommendations for improving DKIM records"""
    recommendations = []
    status = result.get("status", "unknown")
    issues = result.get("issues", [])
    selector = result.get("selector", "default")
    
    if status == "missing":
        recommendations.append(f"Set up DKIM for your domain using selector '{selector}'.")
        recommendations.append("Contact your email service provider for specific DKIM setup instructions.")
        return recommendations
    
    # Check for common issues
    if "Invalid DKIM record format" in str(issues):
        recommendations.append("Your DKIM record has formatting issues. Verify the syntax with your email provider.")
    
    if "Key too short" in str(issues) or "weak key" in str(issues).lower():
        recommendations.append("Use a stronger encryption key (2048-bit RSA or higher) for better security.")
    
    if "Missing required tag" in str(issues):
        recommendations.append("Ensure your DKIM record includes all required tags (v=DKIM1, k=rsa, p=public-key).")
    
    # If no specific recommendations were generated but there are issues
    if not recommendations and issues:
        recommendations.append("Review your DKIM record format with your email service provider.")
        
    return recommendations


def generate_dmarc_recommendations(domain: str, result: Dict) -> List[str]:
    """Generate recommendations for improving DMARC records"""
    recommendations = []
    status = result.get("status", "unknown")
    issues = result.get("issues", [])
    value = result.get("value", "")
    
    if status == "missing":
        recommendations.append(f"Add a DMARC record with: v=DMARC1; p=none; rua=mailto:dmarc@{domain}")
        recommendations.append("Start with monitoring mode (p=none) to gather data before enforcing policies.")
        return recommendations
    
    if not value:
        return recommendations
    
    # Parse existing policy if present
    policy = "none"
    if "p=none" in value.lower():
        policy = "none"
    elif "p=quarantine" in value.lower():
        policy = "quarantine"
    elif "p=reject" in value.lower():
        policy = "reject"
    
    # Check common issues
    if "Missing reporting" in str(issues) or "rua=" not in value.lower():
        recommendations.append(f"Add aggregate reporting with: rua=mailto:dmarc@{domain}")
        recommendations.append("Aggregate reports help you monitor email authentication results.")
    
    if policy == "none" and "p=none" in value.lower():
        recommendations.append("Once you've reviewed reports, consider strengthening your policy from p=none to p=quarantine or p=reject.")
        recommendations.append("This will better protect your domain from being spoofed.")
    
    if "low percentage" in str(issues).lower() and "pct=" in value.lower():
        recommendations.append("Gradually increase your DMARC percentage (pct=) towards 100% for complete coverage.")
    
    if "Missing subdomain policy" in str(issues) or "sp=" not in value.lower():
        recommendations.append("Add subdomain policy (sp=) to protect your subdomains from spoofing.")
    
    # If no specific recommendations were generated but there are issues
    if not recommendations and issues:
        recommendations.append("Review your DMARC policy and gradually strengthen it as your email authentication matures.")
        
    return recommendations

@router.post("/scan-job", response_model=ScanJobResponse)
async def create_domain_scan_job(
    job_request: ScanJobRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new background task to scan domain DNS records"""
    try:
        validated_domain = validate_domain(job_request.domain)

        domain_db = get_domain_by_name(db, domain_name=validated_domain, user_id=current_user.id)
        if not domain_db:
            domain_db = create_domain(db, user_id=current_user.id, domain_name=validated_domain)

            create_audit_log(
                db,
                current_user.id,
                "domain_created",
                {"domain_id": domain_db.id, "domain_name": validated_domain}
            )

        job_id = str(uuid.uuid4())

        job = create_scan_job(
            db,
            job_id=job_id,
            domain_id=domain_db.id,
            user_id=current_user.id,
            check_spf=job_request.check_spf,
            check_dkim=job_request.check_dkim,
            check_dmarc=job_request.check_dmarc,
            dkim_selector=job_request.dkim_selector 
        )

        job_status = {
            "job_id": job_id,
            "domain": validated_domain,
            "status": "pending",
            "progress": 0,
            "message": "Job created, waiting for worker",
            "user_id": current_user.id,
            "created_at": job.created_at.isoformat(),
            "updated_at": job.updated_at.isoformat()
        }

        redis_client.set(f"job_status:{job_id}", json.dumps(job_status), ex=3600)

        background_tasks.add_task(
            run_scheduled_verification,
            job_id=job_id,
            domain=validated_domain,
            check_spf=job_request.check_spf,
            check_dkim=job_request.check_dkim,
            check_dmarc=job_request.check_dmarc,
            dkim_selector=job_request.dkim_selector,
            user_id=current_user.id
        )

        create_audit_log(
            db,
            current_user.id,
            "scan_job_created",
            {"job_id": job_id, "domain_id": domain_db.id, "domain_name": validated_domain}
        )

        return ScanJobResponse(
            job_id=job_id,
            domain=validated_domain,
            status="pending",
            created_at=job.created_at.isoformat(),
            updated_at=job.updated_at.isoformat(),
            message="Job created and queued for processing"
        )
    except ValidationError as e:
        logger.error(f"Validation error: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Invalid input: {str(e)}")
    except Exception as e:
        logger.error(f"Error creating scan job: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create scan job: {str(e)}")

@router.get("/job-status/{job_id}", response_model=JobStatusResponse)
async def get_job_status(
    job_id: str = Path(..., description="Unique ID of the scan job"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get the status of a scan job"""
    try:
        print("Job status endpint hit")
        # First, try to get status from Redis cache for fast response
        cached_status = redis_client.get(f"job_status:{job_id}")
        
        if cached_status:
            # Parse the JSON from cache
            job_status = json.loads(cached_status)
            
            # Verify this job belongs to the current user
            # if job_status.get("user_id") != current_user.id:
            #     raise HTTPException(status_code=403, detail="Not authorized to access this job")
            
            # If job is completed, include results
            results = None
            if job_status.get("status") == "completed":
                # Get results from cache
                cached_results = redis_client.get(f"job_results:{job_id}")
                if cached_results:
                    results = json.loads(cached_results)
                
            return JobStatusResponse(
                job_id=job_id,
                status=job_status.get("status", "unknown"),
                progress=job_status.get("progress", 0),
                message=job_status.get("message"),
                results=results
            )
        
        # If not in cache, get from database
        job = get_scan_job(db, job_id=job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        
        # Verify job belongs to user
        if job.user_id != current_user.id:
            raise HTTPException(status_code=403, detail="Not authorized to access this job")
        
        # Convert database job status to response
        status_mapping = {
            JobStatus.PENDING: "pending",
            JobStatus.PROCESSING: "processing",
            JobStatus.COMPLETED: "completed",
            JobStatus.FAILED: "failed"
        }
        
        status = status_mapping.get(job.status, "unknown")
        
        # For completed jobs, get the results
        results = None
        if job.status == JobStatus.COMPLETED:
            # Get the domain record
            domain = get_domain_by_id(db, domain_id=job.domain_id)
            if domain:
                # Get DNS records
                dns_records = get_domain_dns_records(db, domain_id=domain.id)
                
                # Build verification response
                spf_record = next((r for r in dns_records if r.record_type == RecordType.SPF), None)
                dkim_record = next((r for r in dns_records if r.record_type == RecordType.DKIM), None)
                dmarc_record = next((r for r in dns_records if r.record_type == RecordType.DMARC), None)
                
                # Map statuses
                status_map = {
                    RecordStatus.VALID: "valid",
                    RecordStatus.WARNING: "warning",
                    RecordStatus.CRITICAL: "critical",
                    RecordStatus.PENDING: "pending"
                }
                
                # Determine overall status
                if any(r.status == RecordStatus.CRITICAL for r in dns_records):
                    overall_status = "critical"
                elif any(r.status == RecordStatus.WARNING for r in dns_records):
                    overall_status = "issues"
                elif all(r.status == RecordStatus.VALID for r in dns_records):
                    overall_status = "healthy"
                else:
                    overall_status = "pending"
                
                # Create result object
                results = DomainVerificationResponse(
                    domain=domain.domain_name,
                    overall_status=overall_status,
                    timestamp=domain.last_checked.isoformat() if domain.last_checked else datetime.utcnow().isoformat()
                )
                
                # Add record analysis if available
                if spf_record:
                    results.spf_analysis = RecordAnalysis(
                        record_type="SPF",
                        status=status_map.get(spf_record.status, "pending"),
                        value=spf_record.value,
                        issues=json.loads(spf_record.issues) if spf_record.issues else [],
                        recommendations=json.loads(spf_record.recommendations) if spf_record.recommendations else [],
                        last_checked=spf_record.last_checked
                    )
                
                if dkim_record:
                    results.dkim_analysis = RecordAnalysis(
                        record_type="DKIM",
                        status=status_map.get(dkim_record.status, "pending"),
                        value=dkim_record.value,
                        issues=json.loads(dkim_record.issues) if dkim_record.issues else [],
                        recommendations=json.loads(dkim_record.recommendations) if dkim_record.recommendations else [],
                        last_checked=dkim_record.last_checked
                    )
                
                if dmarc_record:
                    results.dmarc_analysis = RecordAnalysis(
                        record_type="DMARC",
                        status=status_map.get(dmarc_record.status, "pending"),
                        value=dmarc_record.value,
                        issues=json.loads(dmarc_record.issues) if dmarc_record.issues else [],
                        recommendations=json.loads(dmarc_record.recommendations) if dmarc_record.recommendations else [],
                        last_checked=dmarc_record.last_checked
                    )
        
        # Cache the response in Redis for faster subsequent retrievals
        response = JobStatusResponse(
            job_id=job_id,
            status=status,
            progress=job.progress,
            message=job.message,
            results=results
        )
        
        # Cache job status
        job_status = {
            "job_id": job_id,
            "domain": domain.domain_name if 'domain' in locals() else None,
            "status": status,
            "progress": job.progress,
            "message": job.message,
            "user_id": current_user.id,
            "created_at": job.created_at.isoformat(),
            "updated_at": job.updated_at.isoformat()
        }
        redis_client.set(f"job_status:{job_id}", json.dumps(job_status), ex=3600)  # Expire after 1 hour
        
        # Cache results if completed
        if results:
            redis_client.set(f"job_results:{job_id}", results.json(), ex=3600)  # Expire after 1 hour
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting job status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get job status: {str(e)}")


@router.get("/recommendations/{domain_id}", response_model=DnsRecommendationResponse)
async def get_domain_recommendations(
    domain_id: int = Path(..., description="ID of the domain to get recommendations for"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get DNS configuration recommendations for a domain"""
    try:
        # Get domain
        domain = get_domain_by_id(db, domain_id=domain_id)
        if not domain:
            raise HTTPException(status_code=404, detail="Domain not found")
        
        # Verify domain belongs to user
        if domain.user_id != current_user.id:
            raise HTTPException(status_code=403, detail="Not authorized to access this domain")
            
        # Get DNS records
        dns_records = get_domain_dns_records(db, domain_id=domain.id)
        
        # Extract records by type
        spf_record = next((r for r in dns_records if r.record_type == RecordType.SPF), None)
        dkim_record = next((r for r in dns_records if r.record_type == RecordType.DKIM), None)
        dmarc_record = next((r for r in dns_records if r.record_type == RecordType.DMARC), None)
        
        # Build response
        response = DnsRecommendationsResponse(domain=domain.domain_name)
        
        # Generate recommendations based on record status and issues
        if spf_record and (spf_record.status != RecordStatus.VALID or spf_record.issues):
            issues = json.loads(spf_record.issues) if spf_record.issues else []
            recommendations = json.loads(spf_record.recommendations) if spf_record.recommendations else []
            
            # Generate recommended SPF record value
            recommended_value = generate_spf_recommendation(domain.domain_name, spf_record.value, issues)
            
            response.spf_recommendation = DnsRecommendation(
                record_type="SPF",
                current_value=spf_record.value,
                issues=issues,
                recommendations=recommendations,
                recommended_value=recommended_value
            )
        
        if dkim_record and (dkim_record.status != RecordStatus.VALID or dkim_record.issues):
            issues = json.loads(dkim_record.issues) if dkim_record.issues else []
            recommendations = json.loads(dkim_record.recommendations) if dkim_record.recommendations else []
            
            # Generate recommended DKIM record value
            recommended_value = generate_dkim_recommendation(domain.domain_name, dkim_record.value, issues)
            
            response.dkim_recommendation = DnsRecommendation(
                record_type="DKIM",
                current_value=dkim_record.value,
                issues=issues,
                recommendations=recommendations,
                recommended_value=recommended_value
            )
        
        if dmarc_record and (dmarc_record.status != RecordStatus.VALID or dmarc_record.issues):
            issues = json.loads(dmarc_record.issues) if dmarc_record.issues else []
            recommendations = json.loads(dmarc_record.recommendations) if dmarc_record.recommendations else []
            
            # Generate recommended DMARC record value
            recommended_value = generate_dmarc_recommendation(domain.domain_name, dmarc_record.value, issues)
            
            response.dmarc_recommendation = DnsRecommendation(
                record_type="DMARC",
                current_value=dmarc_record.value,
                issues=issues,
                recommendations=recommendations,
                recommended_value=recommended_value
            )
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting domain recommendations: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get domain recommendations: {str(e)}")


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
            dkim_selector=domain_request.dkim_selector
        )
        
        # Update domain last checked timestamp
        update_domain_last_checked(db, domain_db.id)
        
        # Store DNS record results in database
        if domain_request.check_spf and "spf_analysis" in verification_result:
            create_or_update_dns_record(
                db,
                domain_id=domain_db.id,
                record_type=RecordType.SPF,
                status=parse_status(verification_result["spf_analysis"]["status"]),
                record_value=verification_result["spf_analysis"]["value"]
            )

        if domain_request.check_dkim and "dkim_analysis" in verification_result:
            create_or_update_dns_record(
                db,
                domain_id=domain_db.id,
                record_type=RecordType.DKIM,
                status=parse_status(verification_result["dkim_analysis"]["status"]),
                record_value=verification_result["dkim_analysis"]["value"]
            )

        if domain_request.check_dmarc and "dmarc_analysis" in verification_result:
            create_or_update_dns_record(
                db,
                domain_id=domain_db.id,
                record_type=RecordType.DMARC,
                status=parse_status(verification_result["dmarc_analysis"]["status"]),
                record_value=verification_result["dmarc_analysis"]["value"]
            )
        
        # Create audit log for domain verification
        create_audit_log(
            db, 
            current_user.id, 
            "domain_verified", 
            {
                "domain_id": domain_db.id, 
                "domain_name": validated_domain,
                "overall_status": verification_result["overall_status"]
            }
        )
        
        # Schedule a follow-up check in the background for metrics collection
        background_tasks.add_task(
            run_scheduled_verification,
            validated_domain,
            domain_request.check_spf,
            domain_request.check_dkim,
            domain_request.check_dmarc,
            domain_request.dkim_selector,
            current_user.id  # Pass user_id to the background task
        )
        response_data = {
            "domain": validated_domain,
            "overall_status": verification_result["overall_status"],
            "timestamp": datetime.now().isoformat(),
            "spf_analysis": verification_result.get("details", {}).get("spf"),
            "dkim_analysis": verification_result.get("details", {}).get("dkim"),
            "dmarc_analysis": verification_result.get("details", {}).get("dmarc")
        }
        print("Domain verification response: ", response_data)

        return response_data
    
    except ValueError as e:
        logger.error(f"Domain validation error: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception(f"Error verifying domain {domain_name}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error during domain verification")

@router.post("/verify1", response_model=DomainVerificationResponse)
async def verify_domain(
    request: DomainVerificationRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Verify domain DNS records for email security (SPF, DKIM, DMARC)"""
    try:
        # Validate domain
        validated_domain = validate_domain(request.domain)
        
        # Get domain or create if it doesn't exist
        domain = get_domain_by_name(db, domain_name=validated_domain, user_id=current_user.id)
        if not domain:
            domain = create_domain(db, user_id=current_user.id, domain_name=validated_domain)
            
            # Create audit log
            create_audit_log(
                db, 
                current_user.id, 
                "domain_created", 
                {"domain_id": domain.id, "domain_name": validated_domain}
            )
        
        # Update last checked timestamp
        update_domain_last_checked(db, domain_id=domain.id)
        
        # Placeholder response while job is created
        response = DomainVerificationResponse(
            domain=validated_domain,
            overall_status="pending",
            timestamp=datetime.utcnow().isoformat()
        )
        
        # Create pending DNS records if they don't exist
        if request.check_spf:
            response.spf_analysis = RecordAnalysis(
                record_type="SPF",
                status="pending"
            )
            
            # Create or update SPF record in database
            create_or_update_dns_record(
                db,
                domain_id=domain.id,
                record_type=RecordType.SPF,
                status=RecordStatus.PENDING,
                record_value=None  
            )
        
        if request.check_dkim:
            response.dkim_analysis = RecordAnalysis(
                record_type="DKIM",
                status="pending"
            )
            
            # Create or update DKIM record in database
            create_or_update_dns_record(
                db,
                domain_id=domain.id,
                record_type=RecordType.DKIM,
                status=RecordStatus.PENDING,
                record_value=None
            )
        
        if request.check_dmarc:
            response.dmarc_analysis = RecordAnalysis(
                record_type="DMARC",
                status="pending"
            )
            
            # Create or update DMARC record in database
            create_or_update_dns_record(
                db,
                domain_id=domain.id,
                record_type=RecordType.DMARC,
                status=RecordStatus.PENDING,
                record_value=None
            )
        
        # Create a job ID
        job_id = str(uuid.uuid4())
        
        # Create scan job in database
        job = create_scan_job(
            db,
            job_id=job_id,
            domain_id=domain.id,
            user_id=current_user.id,
            check_spf=request.check_spf,
            check_dkim=request.check_dkim,
            check_dmarc=request.check_dmarc,
            dkim_selector=request.dkim_selector
        )
        
        # Store initial job status in Redis
        job_status = {
            "job_id": job_id,
            "domain": validated_domain,
            "status": "pending",
            "progress": 0,
            "message": "Job created, waiting for worker",
            "user_id": current_user.id,
            "created_at": job.created_at.isoformat(),
            "updated_at": job.updated_at.isoformat()
        }
        redis_client.set(f"job_status:{job_id}", json.dumps(job_status), ex=3600)  # Expire after 1 hour
        
        # Schedule the DNS verification in the background
        background_tasks.add_task(
            run_scheduled_verification,
            job_id=job_id,
            domain=validated_domain,
            check_spf=request.check_spf,
            check_dkim=request.check_dkim,
            check_dmarc=request.check_dmarc,
            dkim_selector=request.dkim_selector,
            user_id=current_user.id
        )
        
        # Return pending response immediately
        return response
        
    except ValidationError as e:
        logger.error(f"Validation error: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Invalid input: {str(e)}")
    except Exception as e:
        logger.error(f"Error verifying domain: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to verify domain: {str(e)}")



@router.get("/history/{domain}", response_model=List[DomainVerificationResponse])
async def get_domain_history(
    domain: str = Path(..., description="Domain name to get history for"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of history records to return"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get historical verification results for a domain"""
    try:
        # Validate domain
        validated_domain = validate_domain(domain)
        
        # Get domain record
        domain_db = get_domain_by_name(db, domain_name=validated_domain, user_id=current_user.id)
        if not domain_db:
            raise HTTPException(status_code=404, detail="Domain not found")
        
        # Get domain verification history from Redis
        history_key = f"domain_history:{domain_db.id}"
        history_json = redis_client.lrange(history_key, 0, limit - 1)
        
        if not history_json:
            # If no history in Redis, return empty list
            return []
        
        # Parse history records
        history = [json.loads(record) for record in history_json]
        
        return history
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting domain history: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get domain history: {str(e)}")


@router.get("/", response_model=List[Dict])
async def get_user_domains(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all domains for the current user with their latest verification status"""
    from app.users.crud import get_user_domains
    
    domains = await get_user_domains(db, user_id=current_user.id)
    results = []
    # print("Domain got:  {}", domains)
    
    for domain in domains:
        # Get the latest record for each type
        records = get_domain_dns_records(db, domain_id=domain.id, limit=3) # (SPF, DKIM, DMARC)
        
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


@router.post("/add", response_model=DomainAddResponse)
async def add_domain(
    request: DomainAddRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Add a new domain or email to monitor"""
    try:
        # Process the input (domain or email)
        original_input = request.domain_or_email.strip()
        input_data = extract_original_input(original_input)

        input_type = input_data.get("input_type") or input_data.get("type", "domain")
        
        # Check if domain exists
        domain_db = get_domain_by_name(db, domain_name=input_data["domain"], user_id=current_user.id)
        
        if domain_db:
            return DomainAddResponse(
                domain=input_data["domain"],
                original_input=original_input,
                input_type=input_type,
                id=domain_db.id,
                success=True,
                message="Domain already exists",
                email_prefix=input_data.get("email_prefix")
            )
        
        # Create new domain
        domain_db = create_domain(
            db, 
            user_id=current_user.id, 
            domain_name=input_data["domain"],
            original_input=original_input,
            input_type=input_type,
            email_prefix=input_data.get("email_prefix"),
            notes=request.notes
        )
        
        # Create audit log
        create_audit_log(
            db, 
            current_user.id, 
            "domain_created", 
            {"domain_id": domain_db.id, "domain_name": input_data["domain"]}
        )
        
        # Return success response
        return DomainAddResponse(
            domain=input_data["domain"],
            original_input=original_input,
            input_type=input_type,
            id=domain_db.id,
            success=True,
            message="Domain added successfully",
            email_prefix=input_data.get("email_prefix")
        )
        
    except ValidationError as e:
        logger.error(f"Validation error: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Invalid input: {str(e)}")
    except Exception as e:
        logger.error(f"Error adding domain: {str(e)}")
        import traceback
        logger.error(f"Exception detail: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Failed to add domain: {str(e)}")


@router.post("/bulk-add", response_model=BulkDomainAddResponse)
async def add_multiple_domains(
    bulk_request: BulkDomainAddRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Add multiple domains to the user's account in bulk, supporting both domain names and email addresses"""
    results = []
    success_count = 0
    failure_count = 0
    
    for domain_or_email in bulk_request.domains_or_emails:
        try:
            # Extract information from the input
            parsed_info = extract_original_input(domain_or_email)
            domain = parsed_info["domain"]
            
            # Validate the domain
            validated_domain = validate_domain(domain)
            
            # Check if domain already exists for this user
            existing_domain = get_domain_by_name(db, domain_name=validated_domain, user_id=current_user.id)
            if existing_domain:
                results.append(DomainAddResponse(
                    domain=validated_domain,
                    original_input=parsed_info["original"],
                    input_type=parsed_info["input_type"],
                    email_prefix=parsed_info.get("email_prefix"),
                    id=existing_domain.id,
                    success=False,
                    message="Domain already exists for this user"
                ))
                failure_count += 1
                continue
            
            # Create the domain in the database
            domain_db = create_domain(db, user_id=current_user.id, domain_name=validated_domain)
            
            # Store additional metadata in audit log
            metadata = {
                "domain_id": domain_db.id, 
                "domain_name": validated_domain,
                "original_input": parsed_info["original"],
                "input_type": parsed_info["input_type"],
                "notes": bulk_request.notes
            }
            
            if "email_prefix" in parsed_info:
                metadata["email_prefix"] = parsed_info["email_prefix"]
            
            # Create audit log for domain creation
            create_audit_log(
                db, 
                current_user.id, 
                "domain_created", 
                metadata
            )
            
            results.append(DomainAddResponse(
                domain=validated_domain,
                original_input=parsed_info["original"],
                input_type=parsed_info["input_type"],
                email_prefix=parsed_info.get("email_prefix"),
                id=domain_db.id,
                success=True,
                message="Domain added successfully"
            ))
            success_count += 1
            
        except ValidationError as e:
            results.append(DomainAddResponse(
                domain=domain_or_email,
                original_input=domain_or_email,
                input_type="unknown",
                id=0,
                success=False,
                message=str(e)
            ))
            failure_count += 1
        except Exception as e:
            results.append(DomainAddResponse(
                domain=domain_or_email,
                original_input=domain_or_email,
                input_type="unknown",
                id=0,
                success=False,
                message=f"Error adding domain: {str(e)}"
            ))
            failure_count += 1
    
    return BulkDomainAddResponse(
        results=results,
        success_count=success_count,
        failure_count=failure_count
    )

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



@router.post("/delete", response_model=DomainDeleteResponse)
async def delete_domain(
    request: DomainDeleteRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a domain from monitoring"""
    try:
        # Validate domain name
        domain_name = request.domain
        # print("Domain to delete: ", domain_name)
        
        # Get domain record by name
        domain_db = get_domain_by_name(db, domain_name=domain_name, user_id=current_user.id)
        # print("Domain record: ", domain_db)
        if not domain_db:
            raise HTTPException(status_code=404, detail="Domain not found")
        
        # Create audit log before deletion
        create_audit_log(
            db, 
            current_user.id, 
            "domain_deleted", 
            {
                "domain_id": domain_db.id, 
                "domain_name": domain_name,
                "notes": request.notes if hasattr(request, 'notes') and request.notes else "No deletion notes provided"
            }
        )
        
        # Soft delete domain (set is_active=False)
        domain_db.is_active = False
        domain_db.deleted_at = datetime.utcnow()
        db.commit()

        # Remove domain from Redis cache
        redis_client.delete(f"domain_history:{domain_db.id}")
        redis_client.delete(f"job_status:{domain_db.id}")
        redis_client.delete(f"job_results:{domain_db.id}")
        redis_client.delete(f"domain:{domain_db.id}")
        redis_client.delete(f"domain:{domain_name}")
        
        # check if domain is in database
        domain_db = get_domain_by_name(db, domain_name=domain_name, user_id=current_user.id)
        # print("Domain record after deletion: ", domain_db)        
        return DomainDeleteResponse(
            domain=domain_name,
            success=True,
            message="Domain removed from monitoring"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting domain: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to delete domain: {str(e)}")


@router.get("/anonymous-scan/{domain}", response_model=DomainVerificationResponse)
async def anonymous_domain_scan(
    domain: str = Path(..., description="Domain name to scan"),
    dkim_selector: Optional[str] = Query(None, description="DKIM selector to check")
) -> Dict[str, Any]:
    """
    Perform a domain scan without authentication.
    Analyzes DNS records relevant to email deliverability (SPF, DKIM, DMARC).
    """
    logger.info(f"Anonymous scan requested for domain: {domain} with DKIM selector: {dkim_selector}")
    
    try:
        # Validate domain format
        domain = domain.lower().strip()
        
        # Check cache first to reduce load
        cache_key = f"anon_scan:{domain}:{dkim_selector or 'default'}"
        cached_result = redis_client.get(cache_key)
        
        if cached_result:
            logger.info(f"Returning cached result for {domain}")
            return json.loads(cached_result)
        
        # Initialize scanner
        scanner = DomainScanner(domain)
        logger.info(f"Scanner initialized for domain: {domain}")
        
        # Perform the scan
        scan_results = await scanner.scan_all(provided_dkim_selector=dkim_selector)
        logger.info(f"Scan completed for domain {domain}")
        
        # Format results for response
        # Extract the status string from the overall_status object
        overall_status = "unknown"
        if isinstance(scan_results["overall_status"], str):
            overall_status = scan_results["overall_status"]
        elif isinstance(scan_results["overall_status"], dict):
            overall_status = scan_results["overall_status"].get("status", "unknown")
        
        # Format the response with proper structures
        response = {
            "domain": domain,
            "overall_status": overall_status,
            "timestamp": datetime.utcnow().isoformat(),
            "spf_analysis": {
                "record_type": "SPF",
                "status": scan_results.get("spf", {}).get("status", "unknown"),
                "value": scan_results.get("spf", {}).get("value", ""),
                "issues": scan_results.get("spf", {}).get("issues", []),
                "recommendations": []
            },
            "dkim_analysis": {
                "record_type": "DKIM",
                "status": scan_results.get("dkim", {}).get("status", "unknown"),
                "value": scan_results.get("dkim", {}).get("value", ""),
                "selector": dkim_selector,
                "issues": scan_results.get("dkim", {}).get("issues", []),
                "recommendations": []
            },
            "dmarc_analysis": {
                "record_type": "DMARC",
                "status": scan_results.get("dmarc", {}).get("status", "unknown"),
                "value": scan_results.get("dmarc", {}).get("value", ""),
                "issues": scan_results.get("dmarc", {}).get("issues", []),
                "recommendations": []
            }
        }
        
        # Cache the result for 1 minutes
        redis_client.set(cache_key, json.dumps(response), ex=60)
        
        return response
        
    except ValidationError as e:
        logger.error(f"Validation error: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Invalid input: {str(e)}")
    except Exception as e:
        logger.error(f"Error scanning domain {domain}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


# Add these endpoints after the existing code

@router.get("/scan-spf/{domain}", response_model=RecordAnalysis)
async def scan_spf_record(
    domain: str = Path(..., description="Domain to scan SPF record for")
) -> Dict[str, Any]:
    """
    Scan only the SPF record for a domain.
    Returns the record value, status, and any issues found.
    """
    logger.info(f"SPF scan requested for domain: {domain}")
    
    try:
        # Validate domain format
        domain = domain.lower().strip()
        
        # Check cache first to reduce load
        cache_key = f"spf_scan:{domain}"
        cached_result = redis_client.get(cache_key)
        
        if cached_result:
            logger.info(f"Returning cached SPF result for {domain}")
            return json.loads(cached_result)
        
        # Initialize scanner
        scanner = DomainScanner(domain)
        
        # Only scan SPF
        spf_result = await scanner.scan_spf()
        logger.info(f"SPF scan completed for domain {domain}")
        
        # Format response
        response = {
            "record_type": "SPF",
            "status": spf_result.get("status", "unknown"),
            "value": spf_result.get("value", ""),
            "issues": spf_result.get("issues", []),
            "recommendations": generate_spf_recommendations(domain, spf_result)
        }
        
        # Cache for 5 minutes
        redis_client.set(cache_key, json.dumps(response), ex=300)
        
        return response
        
    except Exception as e:
        logger.error(f"Error scanning SPF for {domain}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"SPF scan failed: {str(e)}")


@router.get("/scan-dkim/{domain}", response_model=RecordAnalysis)
async def scan_dkim_record(
    domain: str = Path(..., description="Domain to scan DKIM record for"),
    selector: str = Query("default", description="DKIM selector to check")
) -> Dict[str, Any]:
    """
    Scan only the DKIM record for a domain with the specified selector.
    Returns the record value, status, and any issues found.
    """
    logger.info(f"DKIM scan requested for domain: {domain} with selector: {selector}")
    
    try:
        # Validate domain format
        domain = domain.lower().strip()
        
        # Check cache first to reduce load
        cache_key = f"dkim_scan:{domain}:{selector}"
        cached_result = redis_client.get(cache_key)
        
        if cached_result:
            logger.info(f"Returning cached DKIM result for {domain}")
            return json.loads(cached_result)
        
        # Initialize scanner
        scanner = DomainScanner(domain)
        
        # Only scan DKIM with the provided selector
        dkim_result = await scanner.scan_dkim(selector)
        logger.info(f"DKIM scan completed for domain {domain} with selector {selector}")
        
        # Format response
        response = {
            "record_type": "DKIM",
            "status": dkim_result.get("status", "unknown"),
            "value": dkim_result.get("value", ""),
            "selector": selector,
            "issues": dkim_result.get("issues", []),
            "recommendations": generate_dkim_recommendations(domain, dkim_result)
        }
        
        # Cache for 5 minutes
        redis_client.set(cache_key, json.dumps(response), ex=300)
        
        return response
        
    except Exception as e:
        logger.error(f"Error scanning DKIM for {domain}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"DKIM scan failed: {str(e)}")


@router.get("/scan-dmarc/{domain}", response_model=RecordAnalysis)
async def scan_dmarc_record(
    domain: str = Path(..., description="Domain to scan DMARC record for")
) -> Dict[str, Any]:
    """
    Scan only the DMARC record for a domain.
    Returns the record value, status, and any issues found.
    """
    logger.info(f"DMARC scan requested for domain: {domain}")
    
    try:
        # Validate domain format
        domain = domain.lower().strip()
        
        # Check cache first to reduce load
        cache_key = f"dmarc_scan:{domain}"
        cached_result = redis_client.get(cache_key)
        
        if cached_result:
            logger.info(f"Returning cached DMARC result for {domain}")
            return json.loads(cached_result)
        
        # Initialize scanner
        scanner = DomainScanner(domain)
        
        # Only scan DMARC
        dmarc_result = await scanner.scan_dmarc()
        logger.info(f"DMARC scan completed for domain {domain}")
        
        # Format response
        response = {
            "record_type": "DMARC",
            "status": dmarc_result.get("status", "unknown"),
            "value": dmarc_result.get("value", ""),
            "issues": dmarc_result.get("issues", []),
            "recommendations": generate_dmarc_recommendations(domain, dmarc_result)
        }
        
        # Cache for 5 minutes
        redis_client.set(cache_key, json.dumps(response), ex=300)
        
        return response
        
    except Exception as e:
        logger.error(f"Error scanning DMARC for {domain}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"DMARC scan failed: {str(e)}")