import json
import logging
from sqlalchemy.orm import Session
from datetime import datetime
from typing import List, Optional
from passlib.context import CryptContext
from app.db import models
from app.db.models import User, Domain, DNSRecord, AuditLog, RecordType, RecordStatus, ScanJob, JobStatus

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

logger = logging.getLogger(__name__)

async def create_user_if_not_exists(email: str, name: str):
    # query = "SELECT * FROM users WHERE email = :email"
    # user = await database.fetch_one(query=query, values={"email": email})
    # if not user:
    #     insert_query = "INSERT INTO users (email, name) VALUES (:email, :name) RETURNING id"
    #     user_id = await database.execute(insert_query, values={"email": email, "name": name})
    #     return {"id": user_id, "email": email, "name": name}
    # return user

    db_user = models.User(
        email=email,
        name=name,
        created_at=datetime.utcnow()
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


# User operations
def create_user(db: Session, email: str, password: str, name: str, google_id: Optional[str] = None):
    hashed_password = None
    if password:
        hashed_password = pwd_context.hash(password)
    db_user = models.User(
        email=email,
        hashed_password=hashed_password,
        name=name,
        google_id=google_id,
        created_at=datetime.utcnow()
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def authenticate_user(db: Session, email: str, password: str) -> Optional[User]:
    """
    Authenticate a user by email and password.
    Returns the User object if authentication is successful, None otherwise.
    """
    user = get_user_by_email(db, email)
    if not user:
        return None

    if not user.hashed_password:
        # This might be a Google-only account
        return None

    if not pwd_context.verify(password, user.hashed_password):
        return None

    return user


def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def get_user_by_id(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()

def update_user_last_login(db: Session, user_id: int):
    db_user = get_user_by_id(db, user_id)
    if db_user:
        db_user.last_login = datetime.utcnow()
        db.commit()
        db.refresh(db_user)
    return db_user

# Domain operations
def create_domain(
    db: Session,
    *,
    user_id: int,
    domain_name: str,
    original_input: Optional[str] = None,
    input_type: Optional[str] = "domain",
    email_prefix: Optional[str] = None,
    notes: Optional[str] = None
) -> Domain:
    """
    Create a new domain for a user with additional metadata
    
    Args:
        db: Database session
        user_id: User ID to associate with domain
        domain_name: Domain name (e.g., example.com)
        original_input: The original input that was parsed to get the domain
        input_type: Type of input ('domain' or 'email')
        email_prefix: If input was an email, the prefix part
        notes: Optional notes about this domain
        
    Returns:
        Domain: The created domain object
    """
    domain = Domain(
        user_id=user_id,
        domain_name=domain_name,
        original_input=original_input,
        input_type=input_type,
        email_prefix=email_prefix,
        notes=notes,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
        is_active=True
    )
    
    db.add(domain)
    db.commit()
    db.refresh(domain)
    
    return domain

async def get_user_domains(db: Session, user_id: int, skip: int = 0, limit: int = 100):
    # print(f"Fetching domains for user_id: {user_id}, skip: {skip}, limit: {limit}")
    # Check if user_id is valid
    if not db.query(models.User).filter(models.User.id == user_id).first():
        return []
    # Fetch domains for the user
    query = db.query(models.Domain).filter(models.Domain.user_id == user_id, models.Domain.is_active == True).offset(skip).limit(limit)
    # print(f"Query: {query}")
    domains = query.all()
    # print(f"Domains: {domains}")
    return domains

def get_domain_by_id(db: Session, domain_id: int, user_id: int = None):
    """retreive domain by id"""
    #check if the user id is valid
    if not db.query(models.User).filter(models.User.id == user_id).first():
        return []
    #check if the domain id is valid
    print(f"Checking if domain ID {domain_id} exists for user ID {user_id}")
    if not db.query(models.Domain).filter(models.Domain.id == domain_id).first():
        return None
    print(f"Fetching domain with ID: {domain_id}")
    query = db.query(models.Domain).filter(models.Domain.id == domain_id).first()
    domain = query
    return domain

def update_domain_last_checked(db: Session, domain_id: int):
    db_domain = get_domain_by_id(db, domain_id)
    if db_domain:
        db_domain.last_checked = datetime.utcnow()
        db.commit()
        db.refresh(db_domain)
    return db_domain

# DNS Record operations
def create_dns_record(db: Session, domain_id: int, record_type: models.RecordType, 
                     status: models.RecordStatus, record_value: str):
    db_record = models.DNSRecord(
        domain_id=domain_id,
        type=record_type,
        status=status,
        record_value=record_value,
        last_checked=datetime.utcnow()
    )
    db.add(db_record)
    db.commit()
    db.refresh(db_record)
    return db_record

def get_domain_dns_records(db: Session, domain_id: int, limit: int = None):
    query = db.query(models.DNSRecord).filter(models.DNSRecord.domain_id == domain_id)
    if limit:
        query = query.limit(limit)
    return query.all()

def get_domain_by_name(db: Session, domain_name: str, user_id: int = None):
    query = db.query(models.Domain).filter(
        models.Domain.domain_name == domain_name,
        models.Domain.is_active == True 
    )
    
    if user_id is not None:
        query = query.filter(models.Domain.user_id == user_id)
        
    return query.first()

def update_dns_record_status(db: Session, record_id: int, status: models.RecordStatus):
    db_record = db.query(models.DNSRecord).filter(models.DNSRecord.id == record_id).first()
    if db_record:
        db_record.status = status
        db_record.last_checked = datetime.utcnow()
        db.commit()
        db.refresh(db_record)
    return db_record

# Audit Log operations
def create_audit_log(db: Session, user_id: int, action: str, metadata: dict = None):
    db_log = models.AuditLog(
        user_id=user_id,
        action=action,
        timestamp=datetime.utcnow(),
        metadata=metadata
    )
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    return db_log

def get_user_audit_logs(db: Session, user_id: int, skip: int = 0, limit: int = 100):
    return db.query(models.AuditLog).filter(models.AuditLog.user_id == user_id).order_by(
        models.AuditLog.timestamp.desc()
    ).offset(skip).limit(limit).all()

def create_or_update_dns_record(
    db: Session,
    *,
    domain_id: int,
    record_type: RecordType,
    status: RecordStatus,
    record_value: Optional[str] = None,
    issues: Optional[List[str]] = None,
    recommendations: Optional[List[str]] = None,
    selector: Optional[str] = None
) -> DNSRecord:
    """Create or update a DNS record with detailed analysis results"""
    # Query existing record
    record = db.query(DNSRecord).filter(
        DNSRecord.domain_id == domain_id,
        DNSRecord.type == record_type
    ).first()
    
    if record:
        # Update existing record
        record.status = status
        record.last_checked = datetime.utcnow()
        
        if record_value is not None:
            record.record_value = record_value
            
        if issues is not None:
            record.issues = issues if isinstance(issues, str) else json.dumps(issues)
            
        if recommendations is not None:
            record.recommendations = recommendations if isinstance(recommendations, str) else json.dumps(recommendations)
            
        if selector is not None and record_type == RecordType.DKIM:
            record.selector = selector
    else:
        # Create new record
        record = DNSRecord(
            domain_id=domain_id,
            type=record_type,
            status=status,
            record_value=record_value,
            last_checked=datetime.utcnow(),
            issues=issues if isinstance(issues, str) else json.dumps(issues) if issues else None,
            recommendations=recommendations if isinstance(recommendations, str) else json.dumps(recommendations) if recommendations else None,
            selector=selector if record_type == RecordType.DKIM else None
        )
        db.add(record)
        
    db.commit()
    db.refresh(record)
    return record

def create_scan_job(
    db: Session,
    *,
    job_id: str,
    domain_id: int,
    user_id: int,
    check_spf: bool = True,
    check_dkim: bool = True,
    check_dmarc: bool = True,
    dkim_selector: str = "default",
    dkim_selectors: Optional[List[str]] = None
) -> ScanJob:
    """Create a new scan job and its initial status record"""
    # Create the scan job
    job = ScanJob(
        job_id=job_id,
        domain_id=domain_id,
        user_id=user_id,
        status="pending",
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
        check_spf=check_spf,
        check_dkim=check_dkim,
        check_dmarc=check_dmarc,
        dkim_selector=dkim_selector,
        dkim_selectors=json.dumps(dkim_selectors) if dkim_selectors else None
    )
    
    db.add(job)
    db.commit()
    db.refresh(job)
    
    # Create initial job status
    job_status = JobStatus(
        job_id=job_id,
        user_id=user_id,
        status="pending",
        progress=0,
        message="Job created, waiting for worker",
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    
    db.add(job_status)
    db.commit()
    
    return job


def update_job_status(
    db: Session,
    *,
    job_id: str,
    status: str,
    progress: int,
    message: Optional[str] = None,
    results: Optional[dict] = None
) -> JobStatus:
    """Update the status of a scan job"""
    # Find job status
    job_status = db.query(JobStatus).filter(JobStatus.job_id == job_id).first()
    
    if not job_status:
        # Create new status if not found
        job_status = JobStatus(
            job_id=job_id,
            status=status,
            progress=progress,
            message=message,
            results=json.dumps(results) if results else None,
            updated_at=datetime.utcnow()
        )
        db.add(job_status)
    else:
        # Update existing status
        job_status.status = status
        job_status.progress = progress
        job_status.updated_at = datetime.utcnow()
        
        if message:
            job_status.message = message
            
        if results:
            job_status.results = json.dumps(results)
    
    # Also update the scan job status
    job = db.query(ScanJob).filter(ScanJob.job_id == job_id).first()
    if job:
        job.status = status
        job.updated_at = datetime.utcnow()
    
    db.commit()
    
    if job_status:
        db.refresh(job_status)
    
    return job_status


def get_scan_job(
    db: Session,
    *,
    job_id: str
) -> Optional[ScanJob]:
    """Get a scan job by ID"""
    return db.query(ScanJob).filter(ScanJob.job_id == job_id).first()
