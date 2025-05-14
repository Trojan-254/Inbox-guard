from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, JSON, Enum, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import enum
from datetime import datetime
import uuid

Base = declarative_base()

class RecordType(str, enum.Enum):
    SPF = "SPF"
    DKIM = "DKIM"
    DMARC = "DMARC"

class RecordStatus(str, enum.Enum):
    VALID = "valid"
    WARNING = "warning"
    CRITICAL = "critical"
    PENDING = "pending"

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=True)
    name = Column(String, nullable=False)
    google_id = Column(String, unique=True, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # Relationships
    domains = relationship("Domain", back_populates="user", cascade="all, delete-orphan")
    logs = relationship("AuditLog", back_populates="user")


class Domain(Base):
    __tablename__ = "domains"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    domain_name = Column(String, index=True)
    original_input = Column(String, nullable=True)
    input_type = Column(String, nullable=True)
    email_prefix = Column(String, nullable=True)
    notes = Column(String, nullable=True)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)
    last_checked = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    deleted_at = Column(DateTime, nullable=True)

    dns_records = relationship("DNSRecord", back_populates="domain", cascade="all, delete-orphan")
    user = relationship("User", back_populates="domains")

class DNSRecord(Base):
    __tablename__ = "dns_records"
    
    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False)
    type = Column(Enum(RecordType), nullable=False)
    status = Column(Enum(RecordStatus), default=RecordStatus.PENDING)
    record_value = Column(String, nullable=True)
    last_checked = Column(DateTime, nullable=True)

    issues = Column(JSON, nullable=True)    
    recommendations = Column(JSON, nullable=True)
    details = Column(JSON, nullable=True)        
    selector = Column(String, nullable=True)
    
    # Relationships
    domain = relationship("Domain", back_populates="dns_records")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    action = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    extradata = Column(JSON, nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="logs")

class ScanJob(Base):
    __tablename__ = "scan_job"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(String, unique=True, nullable=False, index=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False)
    status = Column(String, default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    check_spf = Column(Boolean, default=True)
    check_dkim = Column(Boolean, default=True) 
    check_dmarc = Column(Boolean, default=True)
    dkim_selector = Column(String, default="default")
    dkim_selectors = Column(JSON, nullable=True)  # Store multiple selectors as JSON array
    
    
    # Relationships
    user = relationship("User")
    domain = relationship("Domain")
    job_status = relationship("JobStatus", uselist=False, back_populates="scan_job", cascade="all, delete-orphan")


class JobStatus(Base):
    __tablename__ = "job_status"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(String, ForeignKey("scan_job.job_id"), nullable=False, unique=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    status = Column(String, default="pending")
    progress = Column(Integer, default=0)
    message = Column(String, nullable=True)
    results = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship("User")
    scan_job = relationship("ScanJob", back_populates="job_status")