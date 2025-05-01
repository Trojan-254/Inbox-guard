from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, JSON, Enum
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
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    domain_name = Column(String, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_checked = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="domains")
    dns_records = relationship("DNSRecord", back_populates="domain", cascade="all, delete-orphan")


class DNSRecord(Base):
    __tablename__ = "dns_records"
    
    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False)
    type = Column(Enum(RecordType), nullable=False)
    status = Column(Enum(RecordStatus), default=RecordStatus.PENDING)
    record_value = Column(String, nullable=True)
    last_checked = Column(DateTime, nullable=True)
    
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