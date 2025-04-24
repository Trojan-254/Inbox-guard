from sqlalchemy.orm import Session
from datetime import datetime
from typing import List, Optional
from passlib.context import CryptContext
from app.db import models
from app.db.models import User, Domain, DNSRecord, AuditLog, RecordType, RecordStatus

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


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
    hashed_password = pwd_context.hash(password)
    db_user = models.User(
        email=email,
        password=hashed_password,
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

    if not user.password:
        # This might be a Google-only account
        return None

    if not pwd_context.verify(password, user.password):
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
def create_domain(db: Session, user_id: int, domain_name: str):
    db_domain = models.Domain(
        user_id=user_id,
        domain_name=domain_name,
        created_at=datetime.utcnow()
    )
    db.add(db_domain)
    db.commit()
    db.refresh(db_domain)
    return db_domain

def get_user_domains(db: Session, user_id: int, skip: int = 0, limit: int = 100):
    return db.query(models.Domain).filter(models.Domain.user_id == user_id).offset(skip).limit(limit).all()

def get_domain_by_id(db: Session, domain_id: int):
    return db.query(models.Domain).filter(models.Domain.id == domain_id).first()

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

def get_domain_dns_records(db: Session, domain_id: int):
    return db.query(models.DNSRecord).filter(models.DNSRecord.domain_id == domain_id).all()

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