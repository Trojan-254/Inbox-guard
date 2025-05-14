"""
App configuration settings.
"""

import os
import secrets
from pathlib import Path
from typing import List, Optional, Union, Dict, Any
from pydantic import AnyHttpUrl, validator, PostgresDsn
from pydantic_settings import BaseSettings
from pydantic import ConfigDict
from dotenv import load_dotenv

env_path = Path(__file__).resolve().parent.parent.parent / ".env"
load_dotenv(dotenv_path=env_path)


class Settings(BaseSettings):
    """Application setting class"""

    PROJECT_NAME: str = "InboxGuard"
    API_V1_STR: str = "/api/v1"
    DEBUG: bool = False

    # secret key for JWT
    SECRET_KEY: str = secrets.token_urlsafe(32)
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8

    # CORS settings
    BACKEND_CORS_ORIGINS: List[Union[str, AnyHttpUrl]] = []

    @validator("BACKEND_CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        """parse CORS origins from string or list"""
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    # Database settings
    DATABASE_URL: PostgresDsn 

    # DNS service settings
    DNS_RESOLVER_TIMEOUT: int = 5  # seconds
    DNS_RESOLVER_LIFETIME: int = 10  # seconds

    
    # Celery settings
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/0"
    
    # Logging
    LOG_LEVEL: str = "INFO"
    
    # Google OAuth settings
    GOOGLE_CLIENT_ID: str 
    GOOGLE_CLIENT_SECRET: str 
    GOOGLE_REDIRECT_URI: str #"http://localhost:8000/api/v1/auth/google/callback"
    
    # Frontend URL for redirects after authentication
    FRONTEND_URL: str
    
    class Config:
        """Pydantic config"""
        case_sensitive = True
        env_file = ".env"
        model_config = ConfigDict(from_attributes=True)

settings = Settings()