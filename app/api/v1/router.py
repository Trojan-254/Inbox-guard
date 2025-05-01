"""
API router that includes all API endpoint routers
"""
from fastapi import APIRouter
from app.api.v1.endpoints import dns_verification, health, auth, domains, google_oauth

api_router = APIRouter()

# dns analysis
api_router.include_router(
    dns_verification.router, 
    prefix="/dns", 
    tags=["DNS Verification"]
)

# Health check
api_router.include_router(
    health.router, 
    prefix="/health", 
    tags=["Health"]
)

# Authentication and Authorization
api_router.include_router(
    auth.router,
    prefix="/auth",
    tags=["Authentication"]
)

# google auth
api_router.include_router(
    google_oauth.router,
    prefix="/auth/google",
    tags=["Google Authentication"]
)

# domain management
api_router.include_router(
    domains.router,
    prefix="/domains",
    tags=["Domains"]    
)
