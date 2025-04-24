"""
API router that includes all API endpoint routers
"""
from fastapi import APIRouter

from app.api.v1.endpoints import dns_verification, health, auth
from app.auth.google import router as google_router

api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(
    dns_verification.router, 
    prefix="/dns", 
    tags=["DNS Verification"]
)
api_router.include_router(
    health.router, 
    prefix="/health", 
    tags=["Health"]
)

# Add more routers as needed
api_router.include_router(
    auth.router,
    prefix="/auth",
    tags=["Authentication"]
)

api_router.include_router(
    google_router,
    prefix="/auth/google",
    tags=["Google Authentication"]
)

# api_router.include_router(
#     users.router,
#     prefix="/users",
#     tags=["Users"]
# )

# api_router.include_router(
#     domains.router,
#     prefix="/domains",
#     tags=["Domains"]
# )
# api_router.include_router(
#     dns_records.router,
#     prefix="/dns-records",
#     tags=["DNS Records"]
# )
# api_router.include_router(
#     audit_logs.router,
#     prefix="/audit-logs",
#     tags=["Audit Logs"]
# )
# api_router.include_router(
#     notifications.router,
#     prefix="/notifications",
#     tags=["Notifications"]
# )
# api_router.include_router(
#     settings.router,
#     prefix="/settings",
#     tags=["Settings"]
# )


# api_router.include_router(
#     reports.router,
#     prefix="/reports",
#     tags=["Reports"]
# )

# api_router.include_router(
#     tasks.router,
#     prefix="/security",
