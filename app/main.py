"""
InboxGuard - Email DNS Verification System
Main application entry point
"""

import os
from dotenv import load_dotenv
from pathlib import Path
import logging
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.api.v1.router import api_router
from app.core.logging import setup_logging
from app.core.exceptions import InboxGuardException
from app.db import database

env_path = Path(__file__).resolve().parent.parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

from app.core.config import settings


# Setup logging
logger = logging.getLogger("__name__")
logger.setLevel(logging.INFO)
logger.info("Starting InboxGuard application...")
setup_logging()

class ForwardedProtoMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        forwarded_proto = request.headers.get("X-Forwarded-Proto")
        if forwarded_proto:
            request.scope["scheme"] = forwarded_proto
        return await call_next(request)

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="API for verifying and analyzing email DNS settings (SPF, DKIM, and DMARC)",
    version="0.1.0",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=f"{settings.API_V1_STR}/redoc",
)

# Set up CORS middleware
# if settings.BACKEND_CORS_ORIGINS:
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
       "https://inboxguard.app",
       "https://staging.inboxguard.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Session middleware
app.add_middleware(
    TrustedHostMiddleware, 
    allowed_hosts=["inbox-guard.online", "www.inbox-guard.online"]
)

# Add middleware to handle X-Forwarded-Proto header
app.add_middleware(ForwardedProtoMiddleware)


# Include API router
app.include_router(api_router, prefix=settings.API_V1_STR)

# Database connection
@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

# Exception handler
@app.exception_handler(InboxGuardException)
async def inbox_guard_exception_handler(request: Request, exc: InboxGuardException):
    """Handle application-specific exceptions"""
    logger.error(f"Application error: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )

@app.get("/", include_in_schema=False)
async def root():
    """Root endpoint redirects to API documentation"""
    return {"message": f"Welcome to {settings.PROJECT_NAME}. See /api/v1/docs for API documentation."}

@app.get("/debug/routes")
async def debug_routes():
    """Debug endpoint to list all registered routes"""
    routes = []
    for route in app.routes:
        routes.append({
            "path": route.path,
            "name": route.name,
            "methods": [m for m in route.methods] if route.methods else None
        })
    return {"routes": routes}

@app.get("/debug/request")
async def debug_request(request: Request):
    """Debug endpoint to show request information"""
    return {
        "path": request.url.path,
        "base_url": str(request.base_url),
        "headers": dict(request.headers),
        "query_params": dict(request.query_params),
        "client": request.client.host if request.client else None,
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=settings.DEBUG)
