"""
Health check endpoints for monitoring
"""
import logging
from typing import Dict
from fastapi import APIRouter, Depends, HTTPException
from app.services.dns.lookup import check_dns_resolver_health
from app.worker.celery_app import check_celery_health

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/", response_model=Dict[str, str])
async def health_check():
    """
    Basic health check endpoint to verify API is running
    """
    return {"status": "healthy"}


@router.get("/readiness", response_model=Dict[str, Dict[str, str]])
async def readiness_check():
    """
    More comprehensive health check that verifies connectivity to dependencies
    """
    health_status = {
        "api": {"status": "healthy"},
    }
    
    # Check DNS resolver
    try:
        dns_healthy = await check_dns_resolver_health()
        health_status["dns_resolver"] = {
            "status": "healthy" if dns_healthy else "unhealthy"
        }
    except Exception as e:
        logger.error(f"DNS resolver health check failed: {str(e)}")
        health_status["dns_resolver"] = {"status": "unhealthy", "reason": str(e)}
    
    # Check Celery
    try:
        celery_healthy = check_celery_health()
        health_status["celery"] = {
            "status": "healthy" if celery_healthy else "unhealthy"
        }
    except Exception as e:
        logger.error(f"Celery health check failed: {str(e)}")
        health_status["celery"] = {"status": "unhealthy", "reason": str(e)}
    
    # Determine overall health
    if all(component["status"] == "healthy" for component in health_status.values()):
        return health_status
    else:
        # Still return the health information but with a 503 status code
        raise HTTPException(status_code=503, detail=health_status)


