"""
Celery worker configuration for background tasks
"""
import logging
from celery import Celery
from celery.signals import setup_logging

from app.core.config import settings

logger = logging.getLogger(__name__)

# Create Celery application
celery_app = Celery(
    "inboxguard",
    'tasks',
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND
)

# Configure Celery
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    worker_hijack_root_logger=False,
    broker_connection_retry_on_startup=True,
    task_routes={
        "app.worker.tasks.*": {"queue": "inboxguard_queue"}
    },
)

# Use our own logging config
@setup_logging.connect
def configure_logging(*args, **kwargs):
    from app.core.logging import setup_logging
    setup_logging()


def check_celery_health() -> bool:
    """
    Check if Celery is working properly
    
    Returns:
        True if healthy, False otherwise
    """
    try:
        # Try to ping the broker
        insp = celery_app.control.inspect()
        if not insp.stats():
            logger.error("No Celery workers available")
            return False
        return True
    except Exception as e:
        logger.error(f"Celery health check failed: {str(e)}")
        return False