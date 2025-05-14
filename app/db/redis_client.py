import redis
import logging
import json
import os
from typing import Optional, Dict, List, Any, Union

logger = logging.getLogger(__name__)

class RedisClient:
    """Redis client for caching job status and results"""
    
    def __init__(self):
        """Initialize Redis connection using environment variables or defaults"""
        redis_host = os.environ.get("REDIS_HOST", "localhost")
        redis_port = int(os.environ.get("REDIS_PORT", 6379))
        redis_db = int(os.environ.get("REDIS_DB", 0))
        redis_password = os.environ.get("REDIS_PASSWORD", None)
        
        try:
            self.redis = redis.Redis(
                host=redis_host,
                port=redis_port,
                db=redis_db,
                password=redis_password,
                decode_responses=True  # Automatically decode responses to strings
            )
            logger.info(f"Connected to Redis at {redis_host}:{redis_port}")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {str(e)}")
            self.redis = None
    
    def set(self, key: str, value: Union[str, Dict, List], ex: Optional[int] = None) -> bool:
        """Set a value in Redis with optional expiration time"""
        try:
            if self.redis is None:
                logger.warning("Redis client not initialized, skipping set operation")
                return False
                
            # Convert dict/list objects to JSON string
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
                
            self.redis.set(key, value, ex=ex)
            return True
        except Exception as e:
            logger.error(f"Redis set error for key {key}: {str(e)}")
            return False
    
    def get(self, key: str) -> Optional[str]:
        """Get a value from Redis"""
        try:
            if self.redis is None:
                logger.warning("Redis client not initialized, skipping get operation")
                return None
                
            return self.redis.get(key)
        except Exception as e:
            logger.error(f"Redis get error for key {key}: {str(e)}")
            return None
    
    def delete(self, key: str) -> bool:
        """Delete a key from Redis"""
        try:
            if self.redis is None:
                logger.warning("Redis client not initialized, skipping delete operation")
                return False
                
            self.redis.delete(key)
            return True
        except Exception as e:
            logger.error(f"Redis delete error for key {key}: {str(e)}")
            return False
    
    def exists(self, key: str) -> bool:
        """Check if a key exists in Redis"""
        try:
            if self.redis is None:
                logger.warning("Redis client not initialized, skipping exists operation")
                return False
                
            return bool(self.redis.exists(key))
        except Exception as e:
            logger.error(f"Redis exists error for key {key}: {str(e)}")
            return False
    
    def lpush(self, key: str, value: Union[str, Dict, List]) -> bool:
        """Push a value to the head of a list"""
        try:
            if self.redis is None:
                logger.warning("Redis client not initialized, skipping lpush operation")
                return False
                
            # Convert dict/list objects to JSON string
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
                
            self.redis.lpush(key, value)
            return True
        except Exception as e:
            logger.error(f"Redis lpush error for key {key}: {str(e)}")
            return False
    
    def lrange(self, key: str, start: int, end: int) -> List[str]:
        """Get a range of values from a list"""
        try:
            if self.redis is None:
                logger.warning("Redis client not initialized, skipping lrange operation")
                return []
                
            return self.redis.lrange(key, start, end)
        except Exception as e:
            logger.error(f"Redis lrange error for key {key}: {str(e)}")
            return []
    
    def ltrim(self, key: str, start: int, end: int) -> bool:
        """Trim a list to the specified range"""
        try:
            if self.redis is None:
                logger.warning("Redis client not initialized, skipping ltrim operation")
                return False
                
            self.redis.ltrim(key, start, end)
            return True
        except Exception as e:
            logger.error(f"Redis ltrim error for key {key}: {str(e)}")
            return False
    
    def ping(self) -> bool:
        """Test Redis connection with ping"""
        try:
            if self.redis is None:
                logger.warning("Redis client not initialized, skipping ping")
                return False
                
            return self.redis.ping()
        except Exception as e:
            logger.error(f"Redis ping error: {str(e)}")
            return False


# Create a global Redis client instance
redis_client = RedisClient()

# Export the client instance
__all__ = ['redis_client']