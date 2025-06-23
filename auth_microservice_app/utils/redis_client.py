"""
Redis client for JWT token blacklist management.
"""

import socket
import logging
from typing import Optional, Dict, Any
import redis
from redis.exceptions import ConnectionError, TimeoutError, RedisError

logger = logging.getLogger(__name__)


class RedisClient:
    """Redis client wrapper with connection pooling and error handling."""
    def __init__(self):
       self._client: Optional[redis.Redis] = None
       self._pool: Optional[redis.ConnectionPool] = None
       self._connected: bool = False
       
    def init_app(self, app):
        """
        Initialize Redis connection with Flask app config.
        
        Args:
            app: Flask application instance
        """
        try:
            # Get configuration from app config
            host = app.config.get('REDIS_HOST', 'localhost')
            port = app.config.get('REDIS_PORT', 6379)
            db = app.config.get('REDIS_DB', 0)
            password = app.config.get('REDIS_PASSWORD')
            decode_responses = app.config.get('REDIS_DECODE_RESPONSES', True)
            max_connections = app.config.get('REDIS_MAX_CONNECTIONS', 50)
            socket_timeout = app.config.get('REDIS_SOCKET_TIMEOUT', 5)
            socket_connect_timeout = app.config.get('REDIS_SOCKET_CONNECT_TIMEOUT', 5)
            
            # Create connection pool
            self._pool = redis.ConnectionPool(
                host=host,
                port=port,
                db=db,
                password=password,
                decode_responses=decode_responses,
                max_connections=max_connections,
                socket_timeout=socket_timeout,
                socket_connect_timeout=socket_connect_timeout,
                socket_keepalive=True,
                socket_keepalive_options={
                socket.TCP_KEEPIDLE: 1,
                socket.TCP_KEEPINTVL: 2,
                socket.TCP_KEEPCNT: 5,
                }   

            )
            
            # Create Redis client
            self._client = redis.Redis(connection_pool=self._pool)
            
            # Test connection
            self._client.ping()
            self._connected = True
            logger.info(f"✅ Redis connected successfully to {host}:{port}")
            
        except (ConnectionError, TimeoutError) as e:
            logger.warning(f"⚠️  Redis connection failed: {e}. Running without Redis blacklist.")
            self._connected = False
        except Exception as e:
            logger.error(f"❌ Unexpected Redis error: {e}")
            self._connected = False
    @property
    def is_connected(self) -> bool:
        """Check if Redis is connected."""
        return self._connected
    
    def ping(self) -> bool:
        """Test Redis connection."""
        try:
            if self._client:
                self._client.ping()
                return True
        except Exception:
            self._connected = False
        return False
    
    def add_token_to_blacklist(self, jti: str, token_type: str = "access", expires_delta: int = None) -> bool:
        """
        Add a token to the blacklist.
        
        Args:
            jti: JWT ID (unique identifier for the token)
            token_type: Type of token (access/refresh)
            expires_delta: Seconds until token expires (for auto-cleanup)
            
        Returns:
            True if successfully blacklisted, False otherwise
        """
        if not self._connected or not self._client:
            logger.warning("Redis not connected. Token blacklist unavailable.")
            return False
            
        try:
            key = f"blacklist:{token_type}:{jti}"
            value = "revoked"
            
            if expires_delta:
                # Set with expiration for automatic cleanup
                self._client.setex(key, expires_delta, value)
            else:
                # Set without expiration (handle cleanup separately)
                self._client.set(key, value)
            
            logger.info(f"Token {jti} added to blacklist")
            return True
            
        except RedisError as e:
            logger.error(f"Failed to blacklist token: {e}")
            return False
    
    def is_token_blacklisted(self, jti: str, token_type: str = "access") -> bool:
        """
        Check if a token is blacklisted.
        
        Args:
            jti: JWT ID to check
            token_type: Type of token (access/refresh)
            
        Returns:
            True if blacklisted, False otherwise (including when Redis is down)
        """
        if not self._connected or not self._client:
            # Graceful fallback: if Redis is down, tokens are not blacklisted
            return False
            
        try:
            key = f"blacklist:{token_type}:{jti}"
            return self._client.exists(key) > 0
            
        except RedisError as e:
            logger.error(f"Failed to check blacklist: {e}")
            # Fail open - if we can't check, assume not blacklisted
            return False
    
    def remove_from_blacklist(self, jti: str, token_type: str = "access") -> bool:
        """
        Remove a token from the blacklist.
        
        Args:
            jti: JWT ID to remove
            token_type: Type of token
            
        Returns:
            True if removed, False otherwise
        """
        if not self._connected or not self._client:
            return False
            
        try:
            key = f"blacklist:{token_type}:{jti}"
            return self._client.delete(key) > 0
            
        except RedisError as e:
            logger.error(f"Failed to remove from blacklist: {e}")
            return False
    
    def clear_user_tokens(self, user_id: str) -> int:
        """
        Clear all tokens for a specific user (logout from all devices).
        
        Args:
            user_id: User identifier
            
        Returns:
            Number of tokens cleared
        """
        if not self._connected or not self._client:
            return 0
            
        try:
            # Set a flag that will be checked during token validation
            key = f"user:logout_all:{user_id}"
            # Set with 30 day expiration (longer than any token)
            self._client.setex(key, 30 * 24 * 60 * 60, "true")
            
            logger.info(f"Set logout_all flag for user {user_id}")
            return 1
            
        except RedisError as e:
            logger.error(f"Failed to set logout_all flag: {e}")
            return 0
    
    def is_user_logged_out_all(self, user_id: str) -> bool:
        """
        Check if user has been logged out from all devices.
        
        Args:
            user_id: User identifier
            
        Returns:
            True if user logged out from all devices
        """
        if not self._connected or not self._client:
            return False
            
        try:
            key = f"user:logout_all:{user_id}"
            return self._client.exists(key) > 0
            
        except RedisError:
            return False
    
    def get_blacklist_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the token blacklist.
        
        Returns:
            Dictionary with blacklist statistics
        """
        if not self._connected or not self._client:
            return {"error": "Redis not connected"}
            
        try:
            # Count blacklisted tokens
            access_tokens = sum(1 for _ in self._client.scan_iter("blacklist:access:*", count=1000))
            refresh_tokens = sum(1 for _ in self._client.scan_iter("blacklist:refresh:*", count=1000))
            logout_all_users = sum(1 for _ in self._client.scan_iter("user:logout_all:*", count=1000))
            
            return {
                "access_tokens_blacklisted": access_tokens,
                "refresh_tokens_blacklisted": refresh_tokens,
                "users_logged_out_all": logout_all_users,
                "total_blacklisted": access_tokens + refresh_tokens
            }
            
        except RedisError as e:
            logger.error(f"Failed to get blacklist stats: {e}")
            return {"error": str(e)}
    
    def health_check(self) -> Dict[str, Any]:
        """
        Perform health check on Redis connection.
        
        Returns:
            Health check results
        """
        try:
            if not self._client:
                return {
                    "status": "disconnected",
                    "error": "No Redis client initialized"
                }
            
            # Ping test
            self._client.ping()
            
            # Get Redis info
            info = self._client.info()
            
            # Get blacklist stats
            stats = self.get_blacklist_stats()
            
            return {
                "status": "healthy",
                "connected": True,
                "redis_version": info.get("redis_version", "unknown"),
                "connected_clients": info.get("connected_clients", 0),
                "used_memory_human": info.get("used_memory_human", "unknown"),
                "blacklist_stats": stats
            }
            
        except Exception as e:
            return {
                "status": "unhealthy",
                "connected": False,
                "error": str(e)
            }


# Global Redis client instance
redis_client = RedisClient()


def init_redis(app):
    """
    Initialize Redis with Flask app.
    
    Args:
        app: Flask application instance
    """
    redis_client.init_app(app)
    return redis_client