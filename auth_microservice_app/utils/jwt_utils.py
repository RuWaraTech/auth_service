"""
JWT token management utilities for authentication.
Implements TICKET-005: JWT Integration with Flask-JWT-Extended
Updated for TICKET-006: Redis Integration for Token Blacklist
"""
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple
import logging

from flask import jsonify, current_app
from flask_jwt_extended import (
    JWTManager, 
    create_access_token, 
    create_refresh_token, 
    decode_token,
    get_jwt,
    get_jwt_identity
)

from auth_microservice_app.utils.redis_client import redis_client

logger = logging.getLogger(__name__)

# Initialize JWT Manager
jwt = JWTManager()


def init_jwt(app):
    """
    Initialize JWT manager with error handlers and Redis blacklist.
    
    Args:
        app: Flask application instance
    """
    jwt.init_app(app)
    
    # Token blacklist loader - check if token is revoked in Redis
    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header: Dict[str, Any], jwt_payload: Dict[str, Any]) -> bool:
        """Check if the token has been revoked via Redis blacklist."""
        jti = jwt_payload.get("jti")
        if not jti:
            return True
        
        # Check if user has been logged out from all devices
        user_id = jwt_payload.get("sub")
        if user_id and redis_client.is_user_logged_out_all(user_id):
            # Check if token was issued before logout_all
            # This prevents old tokens from being used after logout_all
            return True
        
        # Check if specific token is blacklisted
        token_type = jwt_payload.get("type", "access")
        return redis_client.is_token_blacklisted(jti, token_type)
    
    # Register error handlers
    
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header: Dict[str, Any], jwt_payload: Dict[str, Any]):
        """Handle expired token errors."""
        logger.warning(f"Expired token accessed by user: {jwt_payload.get('sub')}")
        return jsonify({
            "error": "token_expired",
            "message": "The access token has expired. Please refresh your token."
        }), 401
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error: str):
        """Handle invalid token errors."""
        logger.warning(f"Invalid token error: {error}")
        return jsonify({
            "error": "invalid_token",
            "message": f"Token validation failed: {error}"
        }), 422
    
    @jwt.unauthorized_loader
    def missing_token_callback(error: str):
        """Handle missing authorization header."""
        return jsonify({
            "error": "authorization_required",
            "message": "Missing Authorization Header. Please provide a valid token."
        }), 401
    
    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header: Dict[str, Any], jwt_payload: Dict[str, Any]):
        """Handle revoked token."""
        logger.warning(f"Revoked token accessed by user: {jwt_payload.get('sub')}")
        return jsonify({
            "error": "token_revoked",
            "message": "The token has been revoked and is no longer valid."
        }), 401
    
    @jwt.needs_fresh_token_loader
    def token_not_fresh_callback(jwt_header: Dict[str, Any], jwt_payload: Dict[str, Any]):
        """Handle operations requiring fresh token."""
        return jsonify({
            "error": "fresh_token_required",
            "message": "A fresh access token is required for this operation. Please re-authenticate."
        }), 401
    
    # Log successful initialization
    logger.info("JWT Manager initialized successfully")


def generate_tokens(
    identity: str,
    fresh: bool = False,
    additional_claims: Optional[Dict[str, Any]] = None
) -> Tuple[str, str]:
    """
    Generate access and refresh tokens for a given identity.
    
    Args:
        identity: User identifier (usually user_id or email)
        fresh: Whether to create a fresh access token
        additional_claims: Extra claims to include in access token
        
    Returns:
        Tuple of (access_token, refresh_token)
    """
    # Prepare claims
    claims = additional_claims or {}
    
    # Create access token
    access_token = create_access_token(
        identity=identity,
        fresh=fresh,
        additional_claims=claims
    )
    
    # Create refresh token
    refresh_token = create_refresh_token(identity=identity)
    
    logger.info(f"Generated tokens for user: {identity}, fresh: {fresh}")
    
    return access_token, refresh_token


def create_access_token_from_refresh(identity: str) -> str:
    """
    Create a new access token from refresh token.
    
    Args:
        identity: User identifier
        
    Returns:
        New access token (not fresh)
    """
    return create_access_token(identity=identity, fresh=False)


def validate_token(token: str) -> Dict[str, Any]:
    """
    Validate a token and return the decoded payload.
    
    Args:
        token: JWT token string
        
    Returns:
        Decoded token payload
        
    Raises:
        Exception: If token validation fails
    """
    try:
        # Decode and validate the token
        payload = decode_token(token)
        
        # Check token type (should not be refresh token for most operations)
        if payload.get("type") == "refresh":
            raise ValueError("Cannot use refresh token for this operation")
        
        logger.debug(f"Token validated for user: {payload.get('sub')}")
        return payload
        
    except Exception as e:
        logger.error(f"Token validation failed: {str(e)}")
        raise


def get_token_identity() -> Optional[str]:
    """
    Get the identity of the current JWT token.
    
    Returns:
        User identity from the token
    """
    return get_jwt_identity()


def get_current_token_claims() -> Dict[str, Any]:
    """
    Get all claims from the current JWT token.
    
    Returns:
        Dictionary of token claims
    """
    return get_jwt()


# Utility functions for token information

def get_token_remaining_time() -> Optional[int]:
    """
    Get remaining time in seconds for the current token.
    
    Returns:
        Seconds until token expiration
    """
    claims = get_jwt()
    exp_timestamp = claims.get("exp")
    
    if exp_timestamp:
        current_timestamp = datetime.now(timezone.utc).timestamp()
        return int(exp_timestamp - current_timestamp)
    
    return None


def revoke_token(jti: str, token_type: str = "access", expires_delta: int = None) -> bool:
    """
    Revoke a token by adding it to the Redis blacklist.
    
    Args:
        jti: JWT ID from the token
        token_type: Type of token (access/refresh)
        expires_delta: Seconds until token naturally expires
        
    Returns:
        Success status
    """
    try:
        success = redis_client.add_token_to_blacklist(jti, token_type, expires_delta)
        if success:
            logger.info(f"Token {jti} revoked successfully")
        else:
            logger.warning(f"Failed to revoke token {jti} - Redis may be unavailable")
        return success
    except Exception as e:
        logger.error(f"Error revoking token: {e}")
        return False


def revoke_all_user_tokens(user_id: str) -> bool:
    """
    Revoke all tokens for a specific user (logout from all devices).
    
    Args:
        user_id: User identifier
        
    Returns:
        Success status
    """
    try:
        count = redis_client.clear_user_tokens(user_id)
        if count > 0:
            logger.info(f"All tokens revoked for user {user_id}")
            return True
        else:
            logger.warning(f"Failed to revoke all tokens for user {user_id}")
            return False
    except Exception as e:
        logger.error(f"Error revoking all user tokens: {e}")
        return False


def is_token_revoked(jti: str, token_type: str = "access") -> bool:
    """
    Check if a token is revoked.
    
    Args:
        jti: JWT ID to check
        token_type: Type of token
        
    Returns:
        True if revoked, False otherwise
    """
    return redis_client.is_token_blacklisted(jti, token_type)


def is_token_fresh() -> bool:
    """
    Check if the current token is fresh.
    
    Returns:
        True if token is fresh, False otherwise
    """
    claims = get_jwt()
    return claims.get("fresh", False)