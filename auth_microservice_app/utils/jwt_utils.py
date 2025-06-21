from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple
import logging


from flask import jsonify
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token, decode_token, get_jwt, get_jwt_identity
)

logger = logging.getLogger(__name__)
jwt = JWTManager()

def init_jwt(app):
    """
    Initialize JWT manager with the Flask app.
    
    Args:
        app: Flask application instance
    """
    jwt.init_app(app)

    
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