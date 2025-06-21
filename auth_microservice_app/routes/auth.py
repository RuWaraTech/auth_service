"""
Authentication routes with logout functionality.
"""

from flask import Blueprint, jsonify, request, current_app
from flask_jwt_extended import get_jwt, jwt_required, get_jwt_identity
from datetime import datetime

from auth_microservice_app.utils.jwt_utils import revoke_token, revoke_all_user_tokens


auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """
    Logout current session by revoking the access token.
    The token is added to Redis blacklist.
    """
    try:
        # Get token info
        token = get_jwt()
        jti = token.get("jti")
        token_type = token.get("type", "access")
        
        # Calculate remaining time until token expires
        exp_timestamp = token.get("exp")
        if exp_timestamp:
            current_timestamp = datetime.utcnow().timestamp()
            expires_delta = int(exp_timestamp - current_timestamp)
        else:
            expires_delta = None
        
        # Revoke the token
        success = revoke_token(jti, token_type, expires_delta)
        
        if success:
            current_app.logger.info(f"User {get_jwt_identity()} logged out successfully")
            return jsonify({
                "message": "Successfully logged out",
                "timestamp": datetime.utcnow().isoformat()
            }), 200
        else:
            # Redis might be down, but we still return success
            # The token will expire naturally
            return jsonify({
                "message": "Logged out (token will expire naturally)",
                "warning": "Token revocation service temporarily unavailable",
                "timestamp": datetime.utcnow().isoformat()
            }), 200
            
    except Exception as e:
        current_app.logger.error(f"Logout error: {e}")
        return jsonify({
            "error": "logout_failed",
            "message": "An error occurred during logout"
        }), 500
        
        
@auth_bp.route('/logout_all', methods=['POST'])
@jwt_required(fresh=True)  # Require fresh token for security
def logout_all_devices():
    """
    Logout from all devices by invalidating all user tokens.
    Requires a fresh token for security.
    """
    try:
        user_id = get_jwt_identity()
        
        # Revoke all tokens for this user
        success = revoke_all_user_tokens(user_id)
        
        if success:
            current_app.logger.info(f"User {user_id} logged out from all devices")
            return jsonify({
                "message": "Successfully logged out from all devices",
                "timestamp": datetime.utcnow().isoformat()
            }), 200
        else:
            return jsonify({
                "message": "Logout attempted (tokens will expire naturally)",
                "warning": "Token revocation service temporarily unavailable",
                "timestamp": datetime.utcnow().isoformat()
            }), 200
            
    except Exception as e:
        current_app.logger.error(f"Logout all devices error: {e}")
        return jsonify({
            "error": "logout_all_failed",
            "message": "An error occurred during logout"
        }), 500       

@auth_bp.route('/revocation_status', methods=['GET'])
@jwt_required()
def check_revocation_status():
    """
    Check if the current token has been revoked.
    Useful for debugging and testing.
    """
    try:
        token = get_jwt()
        jti = token.get("jti")
        
        # This endpoint works because the token hasn't been checked yet
        # In normal flow, revoked tokens are rejected before reaching the endpoint
        from auth_microservice_app.utils.redis_client import redis_client
        
        is_blacklisted = redis_client.is_token_blacklisted(jti)
        
        return jsonify({
            "jti": jti,
            "blacklisted": is_blacklisted,
            "redis_connected": redis_client.is_connected,
            "timestamp": datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({
            "error": "check_failed",
            "message": str(e)
        }), 500