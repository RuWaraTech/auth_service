"""
Authentication routes with improved logout functionality.
"""

from flask import Blueprint, jsonify, request, current_app
from flask_jwt_extended import (
    get_jwt, 
    jwt_required, 
    get_jwt_identity,
    create_access_token
)
from datetime import datetime, timezone

from auth_microservice_app.utils.jwt_utils import (
    revoke_token, 
    revoke_all_user_tokens,
    generate_new_token_after_logout_all,
    get_user_sessions,
    create_access_token_from_refresh
)
from auth_microservice_app.utils.redis_client import redis_client


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
            current_timestamp = datetime.now(timezone.utc).timestamp()
            expires_delta = int(exp_timestamp - current_timestamp)
        else:
            expires_delta = None
        
        # Revoke the token
        success = revoke_token(jti, token_type, expires_delta)
        
        if success:
            current_app.logger.info(f"User {get_jwt_identity()} logged out successfully")
            return jsonify({
                "message": "Successfully logged out",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }), 200
        else:
            # Redis might be down, but we still return success
            # The token will expire naturally
            return jsonify({
                "message": "Logged out (token will expire naturally)",
                "warning": "Token revocation service temporarily unavailable",
                "timestamp": datetime.now(timezone.utc).isoformat()
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
    Optionally keeps the current session active.
    Requires a fresh token for security.
    """
    try:
        user_id = get_jwt_identity()
        current_token = get_jwt()
        current_jti = current_token.get("jti")
        
        # Check if user wants to keep current session (default: True)
        body = request.get_json() or {}
        keep_current_session = body.get('keep_current_session', True)
        
        # Get session info for new token if keeping current session
        session_info = None
        if keep_current_session:
            session_info = {
                "ip": request.remote_addr,
                "user_agent": request.headers.get('User-Agent', 'Unknown'),
                "device": body.get('device', 'Unknown'),
                "logout_all_survivor": True
            }
        
        # Revoke all tokens for this user
        if keep_current_session:
            success = revoke_all_user_tokens(user_id, exclude_current_jti=current_jti)
            message = "Successfully logged out from all other devices"
        else:
            success = revoke_all_user_tokens(user_id)
            message = "Successfully logged out from all devices"
        
        if success:
            current_app.logger.info(
                f"User {user_id} logged out from all devices (keep_current: {keep_current_session})"
            )
            
            response_data = {
                "message": message,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "current_session_active": keep_current_session
            }
            
            # If keeping current session, optionally issue a new token
            if keep_current_session:
                # Check if user wants a new token
                issue_new_token = body.get('issue_new_token', True)
                
                if issue_new_token:
                    # Generate a fresh token to replace the current one
                    new_access_token = generate_new_token_after_logout_all(
                        user_id, 
                        session_info
                    )
                    response_data["new_access_token"] = new_access_token
                    response_data["message"] += ". A new access token has been issued."
                else:
                    response_data["message"] += ". Your current token remains valid."
            
            return jsonify(response_data), 200
        else:
            return jsonify({
                "message": "Logout attempted (tokens will expire naturally)",
                "warning": "Token revocation service temporarily unavailable",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }), 200
            
    except Exception as e:
        current_app.logger.error(f"Logout all devices error: {e}")
        return jsonify({
            "error": "logout_all_failed",
            "message": "An error occurred during logout"
        }), 500


@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh_token():
    """
    Generate new access token from refresh token.
    """
    try:
        identity = get_jwt_identity()
        
        # Get session info from request
        body = request.get_json() or {}
        session_info = {
            "ip": request.remote_addr,
            "user_agent": request.headers.get('User-Agent', 'Unknown'),
            "device": body.get('device', 'Unknown'),
            "refreshed_at": datetime.now(timezone.utc).isoformat()
        }
        
        # Create new access token
        access_token = create_access_token_from_refresh(
            identity=identity,
            track_session=True,
            session_info=session_info
        )
        
        return jsonify({
            "access_token": access_token,
            "token_type": "bearer",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Token refresh error: {e}")
        return jsonify({
            "error": "refresh_failed",
            "message": "Failed to refresh token"
        }), 500


@auth_bp.route('/sessions', methods=['GET'])
@jwt_required()
def list_sessions():
    """
    List all active sessions for the current user.
    """
    try:
        user_id = get_jwt_identity()
        current_jti = get_jwt().get("jti")
        
        # Get all sessions
        sessions = get_user_sessions(user_id)
        
        # Mark current session
        for session in sessions:
            session['is_current'] = session.get('jti') == current_jti
        
        # Sort by creation time (newest first)
        sessions.sort(
            key=lambda s: s.get('created_at', ''), 
            reverse=True
        )
        
        return jsonify({
            "sessions": sessions,
            "total": len(sessions),
            "current_jti": current_jti,
            "note": "Device management features coming soon"
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"List sessions error: {e}")
        return jsonify({
            "error": "list_sessions_failed",
            "message": "Failed to retrieve sessions"
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
        user_id = get_jwt_identity()
        
        # Check various revocation statuses
        is_blacklisted = redis_client.is_token_blacklisted(jti)
        is_whitelisted = redis_client.is_token_whitelisted(jti, user_id)
        logout_all_timestamp = redis_client.get_logout_all_timestamp(user_id)
        
        # Token issued at
        iat = token.get("iat")
        
        # Determine if token would be revoked
        would_be_revoked = is_blacklisted
        if not would_be_revoked and logout_all_timestamp and iat:
            would_be_revoked = iat < logout_all_timestamp and not is_whitelisted
        
        return jsonify({
            "jti": jti,
            "user_id": user_id,
            "blacklisted": is_blacklisted,
            "whitelisted": is_whitelisted,
            "logout_all_active": logout_all_timestamp is not None,
            "logout_all_timestamp": logout_all_timestamp,
            "token_issued_at": iat,
            "would_be_revoked": would_be_revoked,
            "redis_connected": redis_client.is_connected,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({
            "error": "check_failed",
            "message": str(e)
        }), 500


@auth_bp.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint for the auth service.
    """
    try:
        # Check Redis health
        redis_health = redis_client.health_check()
        
        # Overall health
        is_healthy = redis_health.get("status") == "healthy" or not redis_client.is_connected
        
        return jsonify({
            "status": "healthy" if is_healthy else "degraded",
            "service": "auth",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "redis": redis_health,
            "version": "1.0.0"
        }), 200 if is_healthy else 503
        
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "service": "auth",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 503