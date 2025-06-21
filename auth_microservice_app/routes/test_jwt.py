"""
Test routes to verify JWT implementation (TICKET-005).
Remove this file after testing or move logic to proper auth routes.
"""
from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime

from auth_microservice_app.utils.jwt_utils import (
    generate_tokens,
    create_access_token_from_refresh,
    get_token_remaining_time,
    is_token_fresh
)

jwt_test_bp = Blueprint('jwt_test', __name__)


@jwt_test_bp.route('/create-tokens', methods=['POST'])
def create_test_tokens():
    """
    Create test tokens for verification.
    In production, this would be part of login.
    """
    # Simulate a user ID
    test_user_id = "12345"
    
    # Generate tokens
    access_token, refresh_token = generate_tokens(
        identity=test_user_id,
        fresh=True,
        additional_claims={
            "email": "test@example.com",
            "role": "user"
        }
    )
    
    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "timestamp": datetime.utcnow().isoformat()
    }), 200


@jwt_test_bp.route('/protected', methods=['GET'])
@jwt_required()
def protected_route():
    """Test protected route requiring valid access token."""
    current_user = get_jwt_identity()
    remaining_time = get_token_remaining_time()
    token_fresh = is_token_fresh()
    
    return jsonify({
        "message": "Access granted to protected route",
        "user_id": current_user,
        "token_fresh": token_fresh,
        "token_expires_in": remaining_time,
        "timestamp": datetime.utcnow().isoformat()
    }), 200


@jwt_test_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh_token():
    """Test refresh token endpoint."""
    current_user = get_jwt_identity()
    
    # Create new access token
    new_access_token = create_access_token_from_refresh(current_user)
    
    return jsonify({
        "access_token": new_access_token,
        "message": "Token refreshed successfully",
        "timestamp": datetime.utcnow().isoformat()
    }), 200


@jwt_test_bp.route('/fresh-required', methods=['GET'])
@jwt_required(fresh=True)
def fresh_token_required():
    """Test endpoint requiring fresh token."""
    current_user = get_jwt_identity()
    
    return jsonify({
        "message": "Fresh token validated",
        "user_id": current_user,
        "timestamp": datetime.utcnow().isoformat()
    }), 200