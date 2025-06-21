from flask import jsonify
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, decode_token


jwt = JWTManager()


def init_jwt(app):
    """Initialize JWT manager and register error handlers."""
    jwt.init_app(app)

    @jwt.expired_token_loader
    def expired_callback(jwt_header, jwt_payload):
        return jsonify({"msg": "Token has expired"}), 401

    @jwt.invalid_token_loader
    def invalid_callback(error):
        return jsonify({"msg": "Invalid token"}), 422

    @jwt.unauthorized_loader
    def missing_callback(error):
        return jsonify({"msg": "Missing authorization header"}), 401


def generate_tokens(identity):
    """Generate access and refresh tokens for a given identity."""
    access = create_access_token(identity=identity)
    refresh = create_refresh_token(identity=identity)
    return access, refresh


def validate_token(token):
    """Validate a token and return the decoded payload."""
    return decode_token(token)