from flask import Blueprint, jsonify, current_app
from datetime import datetime

health_bp = Blueprint('health', __name__)

@health_bp.route('/')
def index():
    """Root endpoint - Service information."""
    return jsonify({
        'service': 'Authentication Microservice',
        'version': '0.1.0',
        'status': 'running',
        'environment': current_app.config.get('ENV', 'not set'),
        'debug': current_app.debug,
        'timestamp': datetime.utcnow().isoformat()
    })

@health_bp.route('/health')
def health_check():
    """Basic health check endpoint for monitoring."""
    return jsonify({
        'status': 'healthy',
        'service': 'auth_microservice',
        'timestamp': datetime.utcnow().isoformat()
    }), 200

@health_bp.route('/ready')
def readiness_check():
    """
    Readiness check endpoint.
    Verifies the service is ready to accept requests.
    """
    checks = {
        'app': True,
        # Future: 'database': check_database(),
        # Future: 'redis': check_redis(),
    }
    
    all_ready = all(checks.values())
    status_code = 200 if all_ready else 503
    
    return jsonify({
        'ready': all_ready,
        'checks': checks,
        'timestamp': datetime.utcnow().isoformat()
    }), status_code

@health_bp.route('/ping')
def ping():
    """Simple ping endpoint."""
    return jsonify({'pong': True}), 200

