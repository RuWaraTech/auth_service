"""
    Register all application blueprints with the Flask app.
    This module imports and registers all blueprints for the application.
    Each blueprint corresponds to a specific functionality or route group.
    The blueprints are registered without a prefix for health and monitoring routes,
    and with an API version prefix for other routes.
    The health blueprint is available at the root URL."""

from auth_microservice_app.routes.health import health_bp

# Export all blueprints
__all__ = ['health_bp']



# Function to register all blueprints
def register_all_blueprints(app):
    """Register all application blueprints with the Flask app."""
    
    # Health and monitoring routes (no prefix - available at root)
    app.register_blueprint(health_bp)
    
    # Future blueprints with API versioning:
    # from auth_microservice_app.routes.auth import auth_bp
    # from auth_microservice_app.routes.oauth import oauth_bp
    # from auth_microservice_app.routes.user import user_bp
    
    # api_prefix = f"/api/{app.config.get('API_VERSION', 'v1')}"
    # app.register_blueprint(auth_bp, url_prefix=f"{api_prefix}/auth")
    # app.register_blueprint(oauth_bp, url_prefix=f"{api_prefix}/oauth")
    # app.register_blueprint(user_bp, url_prefix=f"{api_prefix}/user")