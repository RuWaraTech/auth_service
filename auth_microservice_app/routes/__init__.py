
from auth_microservice_app.routes.health import health_bp
from auth_microservice_app.routes.auth import auth_bp
from auth_microservice_app.routes.core_auth import core_auth_bp 


# Export all blueprints
__all__ = ['health_bp', 'auth_bp','core_auth_bp']


# # Function to register all blueprints
# def register_all_blueprints(app):
#     """Register all application blueprints with the Flask app."""
  
    
#     api_prefix = f"/api/{app.config.get('API_VERSION', 'v1')}"
#     app.register_blueprint(auth_bp, url_prefix=f"{api_prefix}/auth")
#     app.register_blueprint(health_bp)
    
    
    
    
# Function to register all blueprints
def register_all_blueprints(app):
    """Register all application blueprints with the Flask app."""
    
    api_prefix = f"/api/{app.config.get('API_VERSION', 'v1')}"
    
    # Register existing session management routes
    app.register_blueprint(auth_bp, url_prefix=f"{api_prefix}/session")
    
    # Register new core auth routes (register/login)
    app.register_blueprint(core_auth_bp, url_prefix=f"{api_prefix}/auth")
    
    # Register health check
    app.register_blueprint(health_bp)
    
    app.logger.info("All authentication blueprints registered successfully")
    app.logger.info(f"Session management: {api_prefix}/session/*")
    app.logger.info(f"Core auth: {api_prefix}/auth/*")


"""
Final route structure:
/api/v1/auth/register       - POST (new - user registration)
/api/v1/auth/login          - POST (new - user authentication)
/api/v1/session/logout      - POST (existing - single session logout)
/api/v1/session/logout_all  - POST (existing - multi-device logout)
/api/v1/session/refresh     - POST (existing - token refresh)
/api/v1/session/sessions    - GET (existing - list user sessions)
/api/v1/session/revocation_status - GET (existing - token status)
/api/v1/session/health      - GET (existing - health check)
/health                     - GET (existing - main health check)
"""
    
   
    
 