
from auth_microservice_app.routes.health import health_bp
from auth_microservice_app.routes.auth import auth_bp


# Export all blueprints
__all__ = ['health_bp', 'auth_bp']


# Function to register all blueprints
def register_all_blueprints(app):
    """Register all application blueprints with the Flask app."""
  
    
    api_prefix = f"/api/{app.config.get('API_VERSION', 'v1')}"
    app.register_blueprint(auth_bp, url_prefix=f"{api_prefix}/auth")
    app.register_blueprint(health_bp)
    
    
    
    
    
    
    
    
   
    
 