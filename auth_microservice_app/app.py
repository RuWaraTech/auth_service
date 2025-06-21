from flask import Flask
from flask_migrate import Migrate
from auth_microservice_app.models import db
from auth_microservice_app.flask_config import get_config
from auth_microservice_app.routes import register_all_blueprints
from auth_microservice_app.utils import setup_logger, init_jwt, init_redis
from auth_microservice_app.middleware.logging import request_id_middleware

def create_app():
    """
    Application factory pattern for Flask app creation.
    
    Returns:
        Flask application instance
    """
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(get_config())
    
    # Initialize logging
    setup_logger()
    request_id_middleware(app)
    
    # Initialize Redis (TICKET-006)
    init_redis(app)
    
    # Initialize JWT with Redis blacklist support
    init_jwt(app)
    
    # Initialize database
    db.init_app(app)
    Migrate(app, db)
    
    # Register blueprints
    register_all_blueprints(app)
    
    return app