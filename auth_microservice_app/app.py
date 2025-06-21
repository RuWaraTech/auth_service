
from flask import Flask
from flask_migrate import Migrate
from auth_microservice_app.models import db

from auth_microservice_app.flask_config import get_config
from auth_microservice_app.routes import register_all_blueprints
from auth_microservice_app.utils.logger import setup_logger
from auth_microservice_app.middleware.logging import request_id_middleware
from auth_microservice_app.utils.jwt_utils import init_jwt


def create_app():
    """
    Application factory pattern for Flask app creation.
    
    Args:
        config_name: Configuration environment name (development, production, etc.)
    
    Returns:
        Flask application instance
    """

    app= Flask(__name__)
    app.config.from_object(get_config())

    setup_logger()
    request_id_middleware(app)
    init_jwt(app)

    db.init_app(app)
    Migrate(app, db)

    register_all_blueprints(app)


    return app

