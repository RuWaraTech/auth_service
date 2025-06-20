import os
from flask import Flask, jsonify
from datetime import datetime
from auth_microservice_app.flask_config import Config

def create_app():
    """
    Application factory pattern for Flask app creation.
    
    Args:
        config_name: Configuration environment name (development, production, etc.)
    
    Returns:
        Flask application instance
    """

    app= Flask(__name__)
    app.config.from_object(Config())
 

    return app

