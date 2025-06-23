"""
Database models for the authentication microservice.
"""
from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()

from auth_microservice_app.models.user import User
from auth_microservice_app.models.user_session import UserSession

__all__ = [
    "db",
    "User",
    "UserSession"
]

