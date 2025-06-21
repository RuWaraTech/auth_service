from flask_sqlalchemy import SQLAlchemy
from auth_microservice_app.models.user import User

db = SQLAlchemy()


__all__ = [
	'db',
	'User',
]