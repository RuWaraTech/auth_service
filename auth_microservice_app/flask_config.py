"""
Configuration classes for dev, stag, and prod environments
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base configuration with required environment variables."""
    
    def __init__(self):
        # Required configurations
        self.SECRET_KEY = os.environ.get('SECRET_KEY')
        if not self.SECRET_KEY:
            raise ValueError("No SECRET_KEY set for Flask application. Did you follow the setup instructions?")
        
        # Environment setting
        self.FLASK_ENV = os.environ.get('FLASK_ENV', 'prod')
        self.ENV = self.FLASK_ENV  # Flask uses this internally
        
        # Database configuration
        self.DATABASE_URL = os.environ.get(
            'DATABASE_URL',
            'postgresql://auth_user:password@localhost:5432/auth_db'
        )
        self.SQLALCHEMY_DATABASE_URI = self.DATABASE_URL
        self.SQLALCHEMY_TRACK_MODIFICATIONS = False
        
        # Security settings
        self.BCRYPT_LOG_ROUNDS = int(os.environ.get('BCRYPT_LOG_ROUNDS', '12'))
        
        # JWT Settings - Updated for Flask-JWT-Extended
        self.JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', self.SECRET_KEY)
        self.JWT_ALGORITHM = 'HS256'
        
        # Token expiration times (Flask-JWT-Extended expects timedelta objects)
        access_token_expires = int(os.environ.get('JWT_ACCESS_TOKEN_EXPIRES', '900'))  # 15 minutes default
        refresh_token_expires = int(os.environ.get('JWT_REFRESH_TOKEN_EXPIRES', '2592000'))  # 30 days default
        
        self.JWT_ACCESS_TOKEN_EXPIRES = timedelta(seconds=access_token_expires)
        self.JWT_REFRESH_TOKEN_EXPIRES = timedelta(seconds=refresh_token_expires)
        
        # Token locations
        self.JWT_TOKEN_LOCATION = ['headers']  # Can also include 'cookies'
        self.JWT_HEADER_NAME = 'Authorization'
        self.JWT_HEADER_TYPE = 'Bearer'
        
        # Error message key
        self.JWT_ERROR_MESSAGE_KEY = 'message'
        
        # Blacklist settings (for future Redis integration)
        self.JWT_BLACKLIST_ENABLED = True
        self.JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']
        
        # API settings
        self.API_VERSION = 'v1'
        self.API_TITLE = 'Authentication Microservice'
        
        # Redis configuration (TICKET-006)
        self.REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
        self.REDIS_HOST = os.environ.get('REDIS_HOST', 'localhost')
        self.REDIS_PORT = int(os.environ.get('REDIS_PORT', '6379'))
        self.REDIS_DB = int(os.environ.get('REDIS_DB', '0'))
        self.REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD', None)
        self.REDIS_DECODE_RESPONSES = True
        self.REDIS_MAX_CONNECTIONS = 50
        self.REDIS_SOCKET_TIMEOUT = 5
        self.REDIS_SOCKET_CONNECT_TIMEOUT = 5
        
        # Rate limiting
        self.RATE_LIMIT_DEFAULT = os.environ.get('RATE_LIMIT_DEFAULT', '100 per hour')
        self.RATE_LIMIT_LOGIN = os.environ.get('RATE_LIMIT_LOGIN', '10 per minute')
        self.RATE_LIMIT_REGISTER = os.environ.get('RATE_LIMIT_REGISTER', '5 per minute')
        self.RATELIMIT_HEADERS_ENABLED = True
        
        # CORS
        self.CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*').split(',')


class DevConfig(Config):
    """Development configuration."""
    
    def __init__(self):
        # Set development defaults before calling parent
        # Only set defaults if they're not already set in environment
        if not os.environ.get('SECRET_KEY'):
            os.environ['SECRET_KEY'] = 'dev-secret-key-UNSAFE-ONLY-FOR-DEV'
            print("Warning: Using default SECRET_KEY for development")
        
        if not os.environ.get('JWT_SECRET_KEY'):
            os.environ['JWT_SECRET_KEY'] = 'dev-jwt-secret-key-UNSAFE-ONLY-FOR-DEV'
            print("Warning: Using default JWT_SECRET_KEY for development")
        
        super().__init__()
        
        # Development specific settings
        self.DEBUG = True
        self.TESTING = False

        # Override for dev
        self.DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///dev.db')
        self.SQLALCHEMY_DATABASE_URI = self.DATABASE_URL
        
        # Longer token expiration for development convenience
        self.JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
        self.JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=90)
        
        # More permissive rate limiting for development
        self.RATE_LIMIT_DEFAULT = '1000 per hour'
        
        # Allow all origins in development
        self.CORS_ORIGINS = ['*']
        
        # Faster password hashing for development
        self.BCRYPT_LOG_ROUNDS = 4
        
        # Show SQL queries in development
        self.SQLALCHEMY_ECHO = True


class StagConfig(Config):
    """Staging configuration."""
    
    def __init__(self):
        super().__init__()
        
        # Staging specific settings
        self.DEBUG = False
        self.TESTING = False
        
        # Staging should mirror production closely
        self.SQLALCHEMY_ECHO = False
        
        # Standard token expiration for staging
        self.JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=30)
        self.JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
        
        # Moderate rate limiting for staging
        self.RATE_LIMIT_DEFAULT = '200 per hour'
        
        # Validate staging configuration
        self._validate_staging_config()
    
    def _validate_staging_config(self):
        """Validate staging configuration."""
        # SECRET_KEY should be different from default
        if 'dev-secret-key' in self.SECRET_KEY.lower():
            raise ValueError("Cannot use development SECRET_KEY in staging")
        
        # JWT_SECRET_KEY should be different from default
        if 'dev-jwt-secret-key' in self.JWT_SECRET_KEY.lower():
            raise ValueError("Cannot use development JWT_SECRET_KEY in staging")
        
        # Should have proper database URL
        if 'localhost' in self.DATABASE_URL:
            print("Warning: Using localhost database in staging")


class ProdConfig(Config):
    """Production configuration."""
    
    def __init__(self):
        super().__init__()
        
        # Production specific settings
        self.DEBUG = False
        self.TESTING = False
        
        # No SQL echo in production
        self.SQLALCHEMY_ECHO = False
        
        # Strict token expiration in production
        self.JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
        self.JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
        
        # Strict rate limiting in production
        self.RATE_LIMIT_DEFAULT = os.environ.get('RATE_LIMIT_DEFAULT', '60 per hour')
        
        # Production validation
        self._validate_production_config()
    
    def _validate_production_config(self):
        """Validate critical settings for production."""
        # SECRET_KEY validation
        if len(self.SECRET_KEY) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters in production")
        
        if 'dev-secret-key' in self.SECRET_KEY.lower() or 'unsafe' in self.SECRET_KEY.lower():
            raise ValueError("Cannot use development SECRET_KEY in production")
        
        # JWT_SECRET_KEY validation
        if len(self.JWT_SECRET_KEY) < 32:
            raise ValueError("JWT_SECRET_KEY must be at least 32 characters in production")
        
        if 'dev-jwt-secret-key' in self.JWT_SECRET_KEY.lower() or 'unsafe' in self.JWT_SECRET_KEY.lower():
            raise ValueError("Cannot use development JWT_SECRET_KEY in production")
        
        # Database validation
        if 'localhost' in self.DATABASE_URL or 'password' in self.DATABASE_URL:
            raise ValueError("Production DATABASE_URL appears to use default/local settings")
        
        # Ensure JWT secret is different from app secret
        if self.JWT_SECRET_KEY == self.SECRET_KEY:
            print("Warning: JWT_SECRET_KEY should be different from SECRET_KEY in production")
        
        # Ensure specific CORS origins in production
        if '*' in self.CORS_ORIGINS:
            raise ValueError("CORS cannot use wildcard (*) in production. Set specific origins.")


class TestConfig(Config):
    """Testing configuration."""
    
    def __init__(self):
        # Set test defaults
        if not os.environ.get('SECRET_KEY'):
            os.environ['SECRET_KEY'] = 'test-secret-key'
        if not os.environ.get('JWT_SECRET_KEY'):
            os.environ['JWT_SECRET_KEY'] = 'test-jwt-secret-key'
        
        super().__init__()
        
        # Test specific settings
        self.DEBUG = False
        self.TESTING = True
        
        # Use in-memory SQLite for tests
        self.DATABASE_URL = 'sqlite:///:memory:'
        self.SQLALCHEMY_DATABASE_URI = self.DATABASE_URL
        
        # Very short token expiration for testing
        self.JWT_ACCESS_TOKEN_EXPIRES = timedelta(seconds=5)
        self.JWT_REFRESH_TOKEN_EXPIRES = timedelta(minutes=1)
        
        # Disable rate limiting in tests
        self.RATE_LIMIT_DEFAULT = None
        
        # Fast password hashing for tests
        self.BCRYPT_LOG_ROUNDS = 4
        
        # Disable SQL echo in tests
        self.SQLALCHEMY_ECHO = False


# Configuration mapping
config_map = {
    'dev': DevConfig,
    'stag': StagConfig,
    'prod': ProdConfig,
    'test': TestConfig
}


def get_config():
    """Get configuration object based on FLASK_ENV."""
    env = os.environ.get('FLASK_ENV', 'prod').lower()
    
    config_class = config_map.get(env)
    if not config_class:
        raise ValueError(f"Unknown environment: {env}. Use 'dev', 'stag', 'prod', or 'test'")
    
    return config_class()