# auth_microservice_app/config.py
"""
Configuration classes for dev, stag, and prod environments
"""

import os


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
        
        # JWT Settings (for future use)
        self.JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', self.SECRET_KEY)
        self.JWT_ACCESS_TOKEN_EXPIRES = int(os.environ.get('JWT_ACCESS_TOKEN_EXPIRES', '900'))  # 15 minutes
        self.JWT_REFRESH_TOKEN_EXPIRES = int(os.environ.get('JWT_REFRESH_TOKEN_EXPIRES', '2592000'))  # 30 days
        
        # API settings
        self.API_VERSION = 'v1'
        self.API_TITLE = 'Authentication Microservice'
        
        # Redis configuration (for future use)
        self.REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
        
        # Rate limiting
        self.RATE_LIMIT_DEFAULT = os.environ.get('RATE_LIMIT_DEFAULT', '100 per hour')
        
        # CORS
        self.CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*').split(',')


class DevConfig(Config):
    """Development configuration."""
    
    def __init__(self):
        # Set development defaults before calling parent
        os.environ.setdefault('FLASK_ENV', 'dev')
        if not os.environ.get('SECRET_KEY'):
            os.environ['SECRET_KEY'] = 'dev-secret-key-UNSAFE-ONLY-FOR-DEV'
            print("Warning: Using default SECRET_KEY for development")
        
        super().__init__()
        
        # Development specific settings
        self.DEBUG = True
        self.TESTING = False
        
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
        os.environ['FLASK_ENV'] = 'stag'
        super().__init__()
        
        # Staging specific settings
        self.DEBUG = False
        self.TESTING = False
        
        # Staging should mirror production closely
        self.SQLALCHEMY_ECHO = False
        
        # Moderate rate limiting for staging
        self.RATE_LIMIT_DEFAULT = '200 per hour'
        
        # Validate staging configuration
        self._validate_staging_config()
    
    def _validate_staging_config(self):
        """Validate staging configuration."""
        # SECRET_KEY should be different from default
        if 'dev-secret-key' in self.SECRET_KEY.lower():
            raise ValueError("Cannot use development SECRET_KEY in staging")
        
        # Should have proper database URL
        if 'localhost' in self.DATABASE_URL:
            print("Warning: Using localhost database in staging")


class ProdConfig(Config):
    """Production configuration."""
    
    def __init__(self):
        os.environ['FLASK_ENV'] = 'prod'
        super().__init__()
        
        # Production specific settings
        self.DEBUG = False
        self.TESTING = False
        
        # No SQL echo in production
        self.SQLALCHEMY_ECHO = False
        
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
        
        # Database validation
        if 'localhost' in self.DATABASE_URL or 'password' in self.DATABASE_URL:
            raise ValueError("Production DATABASE_URL appears to use default/local settings")
        
        # Ensure JWT secret is different from app secret
        if self.JWT_SECRET_KEY == self.SECRET_KEY:
            print("Warning: JWT_SECRET_KEY should be different from SECRET_KEY in production")
        
        # Ensure specific CORS origins in production
        if '*' in self.CORS_ORIGINS:
            raise ValueError("CORS cannot use wildcard (*) in production. Set specific origins.")


# Configuration mapping
config_map = {
    'dev': DevConfig,
    'stag': StagConfig,
    'prod': ProdConfig
}


def get_config():
    """Get configuration object based on FLASK_ENV."""
    env = os.environ.get('FLASK_ENV', 'prod').lower()
    
    config_class = config_map.get(env)
    if not config_class:
        raise ValueError(f"Unknown environment: {env}. Use 'dev', 'stag', or 'prod'")
    
    return config_class()