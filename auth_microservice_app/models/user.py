"""
User model for the authentication microservice.
"""

from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from auth_microservice_app.models import db


class User(db.Model):
    """
    User model for the authentication microservice.
    
    Attributes:
        id (int): Unique identifier for the user.
        username (str): Username of the user.
        email (str): Email address of the user.
        password (str): Hashed password of the user.
        created_at (datetime): Timestamp when the user was created.
        updated_at (datetime): Timestamp when the user was last updated.
        last_login (datetime): Timestamp of the user's last login.
        is_active (bool): Whether the user account is active.
        failed_login_attempts (int): Number of consecutive failed login attempts.
        locked_until (datetime): Timestamp until which the account is locked.
        
    Methods:
        set_password: Hash and set the user's password.
        check_password: Verify a password against the stored hash.
        update_last_login: Update the last login timestamp.
        is_account_locked: Check if the account is currently locked.
        increment_failed_attempts: Increment failed login attempts.
        reset_failed_attempts: Reset failed login attempts counter.
        lock_account: Lock the account for a specified duration.
        to_dict: Convert user object to dictionary representation.
        __repr__: String representation of the User object.
    """
    
    __tablename__ = 'users'
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # User credentials
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password = db.Column(db.String(128), nullable=False)
    
    # Account status
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    
    # Security fields
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(
        db.DateTime, 
        default=lambda: datetime.now(timezone.utc), 
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    last_login = db.Column(db.DateTime, nullable=True)
    
    def set_password(self, password: str) -> None:
        """
        Hash and set the user's password.
        
        Args:
            password: Plain text password to hash and store
        """
        self.password = generate_password_hash(password)
    
    def check_password(self, password: str) -> bool:
        """
        Verify a password against the stored hash.
        
        Args:
            password: Plain text password to verify
            
        Returns:
            True if password matches, False otherwise
        """
        return check_password_hash(self.password, password)
    
    def update_last_login(self) -> None:
        """Update the last login timestamp to current UTC time."""
        self.last_login = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)
    
    def is_account_locked(self) -> bool:
        """
        Check if the account is currently locked.
        
        Returns:
            True if account is locked, False otherwise
        """
        if self.locked_until is None:
            return False
        return datetime.now(timezone.utc) < self.locked_until
    
    def increment_failed_attempts(self) -> None:
        """Increment the failed login attempts counter."""
        self.failed_login_attempts += 1
        self.updated_at = datetime.now(timezone.utc)
    
    def reset_failed_attempts(self) -> None:
        """Reset the failed login attempts counter."""
        self.failed_login_attempts = 0
        self.locked_until = None
        self.updated_at = datetime.now(timezone.utc)
    
    def lock_account(self, duration_minutes: int = 30) -> None:
        """
        Lock the account for a specified duration.
        
        Args:
            duration_minutes: Number of minutes to lock the account
        """
        from datetime import timedelta
        self.locked_until = datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)
        self.updated_at = datetime.now(timezone.utc)
    
    def to_dict(self, include_sensitive: bool = False) -> dict:
        """
        Convert user object to dictionary representation.
        
        Args:
            include_sensitive: Whether to include sensitive fields like failed attempts
            
        Returns:
            Dictionary representation of the user
        """
        user_dict = {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
        }
        
        if include_sensitive:
            user_dict.update({
                'failed_login_attempts': self.failed_login_attempts,
                'locked_until': self.locked_until.isoformat() if self.locked_until else None,
                'is_locked': self.is_account_locked()
            })
        
        return user_dict
    
    @classmethod
    def find_by_username(cls, username: str):
        """
        Find a user by username.
        
        Args:
            username: Username to search for
            
        Returns:
            User object or None if not found
        """
        return cls.query.filter_by(username=username).first()
    
    @classmethod
    def find_by_email(cls, email: str):
        """
        Find a user by email.
        
        Args:
            email: Email to search for
            
        Returns:
            User object or None if not found
        """
        return cls.query.filter_by(email=email).first()
    
    @classmethod
    def find_by_username_or_email(cls, identifier: str):
        """
        Find a user by username or email.
        
        Args:
            identifier: Username or email to search for
            
        Returns:
            User object or None if not found
        """
        return cls.query.filter(
            (cls.username == identifier) | (cls.email == identifier)
        ).first()
    
    def __repr__(self) -> str:
        """String representation of the User object."""
        return f'<User {self.username}>'


