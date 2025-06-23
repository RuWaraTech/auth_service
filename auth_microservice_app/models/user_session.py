# auth_microservice_app/models/user_session.py (Optional future enhancement)
"""
User session model for tracking active sessions.
This could replace or complement the Redis session tracking.
"""

from datetime import datetime, timezone
from auth_microservice_app.models import db

class UserSession(db.Model):
    """
    Model to track user sessions in the database.
    This is an alternative/complement to Redis session tracking.
    """
    
    __tablename__ = 'user_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    jti = db.Column(db.String(36), unique=True, nullable=False, index=True)  # JWT ID
    
    # Session metadata
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 compatible
    user_agent = db.Column(db.Text, nullable=True)
    device_info = db.Column(db.String(255), nullable=True)
    
    # Session lifecycle
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_activity = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    revoked_at = db.Column(db.DateTime, nullable=True)
    
    # Session flags
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    logout_all_survivor = db.Column(db.Boolean, default=False, nullable=False)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('sessions', lazy=True, cascade='all, delete-orphan'))
    
    def revoke(self):
        """Mark this session as revoked."""
        self.is_active = False
        self.revoked_at = datetime.now(timezone.utc)
    
    def is_expired(self) -> bool:
        """Check if the session has expired."""
        return datetime.now(timezone.utc) > self.expires_at
    
    def update_activity(self):
        """Update the last activity timestamp."""
        self.last_activity = datetime.now(timezone.utc)
    
    @classmethod
    def find_by_jti(cls, jti: str):
        """Find a session by JWT ID."""
        return cls.query.filter_by(jti=jti).first()
    
    @classmethod
    def get_active_sessions(cls, user_id: int):
        """Get all active sessions for a user."""
        return cls.query.filter_by(
            user_id=user_id, 
            is_active=True
        ).filter(
            cls.expires_at > datetime.now(timezone.utc)
        ).all()
    
    def to_dict(self) -> dict:
        """Convert session to dictionary."""
        return {
            'id': self.id,
            'jti': self.jti,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'device_info': self.device_info,
            'created_at': self.created_at.isoformat(),
            'last_activity': self.last_activity.isoformat(),
            'expires_at': self.expires_at.isoformat(),
            'is_active': self.is_active,
            'is_current': False,  # This would be set by the calling code
            'logout_all_survivor': self.logout_all_survivor
        }
    
    def __repr__(self) -> str:
        return f'<UserSession {self.jti[:8]}... for User {self.user_id}>'