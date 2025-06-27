# auth_microservice_app/routes/core_auth.py
"""
Core authentication routes for user registration and login.
Session management (logout, refresh, sessions) is handled in auth.py.
"""

from flask import Blueprint, request, jsonify, current_app
from marshmallow import Schema, fields, validate, validates, ValidationError, post_load
from datetime import datetime, timezone
from sqlalchemy.exc import IntegrityError
import re

from auth_microservice_app.models import db, User
from auth_microservice_app.utils.jwt_utils import generate_tokens
from auth_microservice_app.utils import limiter

# Create blueprint for core auth (register/login only)
core_auth_bp = Blueprint('core_auth', __name__)


# Marshmallow Schemas
class UserRegistrationSchema(Schema):
    """Schema for user registration validation."""
    
    username = fields.Str(
        required=True,
        validate=[
            validate.Length(min=3, max=80, error="Username must be between 3 and 80 characters"),
            validate.Regexp(
                r'^[a-zA-Z0-9_-]+$',
                error="Username can only contain letters, numbers, underscores, and hyphens"
            )
        ],
        error_messages={
            'required': 'Username is required',
            'invalid': 'Invalid username format'
        }
    )
    
    email = fields.Email(
        required=True,
        validate=validate.Length(max=120, error="Email must be less than 120 characters"),
        error_messages={
            'required': 'Email is required',
            'invalid': 'Invalid email format'
        }
    )
    
    password = fields.Str(
        required=True,
        validate=validate.Length(min=8, max=128, error="Password must be between 8 and 128 characters"),
        error_messages={
            'required': 'Password is required',
            'invalid': 'Invalid password format'
        }
    )
    
    confirm_password = fields.Str(
        required=True,
        error_messages={
            'required': 'Password confirmation is required'
        }
    )
    @validates('password')
    def validate_password_strength(self, password, **kwargs):

        """Validate password strength requirements."""
        errors = []
        
        if not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if not re.search(r'\d', password):
            errors.append("Password must contain at least one number")
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character")
        
        if errors:
            raise ValidationError(errors)
    
    @post_load
    def validate_password_match(self, data, **kwargs):
        """Validate that password and confirm_password match."""
        if data.get('password') != data.get('confirm_password'):
            raise ValidationError({
                'confirm_password': ['Passwords do not match']
            })
        
        # Remove confirm_password from data as it's not needed for user creation
        data.pop('confirm_password', None)
        return data


class UserLoginSchema(Schema):
    """Schema for user login validation."""
    
    identifier = fields.Str(
        required=True,
        validate=validate.Length(min=3, max=120, error="Identifier must be between 3 and 120 characters"),
        error_messages={
            'required': 'Username or email is required',
            'invalid': 'Invalid identifier format'
        }
    )
    
    password = fields.Str(
        required=True,
        validate=validate.Length(min=1, max=128, error="Password cannot be empty"),
        error_messages={
            'required': 'Password is required',
            'invalid': 'Invalid password format'
        }
    )
    
    remember_me = fields.Bool(
        allow_none=True,
        error_messages={
            'invalid': 'Remember me must be a boolean value'
        }
    )
    
    device_info = fields.Str(
        allow_none=True,
        validate=validate.Length(max=255, error="Device info must be less than 255 characters"),
        error_messages={
            'invalid': 'Invalid device info format'
        }
    )


# Initialize schemas
registration_schema = UserRegistrationSchema()
login_schema = UserLoginSchema()


# Helper functions
def handle_validation_error(error):
    """Helper function to format validation errors."""
    return jsonify({
        'error': 'validation_failed',
        'message': 'Input validation failed',
        'details': error.messages
    }), 400


def create_error_response(error_code, message, status_code=400, details=None):
    """Helper function to create standardized error responses."""
    response = {
        'error': error_code,
        'message': message,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
    if details:
        response['details'] = details
    return jsonify(response), status_code


# Routes
@core_auth_bp.route('/register', methods=['POST'])
@limiter.limit(lambda: current_app.config.get('RATE_LIMIT_REGISTER'))
def register():
    """
    Register a new user.
    
    Expected JSON:
    {
        "username": "john_doe",
        "email": "john@example.com",
        "password": "SecurePass123!",
        "confirm_password": "SecurePass123!"
    }
    """
    try:
        # Get and validate request data
        json_data = request.get_json()
        if not json_data:
            return create_error_response(
                'invalid_input',
                'Request body must be valid JSON'
            )
        
        # Validate input with schema
        validated_data = registration_schema.load(json_data)
        
        # Check if username already exists
        existing_user = User.find_by_username(validated_data['username'])
        if existing_user:
            return create_error_response(
                'username_exists',
                'Username already exists',
                409
            )
        
        # Check if email already exists
        existing_email = User.find_by_email(validated_data['email'])
        if existing_email:
            return create_error_response(
                'email_exists',
                'Email already exists',
                409
            )
        
        # Create new user
        user = User(
            username=validated_data['username'],
            email=validated_data['email']
        )
        user.set_password(validated_data['password'])
        
        # Save to database
        try:
            db.session.add(user)
            db.session.commit()
            
            current_app.logger.info(f"New user registered: {user.username}")
            
            return jsonify({
                'message': 'User registered successfully',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'created_at': user.created_at.isoformat()
                },
                'timestamp': datetime.now(timezone.utc).isoformat()
            }), 201
            
        except IntegrityError:
            db.session.rollback()
            current_app.logger.error(f"Database integrity error during registration for {validated_data['username']}")
            return create_error_response(
                'registration_failed',
                'Username or email already exists',
                409
            )
    
    except ValidationError as e:
        return handle_validation_error(e)
    
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Registration error: {e}")
        return create_error_response(
            'registration_failed',
            'An error occurred during registration',
            500
        )


@core_auth_bp.route('/login', methods=['POST'])
@limiter.limit(lambda: current_app.config.get('RATE_LIMIT_LOGIN'))
def login():
    """
    Authenticate user and return tokens.
    
    Expected JSON:
    {
        "identifier": "john_doe",  // username or email
        "password": "SecurePass123!",
        "remember_me": false,
        "device_info": "iPhone 13"
    }
    """
    try:
        # Get and validate request data
        json_data = request.get_json()
        if not json_data:
            return create_error_response(
                'invalid_input',
                'Request body must be valid JSON'
            )
        
        # Validate input with schema
        validated_data = login_schema.load(json_data)
        
        # Set defaults for optional fields
        validated_data.setdefault('remember_me', False)
        validated_data.setdefault('device_info', 'Unknown')
        
        # Find user by username or email
        user = User.find_by_username_or_email(validated_data['identifier'])
        
        if not user:
            current_app.logger.warning(f"Login attempt with non-existent identifier: {validated_data['identifier']}")
            return create_error_response(
                'invalid_credentials',
                'Invalid username/email or password',
                401
            )
        
        # Check if account is locked
        if user.is_account_locked():
            current_app.logger.warning(f"Login attempt on locked account: {user.username}")
            return create_error_response(
                'account_locked',
                'Account is temporarily locked due to too many failed login attempts',
                423
            )
        
        # Check if account is active
        if not user.is_active:
            current_app.logger.warning(f"Login attempt on inactive account: {user.username}")
            return create_error_response(
                'account_inactive',
                'Account is deactivated',
                403
            )
        
        # Verify password
        if not user.check_password(validated_data['password']):
            # Increment failed attempts
            user.increment_failed_attempts()
            
            # Lock account if too many failed attempts
            max_attempts = current_app.config.get('MAX_LOGIN_ATTEMPTS', 5)
            if user.failed_login_attempts >= max_attempts:
                lock_duration = current_app.config.get('ACCOUNT_LOCK_DURATION', 30)
                user.lock_account(lock_duration)
                current_app.logger.warning(f"Account locked for user: {user.username}")
                
                db.session.commit()
                return create_error_response(
                    'account_locked',
                    f'Account locked due to {max_attempts} failed login attempts',
                    423
                )
            
            db.session.commit()
            current_app.logger.warning(f"Failed login attempt for user: {user.username}")
            return create_error_response(
                'invalid_credentials',
                'Invalid username/email or password',
                401
            )
        
        # Successful login - reset failed attempts
        user.reset_failed_attempts()
        user.update_last_login()
        
        # Prepare session info
        session_info = {
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', 'Unknown'),
            'device': validated_data.get('device_info', 'Unknown'),
            'login_time': datetime.now(timezone.utc).isoformat()
        }
        
        # Generate tokens
        access_token, refresh_token = generate_tokens(
            identity=str(user.id),
            fresh=True,
            additional_claims={
                'username': user.username,
                'email': user.email
            },
            track_session=True,
            session_info=session_info
        )
        
        db.session.commit()
        
        current_app.logger.info(f"Successful login for user: {user.username}")
        
        # Prepare response
        response_data = {
            'message': 'Login successful',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'bearer',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'last_login': user.last_login.isoformat()
            },
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        # Set token expiration info
        access_token_expires = current_app.config.get('JWT_ACCESS_TOKEN_EXPIRES')
        refresh_token_expires = current_app.config.get('JWT_REFRESH_TOKEN_EXPIRES')
        
        if access_token_expires:
            response_data['expires_in'] = int(access_token_expires.total_seconds())
        if refresh_token_expires:
            response_data['refresh_expires_in'] = int(refresh_token_expires.total_seconds())
        
        return jsonify(response_data), 200
    
    except ValidationError as e:
        return handle_validation_error(e)
    
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Login error: {e}")
        return create_error_response(
            'login_failed',
            'An error occurred during login',
            500
        )


@core_auth_bp.errorhandler(422)
def handle_unprocessable_entity(e):
    """Handle JWT validation errors."""
    return create_error_response(
        'invalid_token',
        'Token validation failed',
        422
    )


@core_auth_bp.errorhandler(401)
def handle_unauthorized(e):
    """Handle unauthorized access."""
    return create_error_response(
        'unauthorized',
        'Authentication required',
        401
    )