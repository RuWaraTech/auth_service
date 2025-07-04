# auth_service


## System Requirements

The project uses poetry for Python to create an isolated environment and manage package dependencies. To prepare your system, ensure you have an official distribution of Python version 3.12+ and install Poetry using one of the following commands (as instructed by the [poetry documentation](https://python-poetry.org/docs/#system-requirements)):

### Poetry installation (Bash)

```bash
curl -sSL https://install.python-poetry.org | python3 -
```

### Poetry installation (PowerShell)

```powershell
(Invoke-WebRequest -Uri https://install.python-poetry.org -UseBasicParsing).Content | py -
```

## Dependencies

The project uses a virtual environment to isolate package dependencies. To create the virtual environment and install required packages, run the following from your preferred shell:

```bash
$ poetry install
```

You'll also need to clone a new `.env` file from the `.env.template` to store local configuration options. This is a one-time operation on first setup:

```bash
$ cp .env.template .env  # (first time only)

```
# Running the App

Once the all dependencies have been installed, start the Flask app in development mode within the Poetry environment by running:
```bash
$ poetry run gunicorn "auth_microservice_app.app:create_app()" \
  --bind 0.0.0.0:8000 \
  --workers 4 \
  --threads 2 \
  --timeout 60 \
  --log-level info \
  --access-logfile - \
  --error-logfile - \
  --capture-output
```

## Remove for Prod 
### 1. Create tokens
```bash
curl -X POST http://0.0.0.0:8000/api/v1/test/create-tokens
```
#### Save the tokens (example):
ACCESS_TOKEN="<copy-access-token-here>"
REFRESH_TOKEN="<copy-refresh-token-here>"

### 2. Test protected route
```bash
curl -X GET http://0.0.0.0:8000/api/v1/test/protected \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```
### 3. Test fresh token required
```bash
curl -X GET http://0.0.0.0:8000/api/v1/test/fresh-required \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```
### 4. Test refresh
```bash
curl -X POST http://0.0.0.0:8000/api/v1/test/refresh \
  -H "Authorization: Bearer $REFRESH_TOKEN"
```


#### Directory Structure

auth-service/
├── pyproject.toml              # Poetry configuration
├── poetry.lock                 # Locked dependencies
├── README.md
├── .env.example
├── .gitignore
├── Dockerfile
├── docker-compose.yml          # Local development
├── auth_microservice_app/
│   ├── __init__.py
│   ├── app.py                # Flask app initialization
│   ├── flask_config.py              # Configuration management
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── routes.py
│   │   ├── services.py
│   │   └── validators.py
│   ├── oauth/
│   │   ├── __init__.py
│   │   ├── providers/
│   │   │   ├── google.py
│   │   │   ├── github.py
│   │   │   └── apple.py
│   │   └── routes.py
│   ├── models/
│   │   ├── __init__.py
│   │   ├── user.py
│   │   ├── oauth.py
│   │   └── two_factor.py
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── jwt_utils.py
│   │   ├── redis_client.py
│   │   ├── email.py
│   │   └── sms.py
│   └── middleware/
│       ├── __init__.py
│       ├── rate_limit.py
│       └── auth.py
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── unit/
│   └── integration/
├── migrations/                 # Alembic migrations
│   └── versions/
├── infrastructure/
│   ├── terraform/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   │   └── modules/
│   └── kubernetes/
│       ├── namespace.yaml
│       ├── configmap.yaml
│       ├── deployment.yaml
│       └── service.yaml
└── scripts/
    ├── setup.sh
    └── deploy.sh



# Authentication Microservice - Development Tickets

## Epic 1: Core Flask Application Setup (Foundation)

### TICKET-001: Basic Flask App Structure
**Story Points:** 3  
**Priority:** P0 (Blocker)  
**Description:** Create the basic Flask application structure with app.py  

**Acceptance Criteria:**
- [X] Create `auth_microservice_app/app.py` with basic Flask app
- [X] Create `auth_microservice_app/__init__.py`
- [X] Basic "Hello World" endpoint working
- [X] Application runs with `poetry run flask run`

---

### TICKET-002: Configuration Management
**Story Points:** 5  
**Priority:** P0 (Blocker)  
**Dependencies:** TICKET-001  
**Description:** Implement configuration classes for different environments  

**Acceptance Criteria:**
- [X] Create `config.py` with base Config class
- [X] Add environment-specific configs (dev, stag ,prod)
- [X] Load configuration from environment variables
- [X] `.env.example` file created

**Files to create:**
- `auth_microservice_app/config.py`
- `.env.example`
- `.env` (local only, not committed)

---

### TICKET-003: Database Setup with SQLAlchemy
**Story Points:** 5  
**Priority:** P0 (Blocker)  
**Dependencies:** TICKET-002  
**Description:** Integrate SQLAlchemy and Flask-Migrate  

**Acceptance Criteria:**
- [X] Add SQLAlchemy to app.py
- [X] Add Flask-Migrate for database migrations
- [X] Create database connection with proper pooling
- [X] Health check includes database connectivity
- [X] Migration commands working

**Updates to app.py:**
- Initialize `db = SQLAlchemy()`
- Initialize `migrate = Migrate()`
- Add database health check

---

### TICKET-004: Logging Configuration
**Story Points:** 3  
**Priority:** P1 (High)  
**Dependencies:** TICKET-001  
**Description:** Implement structured JSON logging  

**Acceptance Criteria:**
- [X] Configure Python JSON logger
- [X] Environment-based log levels
- [X] Structured logging format
- [X] Request ID tracking
- [X] Logs work in both dev and production

---

## Epic 2: Authentication Core (JWT & Security)

### TICKET-005: JWT Integration
**Story Points:** 8  
**Priority:** P0 (Blocker)  
**Dependencies:** TICKET-003  
**Description:** Implement JWT token management with Flask-JWT-Extended  

**Acceptance Criteria:**
- [X] JWT manager initialized
- [X] Token creation utilities
- [X] Token validation
- [X] Error handlers for expired/invalid tokens
- [X] Access and refresh token support

---

### TICKET-006: Redis Integration for Token Blacklist
**Story Points:** 5  
**Priority:** P0 (Blocker)  
**Dependencies:** TICKET-005  
**Description:** Add Redis for JWT token revocation  

**Acceptance Criteria:**
- [X] Redis client initialization
- [X] Token blacklist checking
- [X] Token revocation endpoint
- [X] Redis health check
- [X] Graceful fallback if Redis unavailable

---

### TICKET-007: User Model
**Story Points:** 8  
**Priority:** P0 (Blocker)  
**Dependencies:** TICKET-003  
**Description:** Create User model with authentication fields  

**Acceptance Criteria:**
- [X] User model with email, password_hash, etc.
- [X] Password hashing utilities
- [X] Email validation
- [X] Timestamps (created_at, updated_at)
- [X] User verification status
- [X] Database migrations created

**File to create:**
- `auth_microservice_app/models/user.py`
- `auth_microservice_app/models/__init__.py`

---

### TICKET-008: Basic Auth Routes
**Story Points:** 8  
**Priority:** P0 (Blocker)  
**Dependencies:** TICKET-007, TICKET-005  
**Description:** Implement core authentication endpoints  

**Acceptance Criteria:**
- [X] POST /api/v1/auth/register
- [X] POST /api/v1/auth/login  
- [X] POST /api/v1/auth/logout
- [X] POST /api/v1/auth/refresh
- [X] Input validation with Marshmallow
- [X] Proper error responses

**Files to create:**
- `auth_microservice_app/auth/__init__.py`
- `auth_microservice_app/auth/routes.py`
- `auth_microservice_app/auth/schemas.py`

---

## Epic 3: Security & Middleware

### TICKET-009: Rate Limiting
**Story Points:** 5  
**Priority:** P1 (High)  
**Dependencies:** TICKET-006  
**Description:** Implement rate limiting with Flask-Limiter  

**Acceptance Criteria:**
- [ ] Flask-Limiter configured with Redis backend
- [ ] Different limits for different endpoints
- [ ] Rate limit headers in responses
- [ ] Configurable limits via environment

---

### TICKET-010: CORS Configuration
**Story Points:** 2  
**Priority:** P1 (High)  
**Dependencies:** TICKET-001  
**Description:** Configure CORS for cross-origin requests  

**Acceptance Criteria:**
- [ ] Flask-CORS configured
- [ ] Allowed origins from environment
- [ ] Proper headers for preflight requests
- [ ] Credentials support enabled

---

### TICKET-011: Security Headers
**Story Points:** 3  
**Priority:** P1 (High)  
**Dependencies:** TICKET-001  
**Description:** Implement security headers with Flask-Talisman  

**Acceptance Criteria:**
- [ ] CSP headers configured
- [ ] HSTS enabled for production
- [ ] X-Frame-Options set
- [ ] Configurable per environment

---

## Epic 4: Advanced Features

### TICKET-012: Email Service Integration
**Story Points:** 5  
**Priority:** P2 (Medium)  
**Dependencies:** TICKET-008  
**Description:** Email service for verification and magic links  

**Acceptance Criteria:**
- [ ] SendGrid integration
- [ ] Email templates
- [ ] Verification email sending
- [ ] Async email sending with Celery

---

### TICKET-013: Two-Factor Authentication
**Story Points:** 13  
**Priority:** P2 (Medium)  
**Dependencies:** TICKET-008  
**Description:** Implement TOTP-based 2FA  

**Acceptance Criteria:**
- [ ] TOTP secret generation
- [ ] QR code generation
- [ ] Verification endpoint
- [ ] Backup codes
- [ ] 2FA enable/disable endpoints

---

### TICKET-014: OAuth Provider - Google
**Story Points:** 8  
**Priority:** P2 (Medium)  
**Dependencies:** TICKET-008  
**Description:** Google OAuth integration  

**Acceptance Criteria:**
- [ ] OAuth flow implementation
- [ ] Callback handling
- [ ] User creation/linking
- [ ] Token exchange
- [ ] Mobile app support (PKCE)

---

## Epic 5: Production Readiness

### TICKET-015: Monitoring & Metrics
**Story Points:** 5  
**Priority:** P1 (High)  
**Dependencies:** TICKET-001  
**Description:** Prometheus metrics integration  

**Acceptance Criteria:**
- [ ] Prometheus Flask exporter
- [ ] Custom metrics for auth events
- [ ] /metrics endpoint
- [ ] Grafana dashboard template

---

### TICKET-016: Docker Configuration
**Story Points:** 5  
**Priority:** P1 (High)  
**Dependencies:** TICKET-001  
**Description:** Create production-ready Dockerfile  

**Acceptance Criteria:**
- [ ] Multi-stage Dockerfile
- [ ] Non-root user
- [ ] Security scanning
- [ ] Optimal image size
- [ ] Health check included

---

### TICKET-017: Error Handling & Validation
**Story Points:** 5  
**Priority:** P1 (High)  
**Dependencies:** TICKET-008  
**Description:** Global error handling and input validation  

**Acceptance Criteria:**
- [ ] Global error handlers
- [ ] Marshmallow schemas for all endpoints
- [ ] Consistent error response format
- [ ] No sensitive data in errors
- [ ] Request/Response logging

---

### TICKET-018: API Documentation
**Story Points:** 5  
**Priority:** P2 (Medium)  
**Dependencies:** TICKET-008  
**Description:** OpenAPI/Swagger documentation  

**Acceptance Criteria:**
- [ ] OpenAPI spec generated
- [ ] Swagger UI endpoint
- [ ] All endpoints documented
- [ ] Request/Response examples
- [ ] Authentication documented

---

## Development Order

**Sprint 1 (Foundation):**
- TICKET-001: Basic Flask App Structure
- TICKET-002: Configuration Management
- TICKET-003: Database Setup
- TICKET-004: Logging Configuration

**Sprint 2 (Core Auth):**
- TICKET-005: JWT Integration
- TICKET-006: Redis Integration
- TICKET-007: User Model
- TICKET-008: Basic Auth Routes

**Sprint 3 (Security):**
- TICKET-009: Rate Limiting
- TICKET-010: CORS Configuration
- TICKET-011: Security Headers
- TICKET-017: Error Handling

**Sprint 4 (Features):**
- TICKET-012: Email Service
- TICKET-013: Two-Factor Authentication
- TICKET-014: OAuth Provider

**Sprint 5 (Production):**
- TICKET-015: Monitoring
- TICKET-016: Docker Configuration
- TICKET-018: API Documentation

---

## Quick Start for TICKET-001

```bash
# Create the basic structure
mkdir -p auth_microservice_app/{models,auth,oauth,utils,middleware}
touch auth_microservice_app/{__init__.py,app.py,config.py}

# Create a simple app.py to start
# Then run:
poetry run python -m auth_microservice_app.app
```