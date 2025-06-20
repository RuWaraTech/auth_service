# auth_service

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