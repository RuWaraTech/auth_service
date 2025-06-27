"""Flask-Limiter initialization."""
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

logger = logging.getLogger(__name__)

limiter = Limiter(key_func=get_remote_address, default_limits=[])


def init_limiter(app):
    """Initialize Flask-Limiter with Redis storage."""
    default = app.config.get("RATE_LIMIT_DEFAULT")
    limits = [default] if default else []
    storage_uri = app.config.get("REDIS_URL")
    try:
        limiter.init_app(app, default_limits=limits, storage_uri=storage_uri)
        logger.info("✅ Rate limiting enabled")
    except Exception as e:
        logger.warning(f"⚠️  Failed to configure rate limiting: {e}")
    return limiter