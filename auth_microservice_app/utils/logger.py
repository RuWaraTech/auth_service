import logging
import os
import sys
import uuid
from flask import request, has_request_context, g
from pythonjsonlogger import jsonlogger


class RequestIDFilter(logging.Filter):
    def filter(self, record):
        if has_request_context():
            record.request_id = getattr(g, 'request_id', None)
        else:
            record.request_id = None
        return True


def setup_logger():
    logger = logging.getLogger()
    logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

    log_handler = logging.StreamHandler(sys.stdout)

    formatter = jsonlogger.JsonFormatter(
        '%(asctime)s %(levelname)s %(name)s %(module)s %(funcName)s %(message)s %(request_id)s'
    )

    log_handler.setFormatter(formatter)
    log_handler.addFilter(RequestIDFilter())

    if not logger.handlers:
        logger.addHandler(log_handler)

    return logger
