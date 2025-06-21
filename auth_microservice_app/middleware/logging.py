import uuid
from flask import g, request

def request_id_middleware(app):
    @app.before_request
    def attach_request_id():
        g.request_id = request.headers.get('X-Request-ID') or str(uuid.uuid4())
