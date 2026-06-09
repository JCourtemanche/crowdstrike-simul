"""
OAuth2 Bearer token authentication for CrowdStrike Falcon mock.
"""
import time
import uuid
from functools import wraps
from flask import request, jsonify
from config import Config

# In-memory token store: token -> expiry timestamp
_active_tokens: dict[str, float] = {}


def issue_token() -> dict:
    token = str(uuid.uuid4()).replace('-', '')
    expiry = time.time() + Config.TOKEN_LIFETIME
    _active_tokens[token] = expiry
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": Config.TOKEN_LIFETIME,
    }


def _purge_expired():
    now = time.time()
    expired = [t for t, exp in _active_tokens.items() if exp < now]
    for t in expired:
        del _active_tokens[t]


def require_bearer(f):
    """Validate OAuth2 Bearer token from Authorization header."""
    @wraps(f)
    def decorated(*args, **kwargs):
        _purge_expired()
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({
                'meta': {'query_time': 0.001, 'trace_id': str(uuid.uuid4())},
                'errors': [{'code': 401, 'message': 'access denied, authorization required'}],
                'resources': [],
            }), 401
        token = auth_header.split(' ', 1)[1]
        if token not in _active_tokens or _active_tokens[token] < time.time():
            return jsonify({
                'meta': {'query_time': 0.001, 'trace_id': str(uuid.uuid4())},
                'errors': [{'code': 401, 'message': 'access denied, authorization required'}],
                'resources': [],
            }), 401
        return f(*args, **kwargs)
    return decorated
