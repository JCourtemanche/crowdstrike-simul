"""
OAuth2 Bearer token authentication for CrowdStrike Falcon mock.

Stateless design: tokens are HMAC-signed so any Cloud Run instance can
validate them without shared memory or a database.
"""
import hmac
import hashlib
import time
import uuid
import os
from functools import wraps
from flask import request, jsonify
from config import Config

# Stable signing secret — same across all Cloud Run instances of this revision.
_SECRET = os.environ.get('TOKEN_SECRET', 'crowdstrike-mock-secret-key').encode()


def _sign(payload: str) -> str:
    return hmac.new(_SECRET, payload.encode(), hashlib.sha256).hexdigest()


def issue_token() -> dict:
    """Return a stateless HMAC-signed token valid for TOKEN_LIFETIME seconds."""
    expires_at = int(time.time()) + Config.TOKEN_LIFETIME
    payload = f"{expires_at}"
    sig = _sign(payload)
    token = f"{payload}.{sig}"
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": Config.TOKEN_LIFETIME,
    }


def _validate_token(token: str) -> bool:
    """Verify the HMAC signature and expiry of a token."""
    try:
        parts = token.split('.', 1)
        if len(parts) != 2:
            return False
        expires_at_str, sig = parts
        expected_sig = _sign(expires_at_str)
        if not hmac.compare_digest(sig, expected_sig):
            return False
        return int(time.time()) < int(expires_at_str)
    except Exception:
        return False


def require_bearer(f):
    """Validate stateless OAuth2 Bearer token from Authorization header."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({
                'meta': {'query_time': 0.001, 'trace_id': str(uuid.uuid4())},
                'errors': [{'code': 401, 'message': 'access denied, authorization required'}],
                'resources': [],
            }), 401
        token = auth_header.split(' ', 1)[1]
        if not _validate_token(token):
            return jsonify({
                'meta': {'query_time': 0.001, 'trace_id': str(uuid.uuid4())},
                'errors': [{'code': 401, 'message': 'access denied, authorization required'}],
                'resources': [],
            }), 401
        return f(*args, **kwargs)
    return decorated
