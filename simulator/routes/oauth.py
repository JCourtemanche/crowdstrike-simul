"""
POST /oauth2/token — OAuth2 Client Credentials token endpoint.

Accepts any non-empty client_id + client_secret. This is a mock server:
credential values are irrelevant; what matters is that XSIAM receives
a valid token it can use for subsequent calls.
"""
from flask import Blueprint, request, jsonify
from auth import issue_token

oauth_bp = Blueprint('oauth', __name__)


def _get_param(key: str) -> str:
    """Read a param from form data or JSON body."""
    value = request.form.get(key, '')
    if not value and request.is_json:
        value = (request.get_json(silent=True) or {}).get(key, '')
    return value or ''


@oauth_bp.route('/oauth2/token', methods=['POST'])
def get_token():
    client_id = _get_param('client_id')
    client_secret = _get_param('client_secret')

    if not client_id or not client_secret:
        return jsonify({
            "errors": [{"code": 400, "message": "client_id and client_secret are required"}],
            "meta": {}
        }), 400

    # Accept any credentials — this is a mock server.
    return jsonify(issue_token()), 201
