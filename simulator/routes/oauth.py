"""
POST /oauth2/token — OAuth2 Client Credentials token endpoint.
"""
from flask import Blueprint, request, jsonify
from auth import issue_token
from config import Config

oauth_bp = Blueprint('oauth', __name__)


@oauth_bp.route('/oauth2/token', methods=['POST'])
def get_token():
    client_id = request.form.get('client_id') or request.json.get('client_id', '') if request.is_json else request.form.get('client_id', '')
    client_secret = request.form.get('client_secret') or (request.json.get('client_secret', '') if request.is_json else request.form.get('client_secret', ''))

    if not client_id or not client_secret:
        return jsonify({
            "errors": [{"code": 400, "message": "client_id and client_secret are required"}],
            "meta": {}
        }), 400

    if client_id != Config.CLIENT_ID or client_secret != Config.CLIENT_SECRET:
        return jsonify({
            "errors": [{"code": 401, "message": "invalid client credentials"}],
            "meta": {}
        }), 401

    return jsonify(issue_token()), 201
