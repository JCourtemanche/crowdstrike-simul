"""
CrowdStrike Falcon Container Security (CNAPP) endpoints.

GET /container-security/combined/container-alerts/v1  → list CNAPP alerts

Used by:
  - fetch-assets command (CNAPP Alerts track)
  - cs-falcon-list-cnapp-alerts command
"""
from flask import Blueprint, request, jsonify
from auth import require_bearer
from helpers import cs_response, paginate
import store

container_security_bp = Blueprint('container_security', __name__)


@container_security_bp.route(
    '/container-security/combined/container-alerts/v1', methods=['GET']
)
@require_bearer
def list_cnapp_alerts():
    limit = min(int(request.args.get('limit', 100)), 100)
    offset = int(request.args.get('offset', 0))
    # The `filter` param is accepted by the API but only used by the debug
    # command cs-falcon-list-cnapp-alerts; fetch-assets does not set it.
    # We accept it and return the full set — good enough for the mock.
    _ = request.args.get('filter', '')

    page, total = paginate(store.cnapp_alerts, offset, limit)
    return jsonify(cs_response(page, total=total, offset=offset, limit=limit)), 200
