"""
CrowdStrike Spotlight (Vulnerability Management) endpoints.

GET /spotlight/combined/vulnerabilities/v1  → search vulnerabilities
"""
from flask import Blueprint, request, jsonify
from auth import require_bearer
from helpers import cs_response, cursor_paginate
import store

spotlight_bp = Blueprint('spotlight', __name__)


@spotlight_bp.route('/spotlight/combined/vulnerabilities/v1', methods=['GET'])
@require_bearer
def search_vulnerabilities():
    limit = min(int(request.args.get('limit', 100)), 400)
    after = request.args.get('after')
    filter_arg = request.args.get('filter', '')
    cve_ids = request.args.getlist('cve_id')
    aids = request.args.getlist('aid')

    filtered = store.vulnerabilities
    if cve_ids:
        filtered = [v for v in filtered if v['cve']['id'] in cve_ids]
    if aids:
        filtered = [v for v in filtered if v['aid'] in aids]

    page, next_after = cursor_paginate(filtered, after, limit)
    return jsonify(cs_response(page, total=len(filtered), after=next_after)), 200
