"""
CrowdStrike Falcon Cases endpoints.

GET  /cases/entities/cases/v2        → get case summaries
POST /cases/entities/case-tags/v1   → add case tag
DELETE /cases/entities/case-tags/v1 → remove case tag
"""
import uuid
import random
from flask import Blueprint, request, jsonify
from auth import require_bearer
from helpers import cs_response, paginate
from generators.crowdstrike import generate_iso8601_date, CUSTOMER_ID, random_user
import store
from datetime import datetime, timedelta

cases_bp = Blueprint('cases', __name__)

_cases: list[dict] = []


def _ensure_cases():
    global _cases
    if not _cases and store.alerts:
        for i, alert in enumerate(store.alerts[:10]):
            _cases.append({
                "id": str(uuid.uuid4()),
                "cid": CUSTOMER_ID,
                "type": random.choice(["incident", "detection"]),
                "status": random.choice(["new", "in_progress", "closed"]),
                "state": "open",
                "title": f"Case {i+1}: {alert.get('display_name', 'Suspicious Activity')}",
                "description": f"Investigation case for detection {alert['detection_id']}",
                "created_time": generate_iso8601_date(
                    start_time=datetime.utcnow() - timedelta(days=14),
                    end_time=datetime.utcnow() - timedelta(days=1),
                ),
                "last_updated_time": generate_iso8601_date(
                    start_time=datetime.utcnow() - timedelta(days=1),
                    end_time=datetime.utcnow(),
                ),
                "assigned_to_uid": random_user()['email'],
                "detection_ids": [alert['detection_id']],
                "tags": [],
            })


@cases_bp.route('/cases/entities/cases/v2', methods=['GET'])
@require_bearer
def get_cases():
    _ensure_cases()
    limit = min(int(request.args.get('limit', 100)), 500)
    offset = int(request.args.get('offset', 0))
    page, total = paginate(_cases, offset, limit)
    return jsonify(cs_response(page, total=total, offset=offset, limit=limit)), 200


@cases_bp.route('/cases/entities/case-tags/v1', methods=['POST'])
@require_bearer
def add_case_tag():
    _ensure_cases()
    body = request.json if request.is_json else {}
    case_id = body.get('case_id', '')
    tag = body.get('tag', '')
    case_by_id = {c['id']: c for c in _cases}
    if case_id in case_by_id:
        if tag not in case_by_id[case_id]['tags']:
            case_by_id[case_id]['tags'].append(tag)
        return jsonify(cs_response([case_by_id[case_id]], total=1)), 200
    return jsonify(cs_response([], total=0)), 200


@cases_bp.route('/cases/entities/case-tags/v1', methods=['DELETE'])
@require_bearer
def remove_case_tag():
    _ensure_cases()
    body = request.json if request.is_json else {}
    case_id = body.get('case_id', '')
    tag = body.get('tag', '')
    case_by_id = {c['id']: c for c in _cases}
    if case_id in case_by_id:
        case_by_id[case_id]['tags'] = [t for t in case_by_id[case_id]['tags'] if t != tag]
        return jsonify(cs_response([case_by_id[case_id]], total=1)), 200
    return jsonify(cs_response([], total=0)), 200
