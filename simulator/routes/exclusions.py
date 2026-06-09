"""
CrowdStrike Falcon Exclusions endpoints.

GET    /policy/entities/{exclusion_type}-exclusions/v1  → get exclusions by IDs
POST   /policy/entities/{exclusion_type}-exclusions/v1  → create exclusion
PATCH  /policy/entities/{exclusion_type}-exclusions/v1  → update exclusion
DELETE /policy/entities/{exclusion_type}-exclusions/v1  → delete exclusions
GET    /policy/queries/{exclusion_type}-exclusions/v1   → query exclusion IDs
"""
import uuid
import random
from flask import Blueprint, request, jsonify
from auth import require_bearer
from helpers import cs_response, paginate
from generators.crowdstrike import generate_iso8601_date, CUSTOMER_ID, random_user, MALICIOUS_FILES
from datetime import datetime, timedelta

exclusions_bp = Blueprint('exclusions', __name__)

_exclusion_store: dict[str, list[dict]] = {}


def _ensure_exclusions(ex_type: str):
    if ex_type not in _exclusion_store:
        _exclusion_store[ex_type] = []
        for i in range(5):
            malicious_file = random.choice(MALICIOUS_FILES)
            _exclusion_store[ex_type].append({
                "id": str(uuid.uuid4()),
                "cid": CUSTOMER_ID,
                "value": f"C:\\Windows\\Temp\\{malicious_file['name']}",
                "name": f"Exclusion-{ex_type}-{i+1}",
                "description": f"Auto-generated {ex_type} exclusion {i+1}",
                "applied_globally": True,
                "pattern_id": str(random.randint(10000, 99999)),
                "groups": [],
                "created_by": random_user()['email'],
                "created_on": generate_iso8601_date(
                    start_time=datetime.utcnow() - timedelta(days=90),
                    end_time=datetime.utcnow() - timedelta(days=1),
                ),
                "modified_by": random_user()['email'],
                "modified_on": generate_iso8601_date(
                    start_time=datetime.utcnow() - timedelta(days=1),
                    end_time=datetime.utcnow(),
                ),
            })


@exclusions_bp.route('/policy/entities/<ex_type>-exclusions/v1', methods=['GET'])
@require_bearer
def get_exclusions(ex_type):
    _ensure_exclusions(ex_type)
    ids = request.args.getlist('ids')
    ex_by_id = {e['id']: e for e in _exclusion_store[ex_type]}
    resources = [ex_by_id[eid] for eid in ids if eid in ex_by_id] if ids else list(ex_by_id.values())
    return jsonify(cs_response(resources, total=len(resources))), 200


@exclusions_bp.route('/policy/entities/<ex_type>-exclusions/v1', methods=['POST'])
@require_bearer
def create_exclusion(ex_type):
    _ensure_exclusions(ex_type)
    body = request.json if request.is_json else {}
    new_ex = {
        "id": str(uuid.uuid4()),
        "cid": CUSTOMER_ID,
        "value": body.get('value', ''),
        "name": body.get('name', ''),
        "description": body.get('description', ''),
        "applied_globally": body.get('applied_globally', True),
        "pattern_id": str(random.randint(10000, 99999)),
        "groups": body.get('groups', []),
        "created_by": random_user()['email'],
        "created_on": generate_iso8601_date(),
        "modified_by": random_user()['email'],
        "modified_on": generate_iso8601_date(),
    }
    _exclusion_store[ex_type].append(new_ex)
    return jsonify(cs_response([new_ex], total=1)), 200


@exclusions_bp.route('/policy/entities/<ex_type>-exclusions/v1', methods=['PATCH'])
@require_bearer
def update_exclusion(ex_type):
    _ensure_exclusions(ex_type)
    body = request.json if request.is_json else {}
    eid = body.get('id')
    ex_by_id = {e['id']: e for e in _exclusion_store[ex_type]}
    if eid in ex_by_id:
        ex_by_id[eid].update({k: v for k, v in body.items() if k in ('value', 'name', 'description')})
        return jsonify(cs_response([ex_by_id[eid]], total=1)), 200
    return jsonify(cs_response([], total=0)), 200


@exclusions_bp.route('/policy/entities/<ex_type>-exclusions/v1', methods=['DELETE'])
@require_bearer
def delete_exclusion(ex_type):
    _ensure_exclusions(ex_type)
    ids = request.args.getlist('ids')
    deleted = []
    _exclusion_store[ex_type] = [e for e in _exclusion_store[ex_type] if e['id'] not in ids or deleted.append(e['id'])]
    return jsonify(cs_response(ids, total=len(ids))), 200


@exclusions_bp.route('/policy/queries/<ex_type>-exclusions/v1', methods=['GET'])
@require_bearer
def query_exclusions(ex_type):
    _ensure_exclusions(ex_type)
    limit = min(int(request.args.get('limit', 100)), 500)
    offset = int(request.args.get('offset', 0))
    page, total = paginate(_exclusion_store[ex_type], offset, limit)
    ids = [e['id'] for e in page]
    return jsonify(cs_response(ids, total=total, offset=offset, limit=limit)), 200
