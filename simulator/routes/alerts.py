"""
CrowdStrike Falcon alert/detection endpoints.

GET  /alerts/queries/alerts/v2          → query alert composite IDs
POST /alerts/entities/alerts/v2         → get alert entities by composite IDs
PATCH /alerts/entities/alerts/v3        → update alert (resolve, assign, tag)
GET  /detects/queries/iom/v2            → query IOM (Cloud Security) IDs
GET  /detects/entities/iom/v2          → get IOM entities
"""
import uuid
import random
from flask import Blueprint, request, jsonify
from auth import require_bearer
from helpers import cs_response, cs_error, paginate
import store

alerts_bp = Blueprint('alerts', __name__)

# Simulated IOM (Indicator of Misconfiguration) records
_iom_records: list[dict] = []


def _ensure_iom():
    """Lazily build IOM records from devices."""
    global _iom_records
    if not _iom_records:
        services = ["S3", "EC2", "IAM", "RDS", "Lambda", "ECS", "CloudTrail"]
        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        policy_ids = [str(uuid.uuid4()).replace('-', '')[:12] for _ in range(10)]
        for _ in range(20):
            device = random.choice(store.devices)
            _iom_records.append({
                "id": str(uuid.uuid4()),
                "cid": device['cid'],
                "aid": device['device_id'],
                "policy_id": random.choice(policy_ids),
                "policy_version": random.randint(1, 5),
                "service": random.choice(services),
                "severity": random.choice(severities),
                "status": random.choice(["new", "recurring", "all"]),
                "cloud_provider": "aws",
                "cloud_account_id": f"{random.randint(100000000000, 999999999999)}",
                "cloud_region": random.choice(["us-east-1", "eu-west-1", "ap-southeast-1"]),
                "resource_id": str(uuid.uuid4()),
                "resource_name": f"resource-{random.randint(1000, 9999)}",
                "created_at": _random_ts(),
                "updated_at": _random_ts(),
            })


def _random_ts():
    from generators.crowdstrike import generate_iso8601_date
    from datetime import datetime, timedelta
    return generate_iso8601_date(
        start_time=datetime.utcnow() - timedelta(days=30),
        end_time=datetime.utcnow(),
    )


# ---------------------------------------------------------------------------
# Query alert IDs
# ---------------------------------------------------------------------------
@alerts_bp.route('/alerts/queries/alerts/v2', methods=['GET'])
@require_bearer
def query_alert_ids():
    limit = min(int(request.args.get('limit', 100)), 10000)
    offset = int(request.args.get('offset', 0))
    filter_arg = request.args.get('filter', '')

    filtered = store.alerts
    # Simple FQL filter support: product + type
    if 'product' in filter_arg and 'epp' in filter_arg:
        filtered = store.alerts  # all are EPP detections in this mock
    elif 'product' in filter_arg and 'idp' in filter_arg:
        filtered = store.alerts[:max(1, len(store.alerts) // 3)]

    page, total = paginate(filtered, offset, limit)
    ids = [a['composite_id'] for a in page]
    return jsonify(cs_response(ids, total=total, offset=offset, limit=limit)), 200


# ---------------------------------------------------------------------------
# Get alert entities by composite IDs
# ---------------------------------------------------------------------------
@alerts_bp.route('/alerts/entities/alerts/v2', methods=['POST'])
@require_bearer
def get_alert_entities():
    body = request.json if request.is_json else {}
    composite_ids = body.get('composite_ids', [])

    resources = []
    for cid in composite_ids:
        # composite_id = customer_cid:detection_id
        parts = cid.split(':') if ':' in cid else []
        detection_id = ':'.join(parts[1:]) if len(parts) > 1 else cid
        if detection_id in store.alert_by_id:
            resources.append(store.alert_by_id[detection_id])
        else:
            # Fallback: search by composite_id
            for alert in store.alerts:
                if alert['composite_id'] == cid:
                    resources.append(alert)
                    break

    return jsonify(cs_response(resources, total=len(resources))), 200


# ---------------------------------------------------------------------------
# Update alert (resolve, assign, add tag, etc.)
# ---------------------------------------------------------------------------
@alerts_bp.route('/alerts/entities/alerts/v3', methods=['PATCH'])
@require_bearer
def update_alerts():
    body = request.json if request.is_json else {}
    ids = body.get('ids', [])
    action_params = body.get('action_parameters', [])

    for param in action_params:
        name = param.get('name')
        value = param.get('value')
        for alert_id in ids:
            # Find by detection_id or composite_id
            target = store.alert_by_id.get(alert_id)
            if not target:
                for a in store.alerts:
                    if a['composite_id'] == alert_id:
                        target = a
                        break
            if target:
                if name == 'update_status':
                    target['status'] = value
                elif name == 'assign_to_name':
                    target['assigned_to_name'] = value
                elif name == 'assign_to_uuid':
                    target['assigned_to_uid'] = value
                elif name == 'add_tag':
                    target.setdefault('tags', [])
                    if value not in target['tags']:
                        target['tags'].append(value)
                elif name == 'remove_tag':
                    target.setdefault('tags', [])
                    target['tags'] = [t for t in target['tags'] if t != value]
                elif name == 'show_in_ui':
                    target['show_in_ui'] = value.lower() == 'true'

    return jsonify(cs_response(ids, total=len(ids))), 200


# ---------------------------------------------------------------------------
# IOM endpoints (Cloud Security misconfigurations)
# ---------------------------------------------------------------------------
@alerts_bp.route('/detects/queries/iom/v2', methods=['GET'])
@require_bearer
def query_iom_ids():
    _ensure_iom()
    limit = min(int(request.args.get('limit', 100)), 500)
    next_token = request.args.get('next_token')

    start = 0
    if next_token:
        try:
            start = int(next_token)
        except ValueError:
            start = 0

    page = _iom_records[start: start + limit]
    new_next_token = str(start + limit) if start + limit < len(_iom_records) else None

    pagination = {
        "offset": start,
        "limit": limit,
        "total": len(_iom_records),
    }
    if new_next_token:
        pagination["next_token"] = new_next_token

    return jsonify({
        "meta": {
            "query_time": 0.001,
            "pagination": pagination,
            "trace_id": str(uuid.uuid4()),
        },
        "resources": [r['id'] for r in page],
        "errors": [],
    }), 200


@alerts_bp.route('/detects/entities/iom/v2', methods=['GET'])
@require_bearer
def get_iom_entities():
    _ensure_iom()
    ids = request.args.getlist('ids')
    resources = [r for r in _iom_records if r['id'] in ids]
    return jsonify(cs_response(resources, total=len(resources))), 200
