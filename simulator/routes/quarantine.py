"""
CrowdStrike Falcon Quarantine endpoints.

GET  /quarantine/queries/quarantined-files/v1          → query quarantined file IDs
POST /quarantine/entities/quarantined-files/GET/v1     → get quarantined file details
PATCH /quarantine/entities/quarantined-files/v1        → update quarantine state
"""
import uuid
import random
from flask import Blueprint, request, jsonify
from auth import require_bearer
from helpers import cs_response, paginate
from generators.crowdstrike import (
    generate_sha256, generate_md5, generate_iso8601_date, MALICIOUS_FILES, CUSTOMER_ID
)
import store
from datetime import datetime, timedelta

quarantine_bp = Blueprint('quarantine', __name__)

_quarantine_files: list[dict] = []


def _ensure_quarantine():
    global _quarantine_files
    if not _quarantine_files and store.devices:
        for _ in range(15):
            device = random.choice(store.devices)
            malicious_file = random.choice(MALICIOUS_FILES)
            _quarantine_files.append({
                "id": str(uuid.uuid4()),
                "cid": CUSTOMER_ID,
                "aid": device['device_id'],
                "username": device['hostname'].split('-')[0].lower(),
                "hostname": device['hostname'],
                "date_updated": generate_iso8601_date(
                    start_time=datetime.utcnow() - timedelta(days=7),
                    end_time=datetime.utcnow(),
                ),
                "date_created": generate_iso8601_date(
                    start_time=datetime.utcnow() - timedelta(days=14),
                    end_time=datetime.utcnow() - timedelta(days=7),
                ),
                "state": random.choice(["quarantined", "unquarantined", "deleted", "release_pending"]),
                "sha256": generate_sha256(),
                "md5": generate_md5(),
                "paths": [
                    {
                        "filename": malicious_file['name'],
                        "path": f"\\Device\\HarddiskVolume3\\Users\\user\\Downloads\\{malicious_file['name']}",
                        "state": "quarantined",
                    }
                ],
                "detect_ids": [],
            })


@quarantine_bp.route('/quarantine/queries/quarantined-files/v1', methods=['GET'])
@require_bearer
def query_quarantined():
    _ensure_quarantine()
    limit = min(int(request.args.get('limit', 100)), 500)
    offset = int(request.args.get('offset', 0))
    page, total = paginate(_quarantine_files, offset, limit)
    ids = [f['id'] for f in page]
    return jsonify(cs_response(ids, total=total, offset=offset, limit=limit)), 200


@quarantine_bp.route('/quarantine/entities/quarantined-files/GET/v1', methods=['POST'])
@require_bearer
def get_quarantined_files():
    _ensure_quarantine()
    body = request.json if request.is_json else {}
    ids = body.get('ids', [])
    qf_by_id = {f['id']: f for f in _quarantine_files}
    resources = [qf_by_id[fid] for fid in ids if fid in qf_by_id]
    return jsonify(cs_response(resources, total=len(resources))), 200


@quarantine_bp.route('/quarantine/entities/quarantined-files/v1', methods=['PATCH'])
@require_bearer
def update_quarantine():
    _ensure_quarantine()
    body = request.json if request.is_json else {}
    ids = body.get('ids', [])
    action = body.get('action', '')
    state_map = {'release': 'unquarantined', 'quarantine': 'quarantined', 'delete': 'deleted'}
    qf_by_id = {f['id']: f for f in _quarantine_files}
    for fid in ids:
        if fid in qf_by_id:
            qf_by_id[fid]['state'] = state_map.get(action, qf_by_id[fid]['state'])
    return jsonify(cs_response(ids, total=len(ids))), 200
