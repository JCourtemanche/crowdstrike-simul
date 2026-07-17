"""
CrowdStrike Falcon device endpoints.

GET  /devices/queries/devices/v1             → query device IDs
POST /devices/entities/devices/v2           → get device details by IDs
GET  /devices/entities/online-state/v1      → device online state
POST /devices/entities/devices-actions/v2   → contain / lift containment
GET  /devices/entities/host-groups/v1       → get host groups by IDs
GET  /devices/combined/host-groups/v1       → list host groups (search)
POST /devices/entities/host-groups/v1       → create host group
PATCH /devices/entities/host-groups/v1      → update host group
DELETE /devices/entities/host-groups/v1     → delete host groups
GET  /devices/combined/host-group-members/v1 → list host group members
POST /devices/entities/host-group-actions/v1 → add/remove members
"""
import uuid
import random
from flask import Blueprint, request, jsonify
from auth import require_bearer
from helpers import cs_response, cs_error, paginate
import store
from generators.crowdstrike import generate_host_group

devices_bp = Blueprint('devices', __name__)


# ---------------------------------------------------------------------------
# /devices/queries/devices/v1  — list device IDs
# ---------------------------------------------------------------------------
@devices_bp.route('/devices/queries/devices/v1', methods=['GET'])
@require_bearer
def query_device_ids():
    limit = min(int(request.args.get('limit', 100)), 5000)
    offset = int(request.args.get('offset', 0))
    hostname_filter = request.args.get('hostname', '')
    status_filter = request.args.get('status', '')
    platform_filter = request.args.get('platform_name', '')

    filtered = store.devices
    if hostname_filter:
        filtered = [d for d in filtered if hostname_filter.lower() in d['hostname'].lower()]
    if status_filter:
        filtered = [d for d in filtered if d['status'] == status_filter]
    if platform_filter:
        filtered = [d for d in filtered if d['platform_name'].lower() == platform_filter.lower()]

    page, total = paginate(filtered, offset, limit)
    ids = [d['device_id'] for d in page]
    return jsonify(cs_response(ids, total=total, offset=offset, limit=limit)), 200


# ---------------------------------------------------------------------------
# /devices/entities/devices/v2  — get device details
# ---------------------------------------------------------------------------
@devices_bp.route('/devices/entities/devices/v2', methods=['GET', 'POST'])
@require_bearer
def get_device_details():
    if request.method == 'POST':
        body = request.get_json(silent=True) or {}
        ids = body.get('ids') or []
    else:
        ids = request.args.getlist('ids')

    if not ids:
        return cs_error(400, "ids parameter is required")

    resources = [store.device_by_id[did] for did in ids if did in store.device_by_id]
    unknown = [did for did in ids if did not in store.device_by_id]

    envelope = cs_response(resources, total=len(resources))
    # Match CS API contract: unknown ids land in errors[] rather than being
    # silently dropped. The fetch-assets client uses ok_codes=(200, 400)
    # and reads response.errors — this defensive path prevents an empty
    # `resources` from causing enrich_and_ingest_batch to early-return
    # and skip the assets seal batch.
    if unknown:
        envelope['errors'] = [
            {"code": 404, "message": f"Device {did} not found", "id": did}
            for did in unknown
        ]
    return jsonify(envelope), 200


# ---------------------------------------------------------------------------
# /devices/entities/online-state/v1  — device online state
# ---------------------------------------------------------------------------
@devices_bp.route('/devices/entities/online-state/v1', methods=['GET'])
@require_bearer
def device_online_state():
    ids = request.args.getlist('ids')
    states = []
    for did in ids:
        if did in store.device_by_id:
            states.append({
                "id": did,
                "cid": store.device_by_id[did]['cid'],
                "state": random.choice(["online", "offline", "unknown"]),
                "state_timestamp": store.device_by_id[did]['last_seen'],
            })
    return jsonify(cs_response(states, total=len(states))), 200


# ---------------------------------------------------------------------------
# /devices/entities/devices-actions/v2  — contain / lift containment
# ---------------------------------------------------------------------------
@devices_bp.route('/devices/entities/devices-actions/v2', methods=['POST'])
@require_bearer
def device_action():
    action_name = request.args.get('action_name', '')
    body = request.json if request.is_json else {}
    ids = body.get('ids', [])

    action_map = {
        'contain': 'contained',
        'lift_containment': 'normal',
        'hide_host': 'normal',
        'unhide_host': 'normal',
    }
    new_status = action_map.get(action_name, 'normal')

    resources = []
    for did in ids:
        if did in store.device_by_id:
            store.device_by_id[did]['status'] = new_status
            resources.append({"id": did, "cid": store.device_by_id[did]['cid']})

    return jsonify(cs_response(resources, total=len(resources))), 202


# ---------------------------------------------------------------------------
# Host Groups
# ---------------------------------------------------------------------------
@devices_bp.route('/devices/combined/host-groups/v1', methods=['GET'])
@require_bearer
def list_host_groups():
    limit = min(int(request.args.get('limit', 100)), 500)
    offset = int(request.args.get('offset', 0))
    page, total = paginate(store.host_groups, offset, limit)
    return jsonify(cs_response(page, total=total, offset=offset, limit=limit)), 200


@devices_bp.route('/devices/entities/host-groups/v1', methods=['GET'])
@require_bearer
def get_host_groups_by_ids():
    ids = request.args.getlist('ids')
    resources = [g for g in store.host_groups if g['id'] in ids]
    return jsonify(cs_response(resources, total=len(resources))), 200


@devices_bp.route('/devices/entities/host-groups/v1', methods=['POST'])
@require_bearer
def create_host_group():
    body = request.json if request.is_json else {}
    new_group = generate_host_group()
    new_group.update({
        "name": body.get('name', new_group['name']),
        "group_type": body.get('group_type', new_group['group_type']),
        "description": body.get('description', new_group['description']),
        "assignment_rule": body.get('assignment_rule', new_group['assignment_rule']),
    })
    store.host_groups.append(new_group)
    return jsonify(cs_response([new_group], total=1)), 201


@devices_bp.route('/devices/entities/host-groups/v1', methods=['PATCH'])
@require_bearer
def update_host_group():
    body = request.json if request.is_json else {}
    group_id = body.get('id')
    for g in store.host_groups:
        if g['id'] == group_id:
            g.update({k: v for k, v in body.items() if k in ('name', 'description', 'assignment_rule')})
            return jsonify(cs_response([g], total=1)), 200
    return cs_error(404, f"Group {group_id} not found", 404)


@devices_bp.route('/devices/entities/host-groups/v1', methods=['DELETE'])
@require_bearer
def delete_host_groups():
    ids = request.args.getlist('ids')
    deleted = []
    for gid in ids:
        for i, g in enumerate(store.host_groups):
            if g['id'] == gid:
                store.host_groups.pop(i)
                deleted.append({"id": gid})
                break
    return jsonify(cs_response(deleted, total=len(deleted))), 200


@devices_bp.route('/devices/combined/host-group-members/v1', methods=['GET'])
@require_bearer
def list_host_group_members():
    group_id = request.args.get('id', '')
    limit = min(int(request.args.get('limit', 100)), 500)
    offset = int(request.args.get('offset', 0))
    members = [d for d in store.devices if group_id in d.get('groups', [])]
    page, total = paginate(members, offset, limit)
    return jsonify(cs_response(page, total=total, offset=offset, limit=limit)), 200


@devices_bp.route('/devices/entities/host-group-actions/v1', methods=['POST'])
@require_bearer
def host_group_action():
    action_name = request.args.get('action_name', '')
    body = request.json if request.is_json else {}
    group_id = body.get('id', '')
    device_ids = [d.get('id') for d in body.get('action_parameters', []) if d.get('name') == 'device_id']

    if action_name == 'add-hosts':
        for did in device_ids:
            if did in store.device_by_id and group_id not in store.device_by_id[did]['groups']:
                store.device_by_id[did]['groups'].append(group_id)
    elif action_name == 'remove-hosts':
        for did in device_ids:
            if did in store.device_by_id:
                store.device_by_id[did]['groups'] = [
                    g for g in store.device_by_id[did]['groups'] if g != group_id
                ]

    return jsonify(cs_response([{"id": group_id}], total=1)), 200
