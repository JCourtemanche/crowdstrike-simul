"""
CrowdStrike Falcon IOC / Custom Indicator endpoints.

GET/POST/PATCH/DELETE /iocs/entities/indicators/v1   → manage custom IOCs
GET                   /iocs/combined/indicator/v1    → search IOCs
GET                   /indicators/queries/iocs/v1    → legacy IOC query
GET                   /indicators/entities/iocs/v1   → legacy IOC entities
GET                   /indicators/queries/devices/v1 → devices that ran an IOC
GET                   /indicators/aggregates/devices-count/v1 → count devices per IOC
GET                   /indicators/queries/processes/v1 → processes that ran an IOC
"""
import uuid
import random
from flask import Blueprint, request, jsonify
from auth import require_bearer
from helpers import cs_response, cs_error, paginate, cursor_paginate
import store
from generators.crowdstrike import generate_ioc

iocs_bp = Blueprint('iocs', __name__)


# ---------------------------------------------------------------------------
# Combined IOC search (new API)
# ---------------------------------------------------------------------------
@iocs_bp.route('/iocs/combined/indicator/v1', methods=['GET'])
@require_bearer
def search_iocs_combined():
    limit = min(int(request.args.get('limit', 100)), 500)
    after = request.args.get('after')
    types = request.args.getlist('filter.type') or request.args.getlist('types')

    filtered = store.iocs
    if types:
        filtered = [i for i in filtered if i['type'] in types]

    page, next_after = cursor_paginate(filtered, after, limit)
    return jsonify(cs_response(page, total=len(filtered), after=next_after)), 200


# ---------------------------------------------------------------------------
# IOC entity CRUD (new API)
# ---------------------------------------------------------------------------
@iocs_bp.route('/iocs/entities/indicators/v1', methods=['GET'])
@require_bearer
def get_ioc_by_ids():
    ids = request.args.getlist('ids')
    resources = [store.ioc_by_id[iid] for iid in ids if iid in store.ioc_by_id]
    return jsonify(cs_response(resources, total=len(resources))), 200


@iocs_bp.route('/iocs/entities/indicators/v1', methods=['POST'])
@require_bearer
def create_ioc():
    body = request.json if request.is_json else {}
    indicators = body.get('indicators', [body])
    created = []
    for indicator in indicators:
        new_ioc = generate_ioc()
        new_ioc.update({
            "type": indicator.get('type', new_ioc['type']),
            "value": indicator.get('value', new_ioc['value']),
            "action": indicator.get('action', new_ioc['action']),
            "severity": indicator.get('severity', new_ioc['severity']),
            "description": indicator.get('description', new_ioc['description']),
            "platforms": indicator.get('platforms', new_ioc['platforms']),
            "tags": indicator.get('tags', []),
            "source": indicator.get('source', new_ioc['source']),
            "expiration": indicator.get('expiration', new_ioc['expiration']),
        })
        store.iocs.append(new_ioc)
        store.ioc_by_id[new_ioc['id']] = new_ioc
        created.append(new_ioc)
    return jsonify(cs_response(created, total=len(created))), 200


@iocs_bp.route('/iocs/entities/indicators/v1', methods=['PATCH'])
@require_bearer
def update_ioc():
    body = request.json if request.is_json else {}
    indicators = body.get('indicators', [body])
    updated = []
    for indicator in indicators:
        iid = indicator.get('id')
        if iid and iid in store.ioc_by_id:
            store.ioc_by_id[iid].update({
                k: v for k, v in indicator.items()
                if k in ('action', 'severity', 'description', 'tags', 'platforms', 'expiration', 'source')
            })
            updated.append(store.ioc_by_id[iid])
    return jsonify(cs_response(updated, total=len(updated))), 200


@iocs_bp.route('/iocs/entities/indicators/v1', methods=['DELETE'])
@require_bearer
def delete_ioc():
    ids = request.args.getlist('ids')
    deleted = []
    for iid in ids:
        if iid in store.ioc_by_id:
            del store.ioc_by_id[iid]
            store.iocs[:] = [i for i in store.iocs if i['id'] != iid]
            deleted.append({"id": iid})
    return jsonify(cs_response(deleted, total=len(deleted))), 200


# ---------------------------------------------------------------------------
# Legacy IOC endpoints
# ---------------------------------------------------------------------------
@iocs_bp.route('/indicators/queries/iocs/v1', methods=['GET'])
@require_bearer
def query_legacy_iocs():
    limit = min(int(request.args.get('limit', 100)), 500)
    offset = int(request.args.get('offset', 0))
    page, total = paginate(store.iocs, offset, limit)
    ids = [i['id'] for i in page]
    return jsonify(cs_response(ids, total=total, offset=offset, limit=limit)), 200


@iocs_bp.route('/indicators/entities/iocs/v1', methods=['GET'])
@require_bearer
def get_legacy_iocs():
    ids = request.args.getlist('ids')
    resources = [store.ioc_by_id.get(iid) for iid in ids if iid in store.ioc_by_id]
    return jsonify(cs_response(resources, total=len(resources))), 200


# ---------------------------------------------------------------------------
# Device / process association queries
# ---------------------------------------------------------------------------
@iocs_bp.route('/indicators/queries/devices/v1', methods=['GET'])
@require_bearer
def devices_ran_on():
    limit = min(int(request.args.get('limit', 100)), 500)
    offset = int(request.args.get('offset', 0))
    device_subset = store.devices[:max(1, len(store.devices) // 2)]
    page, total = paginate(device_subset, offset, limit)
    ids = [d['device_id'] for d in page]
    return jsonify(cs_response(ids, total=total, offset=offset, limit=limit)), 200


@iocs_bp.route('/indicators/aggregates/devices-count/v1', methods=['GET'])
@require_bearer
def device_count_ioc():
    count = random.randint(1, len(store.devices))
    return jsonify(cs_response([{"count": count}], total=1)), 200


@iocs_bp.route('/indicators/queries/processes/v1', methods=['GET'])
@require_bearer
def processes_ran_on():
    limit = min(int(request.args.get('limit', 100)), 500)
    offset = int(request.args.get('offset', 0))
    page, total = paginate(store.processes, offset, limit)
    ids = [p['process_id'] for p in page]
    return jsonify(cs_response(ids, total=total, offset=offset, limit=limit)), 200
