"""
CrowdStrike Falcon process endpoints.

GET /processes/entities/processes/v1  → get process details by IDs
"""
from flask import Blueprint, request, jsonify
from auth import require_bearer
from helpers import cs_response
import store

processes_bp = Blueprint('processes', __name__)

_process_by_id: dict = {}


def _index_processes():
    global _process_by_id
    if not _process_by_id and store.processes:
        _process_by_id = {p['process_id']: p for p in store.processes}


@processes_bp.route('/processes/entities/processes/v1', methods=['GET'])
@require_bearer
def get_processes():
    _index_processes()
    ids = request.args.getlist('ids')
    resources = [_process_by_id[pid] for pid in ids if pid in _process_by_id]
    return jsonify(cs_response(resources, total=len(resources))), 200
