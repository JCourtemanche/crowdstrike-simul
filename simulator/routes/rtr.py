"""
CrowdStrike Real Time Response (RTR) endpoints.

POST /real-time-response/entities/sessions/v1           → init session
POST /real-time-response/entities/command/v1            → run command
POST /real-time-response/entities/get-command/v1        → run get command
GET  /real-time-response/entities/command/v1            → status of command
GET  /real-time-response/entities/get-command/v1        → status of get command
DELETE /real-time-response/entities/sessions/v1         → close session
GET  /real-time-response/combined/session-files/v1      → list session files

POST /real-time-response/entities/scripts/v1            → upload script
DELETE /real-time-response/entities/scripts/v1          → delete script
GET  /real-time-response/entities/scripts/v1            → get scripts
GET  /real-time-response/queries/scripts/v1             → list scripts
POST /real-time-response/entities/put-files/v1          → upload file
DELETE /real-time-response/entities/put-files/v1        → delete file
GET  /real-time-response/entities/put-files/v1          → get files
GET  /real-time-response/queries/put-files/v1           → list files
"""
import uuid
import random
from flask import Blueprint, request, jsonify
from auth import require_bearer
from helpers import cs_response, paginate
from generators.crowdstrike import generate_iso8601_date, CUSTOMER_ID, random_user
import store

rtr_bp = Blueprint('rtr', __name__)

_sessions: dict[str, dict] = {}
_scripts: list[dict] = []
_put_files: list[dict] = []


def _ensure_scripts():
    global _scripts
    if not _scripts:
        for name in ["RunScript.ps1", "GetSystemInfo.ps1", "KillProcess.ps1", "CollectLogs.sh"]:
            _scripts.append({
                "id": str(uuid.uuid4()).replace('-', '')[:16],
                "name": name,
                "description": f"RTR script: {name}",
                "platform": ["windows"] if name.endswith('.ps1') else ["linux", "mac"],
                "created_by": random_user()['email'],
                "created_timestamp": generate_iso8601_date(),
                "modified_by": random_user()['email'],
                "modified_timestamp": generate_iso8601_date(),
            })


# ---------------------------------------------------------------------------
# RTR Session management
# ---------------------------------------------------------------------------
@rtr_bp.route('/real-time-response/entities/sessions/v1', methods=['POST'])
@require_bearer
def init_session():
    body = request.json if request.is_json else {}
    device_id = body.get('device_id', '')
    session_id = str(uuid.uuid4())
    _sessions[session_id] = {
        "session_id": session_id,
        "device_id": device_id,
        "created_at": generate_iso8601_date(),
        "status": "established",
    }
    return jsonify(cs_response([{"session_id": session_id}], total=1)), 201


@rtr_bp.route('/real-time-response/entities/sessions/v1', methods=['DELETE'])
@require_bearer
def close_session():
    session_id = request.args.get('session_id', '')
    if session_id in _sessions:
        del _sessions[session_id]
    return jsonify(cs_response([], total=0)), 204


# ---------------------------------------------------------------------------
# RTR Commands
# ---------------------------------------------------------------------------
@rtr_bp.route('/real-time-response/entities/command/v1', methods=['POST'])
@require_bearer
def run_command():
    body = request.json if request.is_json else {}
    cloud_req_id = str(uuid.uuid4())
    return jsonify(cs_response([{
        "session_id": body.get('session_id', ''),
        "cloud_request_id": cloud_req_id,
        "queued_commandline": body.get('command_string', ''),
    }], total=1)), 201


@rtr_bp.route('/real-time-response/entities/command/v1', methods=['GET'])
@require_bearer
def status_command():
    cloud_req_id = request.args.get('cloud_request_id', '')
    return jsonify(cs_response([{
        "cloud_request_id": cloud_req_id,
        "session_id": str(uuid.uuid4()),
        "task_id": str(uuid.uuid4()),
        "complete": True,
        "stdout": "Command executed successfully",
        "stderr": "",
        "base_command": request.args.get('sequence_id', '0'),
        "stop_on_done": True,
    }], total=1)), 200


@rtr_bp.route('/real-time-response/entities/get-command/v1', methods=['POST'])
@require_bearer
def run_get_command():
    body = request.json if request.is_json else {}
    cloud_req_id = str(uuid.uuid4())
    return jsonify(cs_response([{
        "session_id": body.get('session_id', ''),
        "cloud_request_id": cloud_req_id,
    }], total=1)), 201


@rtr_bp.route('/real-time-response/entities/get-command/v1', methods=['GET'])
@require_bearer
def status_get_command():
    cloud_req_id = request.args.get('cloud_request_id', '')
    return jsonify(cs_response([{
        "cloud_request_id": cloud_req_id,
        "complete": True,
        "stdout": "",
        "stderr": "",
        "device_id": str(uuid.uuid4()),
    }], total=1)), 200


@rtr_bp.route('/real-time-response/combined/session-files/v1', methods=['GET'])
@require_bearer
def list_session_files():
    return jsonify(cs_response([], total=0)), 200


# ---------------------------------------------------------------------------
# Scripts
# ---------------------------------------------------------------------------
@rtr_bp.route('/real-time-response/entities/scripts/v1', methods=['POST'])
@require_bearer
def upload_script():
    _ensure_scripts()
    name = request.form.get('name', 'unnamed.ps1')
    new_script = {
        "id": str(uuid.uuid4()).replace('-', '')[:16],
        "name": name,
        "description": request.form.get('description', ''),
        "platform": [request.form.get('platform', 'windows')],
        "created_by": random_user()['email'],
        "created_timestamp": generate_iso8601_date(),
        "modified_by": random_user()['email'],
        "modified_timestamp": generate_iso8601_date(),
    }
    _scripts.append(new_script)
    return jsonify(cs_response([new_script], total=1)), 200


@rtr_bp.route('/real-time-response/entities/scripts/v1', methods=['GET'])
@require_bearer
def get_scripts():
    _ensure_scripts()
    ids = request.args.getlist('ids')
    script_by_id = {s['id']: s for s in _scripts}
    resources = [script_by_id[sid] for sid in ids if sid in script_by_id] if ids else _scripts
    return jsonify(cs_response(resources, total=len(resources))), 200


@rtr_bp.route('/real-time-response/entities/scripts/v1', methods=['DELETE'])
@require_bearer
def delete_script():
    ids = request.args.getlist('ids')
    global _scripts
    _scripts = [s for s in _scripts if s['id'] not in ids]
    return jsonify(cs_response(ids, total=len(ids))), 200


@rtr_bp.route('/real-time-response/queries/scripts/v1', methods=['GET'])
@require_bearer
def list_scripts():
    _ensure_scripts()
    ids = [s['id'] for s in _scripts]
    return jsonify(cs_response(ids, total=len(ids))), 200


# ---------------------------------------------------------------------------
# Put files
# ---------------------------------------------------------------------------
@rtr_bp.route('/real-time-response/entities/put-files/v1', methods=['POST'])
@require_bearer
def upload_file():
    name = request.form.get('name', 'unnamed.exe')
    new_file = {
        "id": str(uuid.uuid4()).replace('-', '')[:16],
        "name": name,
        "description": request.form.get('description', ''),
        "created_by": random_user()['email'],
        "created_timestamp": generate_iso8601_date(),
    }
    _put_files.append(new_file)
    return jsonify(cs_response([new_file], total=1)), 200


@rtr_bp.route('/real-time-response/entities/put-files/v1', methods=['GET'])
@require_bearer
def get_put_files():
    ids = request.args.getlist('ids')
    file_by_id = {f['id']: f for f in _put_files}
    resources = [file_by_id[fid] for fid in ids if fid in file_by_id] if ids else _put_files
    return jsonify(cs_response(resources, total=len(resources))), 200


@rtr_bp.route('/real-time-response/entities/put-files/v1', methods=['DELETE'])
@require_bearer
def delete_put_file():
    ids = request.args.getlist('ids')
    global _put_files
    _put_files = [f for f in _put_files if f['id'] not in ids]
    return jsonify(cs_response(ids, total=len(ids))), 200


@rtr_bp.route('/real-time-response/queries/put-files/v1', methods=['GET'])
@require_bearer
def list_put_files():
    ids = [f['id'] for f in _put_files]
    return jsonify(cs_response(ids, total=len(ids))), 200
