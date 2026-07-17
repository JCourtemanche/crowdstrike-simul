"""
Common response helpers for CrowdStrike Falcon mock API.
"""
import uuid
import time


def cs_response(resources, total: int | None = None, offset: int = 0, limit: int = 100, after: str | None = None):
    """Build a standard CrowdStrike API envelope."""
    pagination = {
        "offset": offset,
        "limit": limit,
        "total": total if total is not None else len(resources),
    }
    if after is not None:
        pagination["after"] = after
    return {
        "meta": {
            "query_time": round(time.time() % 1, 6),
            "pagination": pagination,
            "trace_id": str(uuid.uuid4()),
        },
        "resources": resources,
        "errors": [],
    }


def cs_error(code: int, message: str, http_status: int = 400):
    """Build a CrowdStrike error envelope + HTTP status as a Flask return tuple.
    Callers use `return cs_error(...)` (no jsonify wrap).
    """
    from flask import jsonify
    return jsonify({
        "meta": {"query_time": 0.001, "trace_id": str(uuid.uuid4())},
        "errors": [{"code": code, "message": message}],
        "resources": [],
    }), http_status


def paginate(items: list, offset: int, limit: int) -> tuple[list, int]:
    """Slice a list and return (page, total)."""
    total = len(items)
    page = items[offset: offset + limit]
    return page, total


def cursor_paginate(items: list, after: str | None, limit: int) -> tuple[list, str | None]:
    """Cursor-based pagination using base64-encoded index."""
    import base64
    if after:
        try:
            start = int(base64.b64decode(after).decode())
        except Exception:
            start = 0
    else:
        start = 0
    page = items[start: start + limit]
    next_cursor = None
    if start + limit < len(items):
        next_cursor = base64.b64encode(str(start + limit).encode()).decode()
    return page, next_cursor
