"""
CrowdStrike Spotlight (Vulnerability Management) endpoints.

GET /spotlight/combined/vulnerabilities/v1  → search vulnerabilities

Consumed by:
  - cs-falcon-spotlight-search-vulnerability
  - cs-falcon-spotlight-list-host-by-vulnerability
  - `cve` command
  - fetch-assets (Spotlight track — severity-parallel fan-out, filter
    `status:['open','reopen']+cve.severity:['<SEV>']+updated_timestamp:>'now-100d'`,
    facet=host_info&facet=cve, cursor pagination via `after`)
"""
import re
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify
from auth import require_bearer
from helpers import cs_response, cursor_paginate
import store

spotlight_bp = Blueprint('spotlight', __name__)


# ---------------------------------------------------------------------------
# Minimalist FQL filter parser
# ---------------------------------------------------------------------------
# Only the clauses actually emitted by the XSIAM content pack are recognized:
#   status:['open','reopen']
#   cve.severity:['CRITICAL','HIGH']
#   updated_timestamp:>'now-100d'
#   aid:'<uuid>'
#   cve.id:'CVE-YYYY-NNNN'
# Unknown clauses are silently ignored — good enough for a mock, avoids
# writing a full FQL grammar.

_LIST_RE = re.compile(r"^([\w.]+):\[([^\]]*)\]$")
_EQ_RE = re.compile(r"^([\w.]+):'([^']*)'$")
_GT_RE = re.compile(r"^([\w.]+):>'([^']*)'$")


def _split_fql(filter_str: str) -> list[str]:
    """Split a FQL string on the top-level '+' (AND) operator."""
    parts, buf, depth = [], "", 0
    for ch in filter_str:
        if ch == '[':
            depth += 1
        elif ch == ']':
            depth = max(0, depth - 1)
        if ch == '+' and depth == 0:
            parts.append(buf.strip())
            buf = ""
        else:
            buf += ch
    if buf.strip():
        parts.append(buf.strip())
    return parts


def _parse_list(raw: str) -> list[str]:
    """Turn "'open','reopen'" into ['open', 'reopen']."""
    return [item.strip().strip("'\"") for item in raw.split(',') if item.strip()]


def _parse_lookback(value: str) -> datetime | None:
    """Parse "now-100d" / "now-24h" / "now-30m" into an absolute UTC datetime."""
    m = re.match(r"^now-(\d+)([dhm])$", value)
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2)
    delta = {'d': timedelta(days=n), 'h': timedelta(hours=n), 'm': timedelta(minutes=n)}[unit]
    return datetime.utcnow() - delta


def _apply_fql(vulns: list[dict], filter_str: str) -> list[dict]:
    if not filter_str:
        return vulns
    filtered = vulns
    for clause in _split_fql(filter_str):
        if m := _LIST_RE.match(clause):
            field, values = m.group(1), _parse_list(m.group(2))
            if not values:
                continue
            if field == 'status':
                filtered = [v for v in filtered if v.get('status') in values]
            elif field == 'cve.severity':
                filtered = [v for v in filtered if v.get('cve', {}).get('severity') in values]
        elif m := _GT_RE.match(clause):
            field, val = m.group(1), m.group(2)
            if field == 'updated_timestamp':
                cutoff = _parse_lookback(val)
                if cutoff is not None:
                    filtered = [
                        v for v in filtered
                        if _iso_to_dt(v.get('updated_timestamp')) and
                        _iso_to_dt(v.get('updated_timestamp')) >= cutoff
                    ]
        elif m := _EQ_RE.match(clause):
            field, val = m.group(1), m.group(2)
            if field == 'aid':
                filtered = [v for v in filtered if v.get('aid') == val]
            elif field == 'cve.id':
                filtered = [v for v in filtered if v.get('cve', {}).get('id') == val]
    return filtered


def _iso_to_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ')
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------
@spotlight_bp.route('/spotlight/combined/vulnerabilities/v1', methods=['GET'])
@require_bearer
def search_vulnerabilities():
    # Fetch-assets flow passes limit=5000; the search command caps at 2500.
    limit = min(int(request.args.get('limit', 100)), 5000)
    after = request.args.get('after')
    filter_arg = request.args.get('filter', '')
    cve_ids = request.args.getlist('cve_id')
    aids = request.args.getlist('aid')
    # The `facet` param is accepted (fetch-assets sends ["host_info", "cve"];
    # cs-falcon-spotlight-search-vulnerability sends up to 4 facets). We
    # always return the full document — clients tolerate extra fields.
    _ = request.args.getlist('facet')

    filtered = store.vulnerabilities
    if cve_ids:
        filtered = [v for v in filtered if v['cve']['id'] in cve_ids]
    if aids:
        filtered = [v for v in filtered if v['aid'] in aids]
    filtered = _apply_fql(filtered, filter_arg)

    page, next_after = cursor_paginate(filtered, after, limit)
    return jsonify(cs_response(page, total=len(filtered), after=next_after)), 200
