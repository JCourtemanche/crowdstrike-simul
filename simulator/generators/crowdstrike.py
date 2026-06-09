"""
CrowdStrike Falcon data generators.

Produces realistic seed data that satisfies all field requirements
identified in the integration YAML (DETECTIONS_BASE_KEY_MAP,
DETECTIONS_BEHAVIORS_KEY_MAP, SEARCH_DEVICE_VERBOSE_KEY_MAP, IOC_KEY_MAP,
HOST_GROUP_HEADERS, Spotlight vulnerability structure).
"""
import random
import uuid
import hashlib
from datetime import datetime, timedelta
from faker import Faker

from .base import (
    USERS,
    INTERNAL_IPS,
    MALICIOUS_IPS,
    MALICIOUS_DOMAINS,
    MALICIOUS_FILES,
    DOMAIN,
    COMPANY_NAME,
    generate_guid,
    generate_iso8601_date,
    generate_sha256,
    generate_md5,
    random_internal_ip,
    random_malicious_ip,
    random_user,
)

fake = Faker()

# ---------------------------------------------------------------------------
# Fixed CrowdStrike customer ID (CID) and shared IDs
# ---------------------------------------------------------------------------
CUSTOMER_ID = "abc123def456abc123def456abc123de"

PLATFORM_NAMES = ["Windows", "Mac", "Linux"]
OS_VERSIONS = {
    "Windows": ["Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022"],
    "Mac": ["macOS 13.6", "macOS 14.2"],
    "Linux": ["Amazon Linux 2", "CentOS 7", "Ubuntu 22.04"],
}
TACTICS = [
    ("Initial Access", "TA0001"), ("Execution", "TA0002"), ("Persistence", "TA0003"),
    ("Privilege Escalation", "TA0004"), ("Defense Evasion", "TA0005"),
    ("Credential Access", "TA0006"), ("Discovery", "TA0007"), ("Lateral Movement", "TA0008"),
    ("Collection", "TA0009"), ("Exfiltration", "TA0010"), ("Impact", "TA0040"),
]
TECHNIQUES = [
    ("PowerShell", "T1059.001"), ("WMI", "T1047"), ("Scheduled Task", "T1053.005"),
    ("Credential Dumping", "T1003"), ("Process Injection", "T1055"),
    ("Phishing", "T1566"), ("User Execution", "T1204"), ("Masquerading", "T1036"),
]
SCENARIOS = [
    "malicious_file", "suspicious_process", "privilege_escalation",
    "lateral_movement", "credential_access", "ransomware", "process_injection",
]
STATUSES = ["new", "in_progress", "true_positive", "false_positive", "ignored"]
DEVICE_STATUSES = ["normal", "contained", "containment_pending", "lift_containment_pending"]
SEVERITIES = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
IOC_TYPES = ["md5", "sha256", "domain", "ipv4", "ipv6", "sha1"]
IOC_ACTIONS = ["detect", "prevent", "no_action"]
IOC_PLATFORMS = ["windows", "mac", "linux"]
CVE_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
VULN_STATUSES = ["open", "reopen", "closed"]
GROUP_TYPES = ["static", "dynamic", "staticByID"]


# ---------------------------------------------------------------------------
# Helper generators
# ---------------------------------------------------------------------------

def _device_id():
    return uuid.uuid4().hex[:32]


def _detection_id(device_id: str):
    num = random.randint(100000000, 999999999)
    return f"ldt:{device_id}:{num}"


def _behavior_id(device_id: str):
    num = random.randint(100000000, 999999999)
    return f"ind:{device_id}:{num}"


def _cve_id():
    year = random.randint(2019, 2024)
    num = random.randint(1000, 99999)
    return f"CVE-{year}-{num}"


# ---------------------------------------------------------------------------
# Device generator
# ---------------------------------------------------------------------------

def generate_device(device_id: str | None = None) -> dict:
    device_id = device_id or _device_id()
    user = random_user()
    platform = random.choice(PLATFORM_NAMES)
    os_version = random.choice(OS_VERSIONS[platform])
    first_seen = generate_iso8601_date(
        start_time=datetime.utcnow() - timedelta(days=365),
        end_time=datetime.utcnow() - timedelta(days=30),
    )
    last_seen = generate_iso8601_date(
        start_time=datetime.utcnow() - timedelta(days=1),
        end_time=datetime.utcnow(),
    )
    mac = fake.mac_address().upper().replace(':', '-')
    local_ip = random_internal_ip()
    return {
        "device_id": device_id,
        "cid": CUSTOMER_ID,
        "agent_load_flags": str(random.randint(0, 3)),
        "agent_local_time": generate_iso8601_date(),
        "agent_version": f"{random.randint(6, 7)}.{random.randint(0, 9)}.{random.randint(10000, 19999)}.0",
        "bios_manufacturer": random.choice(["Dell Inc.", "HP", "Lenovo", "American Megatrends Inc."]),
        "bios_version": f"{random.randint(1, 3)}.{random.randint(0, 20)}.{random.randint(0, 9)}",
        "config_id_base": str(random.randint(65000000, 66000000)),
        "config_id_build": str(random.randint(10000, 20000)),
        "config_id_platform": str(random.randint(0, 5)),
        "connection_ip": local_ip,
        "connection_mac_address": mac,
        "cpu_signature": hex(random.randint(0x100000, 0xFFFFFF)),
        "default_gateway_ip": local_ip.rsplit('.', 1)[0] + '.1',
        "external_ip": random.choice([random_malicious_ip(), f"203.0.113.{random.randint(1,254)}"]),
        "first_seen": first_seen,
        "group_hash": uuid.uuid4().hex,
        "groups": [],
        "hostname": user['hostname'],
        "kernel_version": f"{random.randint(5, 10)}.{random.randint(0, 15)}.0-generic",
        "last_seen": last_seen,
        "local_ip": local_ip,
        "mac_address": mac,
        "major_version": str(random.randint(6, 10)),
        "meta": {"version": str(random.randint(1, 100)), "version_string": ""},
        "minor_version": str(random.randint(0, 3)),
        "modified_timestamp": last_seen,
        "os_version": os_version,
        "platform_id": str(PLATFORM_NAMES.index(platform)),
        "platform_name": platform,
        "policies": [
            {
                "policy_type": "prevention",
                "policy_id": uuid.uuid4().hex[:16],
                "applied": True,
                "settings_hash": uuid.uuid4().hex[:8],
                "assigned_date": first_seen,
                "applied_date": first_seen,
            }
        ],
        "product_type_desc": random.choice(["Workstation", "Server", "Domain Controller"]),
        "provision_status": "Provisioned",
        "reduced_functionality_mode": "no",
        "serial_number": fake.bothify(text='??###???##').upper(),
        "status": random.choice(DEVICE_STATUSES),
        "system_manufacturer": random.choice(["Dell Inc.", "HP Inc.", "Lenovo", "VMware, Inc."]),
        "system_product_name": random.choice(["Latitude 5520", "EliteBook 840", "ThinkPad X1 Carbon", "VMware Virtual Platform"]),
        "tags": [],
    }


# ---------------------------------------------------------------------------
# Alert / Detection generator
# ---------------------------------------------------------------------------

def generate_alert(device: dict) -> dict:
    device_id = device['device_id']
    detection_id = _detection_id(device_id)
    composite_id = f"{CUSTOMER_ID}:{detection_id}"
    behavior_id = _behavior_id(device_id)

    tactic, tactic_id = random.choice(TACTICS)
    technique, technique_id = random.choice(TECHNIQUES)
    malicious_file = random.choice(MALICIOUS_FILES)
    sha256 = generate_sha256()
    md5 = generate_md5()
    parent_sha256 = generate_sha256()
    parent_md5 = generate_md5()
    user = random_user()
    severity = random.choice(SEVERITIES)
    ts = generate_iso8601_date(
        start_time=datetime.utcnow() - timedelta(days=7),
        end_time=datetime.utcnow(),
    )

    return {
        "composite_id": composite_id,
        "cid": CUSTOMER_ID,
        "detection_id": detection_id,
        "created_timestamp": ts,
        "max_severity": severity,
        "max_severity_displayname": _severity_name(severity),
        "max_confidence": random.randint(50, 100),
        "show_in_ui": True,
        "status": random.choice(STATUSES),
        "first_behavior": ts,
        "last_behavior": ts,
        # Behavior fields (top-level in Raptor release, moved into behaviors list by integration code)
        "filename": malicious_file['name'],
        "scenario": random.choice(SCENARIOS),
        "md5": md5,
        "sha256": sha256,
        "ioc_type": random.choice(["hash_sha256", "hash_md5", "domain", "ipv4"]),
        "ioc_value": sha256,
        "cmdline": f"{malicious_file['name']} --payload {random.randint(1000, 9999)}",
        "user_name": user['name'],
        "behavior_id": behavior_id,
        "alleged_filetype": random.choice(["pe32", "pe64", "script", "doc"]),
        "confidence": random.randint(50, 100),
        "description": f"Suspicious {technique} activity detected on {device['hostname']}",
        "display_name": f"{tactic}: {technique}",
        "filepath": f"C:\\Users\\{user['name'].split()[0]}\\AppData\\Local\\Temp\\{malicious_file['name']}",
        "parent_md5": parent_md5,
        "parent_sha256": parent_sha256,
        "pattern_disposition": random.choice([0, 2048, 16384, 32768]),
        "pattern_disposition_details": {
            "blocking_unsupported_or_disabled": False,
            "detect": True,
            "fs_operation_blocked": False,
            "handle_operation_downgraded": False,
            "inddet_mask": False,
            "indicator": False,
            "kill_action_failed": False,
            "kill_parent": False,
            "kill_process": False,
            "kill_subprocess": False,
            "operation_blocked": False,
            "policy_disabled": False,
            "process_blocked": False,
            "quarantine_file": False,
            "quarantine_machine": False,
            "registry_operation_blocked": False,
            "rooting": False,
            "sensor_only": False,
            "suspend_parent": False,
            "suspend_process": False,
        },
        "tactic": tactic,
        "tactic_id": tactic_id,
        "technique": technique,
        "technique_id": technique_id,
        "parent_details": {
            "parent_cmdline": "C:\\Windows\\System32\\cmd.exe",
            "parent_md5": parent_md5,
            "parent_process_graph_id": f"pid:{device_id}:{random.randint(1000, 9999)}",
            "parent_sha256": parent_sha256,
        },
        "triggering_process_graph_id": f"pid:{device_id}:{random.randint(1000, 9999)}",
        "device": {
            "device_id": device_id,
            "cid": CUSTOMER_ID,
            "hostname": device['hostname'],
            "local_ip": device['local_ip'],
            "external_ip": device['external_ip'],
            "mac_address": device['mac_address'],
            "os_version": device['os_version'],
            "platform_name": device['platform_name'],
        },
        "hostinfo": {
            "domain": DOMAIN.split('.')[0].upper(),
        },
        "behaviors": [],
    }


def _severity_name(severity: int) -> str:
    if severity >= 90:
        return "Critical"
    if severity >= 70:
        return "High"
    if severity >= 50:
        return "Medium"
    if severity >= 30:
        return "Low"
    return "Informational"


# ---------------------------------------------------------------------------
# Custom IOC generator
# ---------------------------------------------------------------------------

def generate_ioc() -> dict:
    ioc_type = random.choice(IOC_TYPES)
    if ioc_type in ("md5",):
        value = generate_md5()
    elif ioc_type == "sha256":
        value = generate_sha256()
    elif ioc_type == "domain":
        value = random.choice(MALICIOUS_DOMAINS)
    elif ioc_type in ("ipv4",):
        value = random_malicious_ip()
    elif ioc_type == "ipv6":
        value = fake.ipv6()
    else:
        value = generate_sha256()

    created_ts = generate_iso8601_date(
        start_time=datetime.utcnow() - timedelta(days=90),
        end_time=datetime.utcnow() - timedelta(days=1),
    )
    expiry = (datetime.utcnow() + timedelta(days=random.randint(30, 365))).strftime('%Y-%m-%d')

    return {
        "id": str(uuid.uuid4()),
        "type": ioc_type,
        "value": value,
        "policy": random.choice(["detect", "none"]),
        "action": random.choice(IOC_ACTIONS),
        "severity": random.choice(["critical", "high", "medium", "low", "informational"]),
        "source": random.choice(["Analyst", "Threat Intel", "SIEM", "SOAR"]),
        "share_level": "red",
        "expiration": expiry,
        "description": f"Indicator of compromise: {value[:20]}...",
        "created_on": created_ts,
        "created_by": random_user()['email'],
        "modified_on": created_ts,
        "modified_by": random_user()['email'],
        "platforms": random.sample(IOC_PLATFORMS, k=random.randint(1, 3)),
        "tags": [],
        "mobile_action": "no_action",
        "applied_globally": True,
        "from_parent": False,
    }


# ---------------------------------------------------------------------------
# Vulnerability (Spotlight) generator
# ---------------------------------------------------------------------------

def generate_vulnerability(device: dict) -> dict:
    cve_id = _cve_id()
    base_score = round(random.uniform(3.0, 10.0), 1)
    return {
        "id": str(uuid.uuid4()),
        "cid": CUSTOMER_ID,
        "aid": device['device_id'],
        "created_timestamp": generate_iso8601_date(
            start_time=datetime.utcnow() - timedelta(days=60),
            end_time=datetime.utcnow() - timedelta(days=1),
        ),
        "updated_timestamp": generate_iso8601_date(),
        "status": random.choice(VULN_STATUSES),
        "apps": [
            {
                "product_name_version": fake.bothify(text="???? v#.#.#"),
                "sub_status": "open",
                "remediation": {
                    "ids": [str(uuid.uuid4())],
                },
                "evaluation_logic": {
                    "id": str(uuid.uuid4()),
                },
            }
        ],
        "cve": {
            "id": cve_id,
            "base_score": base_score,
            "severity": random.choice(CVE_SEVERITIES),
            "exploit_status": random.randint(0, 50),
            "exprt_rating": random.choice(CVE_SEVERITIES),
            "description": f"A vulnerability in software component allows attackers to execute arbitrary code.",
            "published_date": generate_iso8601_date(
                start_time=datetime.utcnow() - timedelta(days=365),
                end_time=datetime.utcnow() - timedelta(days=30),
            ),
            "impact_score": round(random.uniform(1.0, 10.0), 1),
            "exploitability_score": round(random.uniform(1.0, 10.0), 1),
            "vector": random.choice([
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H",
            ]),
        },
        "host_info": {
            "hostname": device['hostname'],
            "local_ip": device['local_ip'],
            "machine_domain": DOMAIN.split('.')[0].upper(),
            "os_version": device['os_version'],
            "platform_name": device['platform_name'],
            "site_name": "Default",
            "system_manufacturer": device['system_manufacturer'],
        },
        "remediation": {
            "entities": [
                {
                    "id": str(uuid.uuid4()),
                    "reference": f"Update to patched version to mitigate {cve_id}",
                    "title": "Apply security patch",
                    "action": "Patch",
                    "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                }
            ]
        },
    }


# ---------------------------------------------------------------------------
# Host group generator
# ---------------------------------------------------------------------------

def generate_host_group(group_id: str | None = None) -> dict:
    group_id = group_id or str(uuid.uuid4()).replace('-', '')[:16]
    group_type = random.choice(GROUP_TYPES)
    ts = generate_iso8601_date(
        start_time=datetime.utcnow() - timedelta(days=180),
        end_time=datetime.utcnow() - timedelta(days=1),
    )
    names = [
        "Windows Workstations", "Linux Servers", "Domain Controllers",
        "Finance Team", "Engineering", "Executive Endpoints", "DMZ Hosts",
    ]
    name = random.choice(names)
    return {
        "id": group_id,
        "cid": CUSTOMER_ID,
        "group_type": group_type,
        "name": name,
        "description": f"Group containing {name.lower()}",
        "assignment_rule": "" if group_type == "static" else f"platform_name:'Windows'+status:'normal'",
        "created_by": random_user()['email'],
        "created_timestamp": ts,
        "modified_by": random_user()['email'],
        "modified_timestamp": ts,
    }


# ---------------------------------------------------------------------------
# Process generator
# ---------------------------------------------------------------------------

def generate_process(device: dict) -> dict:
    malicious_file = random.choice(MALICIOUS_FILES)
    user = random_user()
    return {
        "process_id": f"pid:{device['device_id']}:{random.randint(1000, 65535)}",
        "device_id": device['device_id'],
        "cmdline": f"{malicious_file['name']} --run {random.randint(1, 100)}",
        "image_file_name": f"\\Device\\HarddiskVolume3\\Users\\{user['name'].split()[0]}\\{malicious_file['name']}",
        "process_id_local": str(random.randint(1000, 65535)),
        "start_timestamp": generate_iso8601_date(
            start_time=datetime.utcnow() - timedelta(hours=2),
            end_time=datetime.utcnow() - timedelta(minutes=5),
        ),
        "stop_timestamp": generate_iso8601_date(
            start_time=datetime.utcnow() - timedelta(minutes=5),
            end_time=datetime.utcnow(),
        ),
        "sha256": generate_sha256(),
        "md5": generate_md5(),
    }
