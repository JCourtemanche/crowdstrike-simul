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
CVE_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]
VULN_STATUSES = ["open", "reopen", "closed"]
GROUP_TYPES = ["static", "dynamic", "staticByID"]

# ---------------------------------------------------------------------------
# Cloud / CNAPP taxonomy
# ---------------------------------------------------------------------------
CLOUD_PROVIDERS = ["aws", "azure", "gcp"]
CLOUD_REGIONS = {
    "aws": ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1"],
    "azure": ["eastus", "westeurope", "northeurope"],
    "gcp": ["us-central1", "europe-west1", "asia-east1"],
}
CNAPP_CLUSTERS = ["prod-eks-01", "prod-gke-02", "staging-aks-01", "dev-eks-sandbox"]
CNAPP_NAMESPACES = ["default", "kube-system", "payments", "orders-api", "web-frontend", "data-pipeline"]
CNAPP_IMAGE_REGISTRIES = ["docker.io", "gcr.io", "quay.io", "public.ecr.aws"]
CNAPP_IMAGE_REPOS = ["business/api", "business/worker", "nginx", "redis", "postgres", "python", "node"]
CNAPP_DETECTIONS = [
    ("Container running as privileged user",
     "The container was started with --privileged, granting it access to all host devices and capabilities.",
     "CloudContainerPrivileged"),
    ("Sensitive host path mounted into container",
     "A container has mounted a sensitive host path (/var/run/docker.sock, /etc, or /proc), enabling potential host escape.",
     "CloudSensitiveMount"),
    ("Cryptomining process detected in container runtime",
     "A process typical of cryptocurrency mining (xmrig, minerd) was observed executing inside a running container.",
     "CloudRuntimeCryptomining"),
    ("Reverse shell process launched from container",
     "A shell process was spawned with a socket redirected to a remote IP address, consistent with post-exploitation behavior.",
     "CloudRuntimeReverseShell"),
    ("Suspicious kubectl exec into production pod",
     "A kubectl exec session was opened against a production namespace outside of business hours.",
     "K8sSuspiciousExec"),
    ("Image with critical vulnerability deployed to production",
     "A container image containing a known critical CVE was deployed to the production cluster.",
     "CloudImageCriticalCVE"),
    ("Public S3 bucket contains sensitive data",
     "An object storage bucket exposed to the internet contains files matching sensitive data patterns.",
     "CloudStoragePublicSensitive"),
    ("IAM role with wildcard permissions attached to workload",
     "A cloud workload is running with an over-privileged IAM role granting Action:* on Resource:*.",
     "CloudIAMWildcardPermissions"),
    ("Container image pulled from untrusted registry",
     "A pod was scheduled with an image sourced from a registry not on the organization's allowlist.",
     "CloudImageUntrustedRegistry"),
    ("Outbound connection to known-malicious IP from container",
     "A container established an egress connection to an IP address on the threat intelligence blocklist.",
     "CloudRuntimeMaliciousEgress"),
]
CNAPP_SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]
CVE_REMEDIATION_LEVELS = ["O", "T", "W", "U"]  # Official-fix, Temp-fix, Workaround, Unavailable
CVE_ACTOR_POOL = [
    "APT28", "APT29", "APT41", "Lazarus", "Silent Ram", "Fancy Bear", "Cozy Bear",
    "Charming Kitten", "Wizard Spider", "Muddled Libra",
]
OS_BUILDS = {
    "Windows": ["19045", "22000", "22621", "22631", "20348"],
    "Mac": ["22G120", "23B92", "23C71"],
    "Linux": ["5.15.0-88-generic", "6.1.0-15-amd64", "4.14.336-256.h539"],
}
OS_PRODUCT_NAMES = {
    "Windows": ["Windows 10 Enterprise", "Windows 10 Pro", "Windows 11 Enterprise", "Windows Server 2019 Datacenter", "Windows Server 2022 Standard"],
    "Mac": ["macOS Ventura", "macOS Sonoma"],
    "Linux": ["Amazon Linux 2", "CentOS Linux 7", "Ubuntu Server 22.04 LTS"],
}
CLOUD_SERVICE_PROVIDERS = ["AWS_EC2_V2", "Azure", "Google_Cloud_Compute_Engine", "On-Prem"]


# ---------------------------------------------------------------------------
# Helper generators
# ---------------------------------------------------------------------------

def _device_id():
    # NOT uuid.uuid4() — that uses os.urandom and is not deterministic even
    # when random.seed() is called. This uses stdlib random, so bootstrap
    # with a fixed Config.SEED produces the same device_ids across every
    # instance / restart. Required for multi-instance consistency on Cloud
    # Run (fetch-assets otherwise fails to enrich cross-instance AIDs).
    return f"{random.getrandbits(128):032x}"


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
    last_login = generate_iso8601_date(
        start_time=datetime.utcnow() - timedelta(days=7),
        end_time=datetime.utcnow(),
    )
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
        "last_login_timestamp": last_login,
        "last_seen": last_seen,
        "local_ip": local_ip,
        "mac_address": mac,
        "machine_domain": DOMAIN.split('.')[0].upper(),
        "major_version": str(random.randint(6, 10)),
        "meta": {"version": str(random.randint(1, 100)), "version_string": ""},
        "minor_version": str(random.randint(0, 3)),
        "modified_timestamp": last_seen,
        "os_build": random.choice(OS_BUILDS[platform]),
        "os_product_name": random.choice(OS_PRODUCT_NAMES[platform]),
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

def generate_vulnerability(device: dict, host_groups: list[dict] | None = None, severity: str | None = None) -> dict:
    cve_id = _cve_id()
    base_score = round(random.uniform(0.0, 10.0), 1)
    cve_severity = severity or random.choice(CVE_SEVERITIES)
    published = generate_iso8601_date(
        start_time=datetime.utcnow() - timedelta(days=365),
        end_time=datetime.utcnow() - timedelta(days=30),
    )
    spotlight_published = generate_iso8601_date(
        start_time=datetime.utcnow() - timedelta(days=180),
        end_time=datetime.utcnow() - timedelta(days=1),
    )
    is_kev = random.random() < 0.15
    kev_due_date = (
        (datetime.utcnow() + timedelta(days=random.randint(7, 60))).strftime('%Y-%m-%d')
        if is_kev else ""
    )
    actors = random.sample(CVE_ACTOR_POOL, k=random.randint(0, 2))

    # Pick 0–2 real host_groups for this host (falls back to empty when none seeded)
    device_group_ids = device.get('groups') or []
    resolved_groups = []
    if host_groups:
        by_id = {g['id']: g for g in host_groups}
        for gid in device_group_ids[:3]:
            g = by_id.get(gid)
            if g:
                resolved_groups.append({"id": g['id'], "name": g['name']})

    provider = random.choice(CLOUD_SERVICE_PROVIDERS)
    return {
        "id": str(uuid.uuid4()),
        "cid": CUSTOMER_ID,
        "aid": device['device_id'],
        "created_timestamp": generate_iso8601_date(
            start_time=datetime.utcnow() - timedelta(days=60),
            end_time=datetime.utcnow() - timedelta(days=1),
        ),
        "updated_timestamp": generate_iso8601_date(
            start_time=datetime.utcnow() - timedelta(days=7),
            end_time=datetime.utcnow(),
        ),
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
            "name": f"Remote Code Execution in {fake.company()} Product",
            "base_score": base_score,
            "severity": cve_severity,
            "exploit_status": random.randint(0, 50),
            "exprt_rating": random.choice(CVE_SEVERITIES),
            "description": (
                f"A vulnerability in a software component allows a remote attacker to "
                f"execute arbitrary code by sending a specially crafted request. "
                f"Successful exploitation could lead to full system compromise."
            ),
            "published_date": published,
            "spotlight_published_date": spotlight_published,
            "impact_score": round(random.uniform(1.0, 10.0), 1),
            "exploitability_score": round(random.uniform(1.0, 10.0), 1),
            "remediation_level": random.choice(CVE_REMEDIATION_LEVELS),
            "vendor_advisory": f"https://vendor.example.com/security/advisories/{cve_id}",
            "vector": random.choice([
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H",
            ]),
            "cisa_info": {
                "is_cisa_kev": is_kev,
                "due_date": kev_due_date,
            },
            "actors": actors,
        },
        "host_info": {
            "hostname": device['hostname'],
            "instance_id": f"i-{uuid.uuid4().hex[:17]}" if provider != "On-Prem" else "",
            "service_provider": provider,
            "service_provider_account_id": (
                str(random.randint(100000000000, 999999999999)) if provider != "On-Prem" else ""
            ),
            "local_ip": device['local_ip'],
            "machine_domain": DOMAIN.split('.')[0].upper(),
            "os_build": device.get('os_build', ''),
            "os_version": device['os_version'],
            "ou": random.choice(["Corporate/Endpoints", "Corporate/Servers", "Cloud/EKS", "Cloud/AKS"]),
            "product_type_desc": device.get('product_type_desc', 'Workstation'),
            "platform": device['platform_name'],
            "platform_name": device['platform_name'],
            "site_name": "Default",
            "system_manufacturer": device['system_manufacturer'],
            "groups": resolved_groups,
            "tags": [],
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
    # Deterministic (see _device_id note).
    group_id = group_id or f"{random.getrandbits(64):016x}"
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
# CNAPP / Container-Security alert generator
# ---------------------------------------------------------------------------

def _container_id():
    # Deterministic (see _device_id note) — CNAPP alerts and their
    # containers_impacted_ids should also be stable across Cloud Run
    # instances so XSIAM doesn't see duplicate rows on re-ingestion.
    return f"{random.getrandbits(128):032x}"


def _alert_uuid():
    """Deterministic UUID-shaped string for CNAPP alert `id` / `image_digest`."""
    rb = random.getrandbits(128).to_bytes(16, 'big')
    hx = rb.hex()
    return f"{hx[:8]}-{hx[8:12]}-{hx[12:16]}-{hx[16:20]}-{hx[20:]}"


def generate_cnapp_alert() -> dict:
    detection_name, description, event_simple_name = random.choice(CNAPP_DETECTIONS)
    provider = random.choice(CLOUD_PROVIDERS)
    region = random.choice(CLOUD_REGIONS[provider])
    cluster = random.choice(CNAPP_CLUSTERS)
    namespace = random.choice(CNAPP_NAMESPACES)
    registry = random.choice(CNAPP_IMAGE_REGISTRIES)
    repo = random.choice(CNAPP_IMAGE_REPOS)
    tag = random.choice(["latest", "v1.2.3", "v2.0.0-rc1", "stable", "prod-2026-07"])
    impacted_count = random.randint(1, 8)
    container_ids = [_container_id() for _ in range(impacted_count)]
    first_seen = generate_iso8601_date(
        start_time=datetime.utcnow() - timedelta(days=14),
        end_time=datetime.utcnow() - timedelta(hours=1),
    )
    last_seen = generate_iso8601_date(
        start_time=datetime.utcnow() - timedelta(hours=1),
        end_time=datetime.utcnow(),
    )
    account_id = (
        str(random.randint(100000000000, 999999999999)) if provider == "aws"
        else f"{provider}-subscription-{uuid.uuid4().hex[:12]}"
    )
    return {
        "id": _alert_uuid(),
        "cid": CUSTOMER_ID,
        "detection_name": detection_name,
        "detection_description": description,
        "detection_event_simple_name": event_simple_name,
        "severity": random.choice(CNAPP_SEVERITIES),
        "first_seen_timestamp": first_seen,
        "last_seen_timestamp": last_seen,
        "containers_impacted_count": str(impacted_count),
        "containers_impacted_ids": container_ids,
        # Context enrichment fields (realistic, non-schema)
        "cloud_provider": provider,
        "cloud_region": region,
        "cloud_account_id": account_id,
        "cluster_name": cluster,
        "namespace": namespace,
        "image_id": generate_sha256(),
        "image_registry": registry,
        "image_repository": repo,
        "image_tag": tag,
        "image_digest": f"sha256:{generate_sha256()}",
        "resource_type": random.choice(["Pod", "Container", "Node", "CloudFunction"]),
        "resource_id": f"{cluster}/{namespace}/{random.getrandbits(32):08x}",
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
