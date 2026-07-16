"""
In-memory seed data store. Populated once at startup.
"""
import random

from config import Config
from generators.crowdstrike import (
    generate_device,
    generate_alert,
    generate_ioc,
    generate_vulnerability,
    generate_host_group,
    generate_process,
    generate_cnapp_alert,
    _device_id,
    CVE_SEVERITIES,
)

devices: list[dict] = []
alerts: list[dict] = []
iocs: list[dict] = []
vulnerabilities: list[dict] = []
host_groups: list[dict] = []
processes: list[dict] = []
cnapp_alerts: list[dict] = []

# Index maps for fast lookup
device_by_id: dict[str, dict] = {}
alert_by_id: dict[str, dict] = {}
ioc_by_id: dict[str, dict] = {}


def bootstrap():
    global devices, alerts, iocs, vulnerabilities, host_groups, processes, cnapp_alerts
    global device_by_id, alert_by_id, ioc_by_id

    # 1) Host groups first — vulnerability host_info.groups refers to them
    host_groups = [generate_host_group() for _ in range(Config.NUM_HOST_GROUPS)]
    group_ids = [g['id'] for g in host_groups]

    # 2) Devices, then assign them to a subset of host groups
    devices = [generate_device() for _ in range(Config.NUM_DEVICES)]
    for device in devices:
        device['groups'] = [gid for gid in group_ids if random.random() > 0.5]
    device_by_id = {d['device_id']: d for d in devices}

    alerts = [generate_alert(random.choice(devices)) for _ in range(Config.NUM_ALERTS)]
    alert_by_id = {a['detection_id']: a for a in alerts}

    iocs = [generate_ioc() for _ in range(Config.NUM_IOCS)]
    ioc_by_id = {i['id']: i for i in iocs}

    # Round-robin severities so every CRITICAL/HIGH/... bucket the
    # fetch-assets flow fans out to actually returns data.
    vulnerabilities = [
        generate_vulnerability(
            random.choice(devices),
            host_groups=host_groups,
            severity=CVE_SEVERITIES[i % len(CVE_SEVERITIES)],
        )
        for i in range(Config.NUM_VULNERABILITIES)
    ]

    processes = [
        generate_process(random.choice(devices))
        for _ in range(Config.NUM_DEVICES * 2)
    ]

    cnapp_alerts = [generate_cnapp_alert() for _ in range(Config.NUM_CNAPP_ALERTS)]
