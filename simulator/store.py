"""
In-memory seed data store. Populated once at startup.
"""
from config import Config
from generators.crowdstrike import (
    generate_device,
    generate_alert,
    generate_ioc,
    generate_vulnerability,
    generate_host_group,
    generate_process,
    _device_id,
)

devices: list[dict] = []
alerts: list[dict] = []
iocs: list[dict] = []
vulnerabilities: list[dict] = []
host_groups: list[dict] = []
processes: list[dict] = []

# Index maps for fast lookup
device_by_id: dict[str, dict] = {}
alert_by_id: dict[str, dict] = {}
ioc_by_id: dict[str, dict] = {}


def bootstrap():
    global devices, alerts, iocs, vulnerabilities, host_groups, processes
    global device_by_id, alert_by_id, ioc_by_id

    devices = [generate_device() for _ in range(Config.NUM_DEVICES)]
    device_by_id = {d['device_id']: d for d in devices}

    # Assign devices to host groups
    host_groups = [generate_host_group() for _ in range(Config.NUM_HOST_GROUPS)]
    group_ids = [g['id'] for g in host_groups]
    for device in devices:
        assigned = [gid for gid in group_ids if __import__('random').random() > 0.5]
        device['groups'] = assigned

    alerts = [generate_alert(__import__('random').choice(devices)) for _ in range(Config.NUM_ALERTS)]
    alert_by_id = {a['detection_id']: a for a in alerts}

    iocs = [generate_ioc() for _ in range(Config.NUM_IOCS)]
    ioc_by_id = {i['id']: i for i in iocs}

    vulnerabilities = [
        generate_vulnerability(__import__('random').choice(devices))
        for _ in range(Config.NUM_VULNERABILITIES)
    ]

    processes = [
        generate_process(__import__('random').choice(devices))
        for _ in range(Config.NUM_DEVICES * 2)
    ]
