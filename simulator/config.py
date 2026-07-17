import os


class Config:
    DEBUG = os.environ.get('DEBUG', 'True').lower() == 'true'
    HOST = os.environ.get('HOST', '0.0.0.0')
    PORT = int(os.environ.get('PORT', 8080))

    CLIENT_ID = os.environ.get('CLIENT_ID', 'mock-client-id')
    CLIENT_SECRET = os.environ.get('CLIENT_SECRET', 'mock-client-secret')

    # Token lifetime in seconds (CrowdStrike tokens live ~30 mins)
    TOKEN_LIFETIME = int(os.environ.get('TOKEN_LIFETIME', 1799))

    # Seed data sizes
    NUM_DEVICES = int(os.environ.get('NUM_DEVICES', 20))
    NUM_ALERTS = int(os.environ.get('NUM_ALERTS', 50))
    NUM_IOCS = int(os.environ.get('NUM_IOCS', 30))
    NUM_VULNERABILITIES = int(os.environ.get('NUM_VULNERABILITIES', 60))
    NUM_HOST_GROUPS = int(os.environ.get('NUM_HOST_GROUPS', 5))
    NUM_CNAPP_ALERTS = int(os.environ.get('NUM_CNAPP_ALERTS', 25))

    # Deterministic seed for bootstrap. Every instance that boots with the
    # same SEED produces identical device_ids, host-group ids, vulns, etc.
    # CRITICAL for Cloud Run: multiple concurrent instances would otherwise
    # generate divergent IDs and the fetch-assets flow would fail to enrich
    # AIDs collected by another instance (empty POST /devices/entities/
    # devices/v2 response → seal batch skipped → assets dataset stays empty).
    SEED = int(os.environ.get('SEED', 42))
