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
    NUM_VULNERABILITIES = int(os.environ.get('NUM_VULNERABILITIES', 40))
    NUM_HOST_GROUPS = int(os.environ.get('NUM_HOST_GROUPS', 5))
