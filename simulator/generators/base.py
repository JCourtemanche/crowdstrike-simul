"""
Base generators — common helpers for all simulators.

Imports the shared Business Corp personas from xsiam-shared-personas so
every simulator uses the same users, IPs, and threat indicators.

Add integration-specific helpers below the shared imports section.
"""
import uuid
import random
import hashlib
from datetime import datetime, timedelta
from faker import Faker

# -- Shared personas (do not change these imports) ---------------------------
from xsiam_shared import (
    USERS,
    INTERNAL_IPS,
    MALICIOUS_IPS,
    MALICIOUS_DOMAINS,
    MALICIOUS_URLS,
    MALICIOUS_FILES,
    DOMAIN,
    COMPANY_NAME,
)

fake = Faker()


# ---------------------------------------------------------------------------
# Generic helpers — keep or remove as needed
# ---------------------------------------------------------------------------

def generate_guid():
    return str(uuid.uuid4())


def generate_iso8601_date(start_time=None, end_time=None):
    if end_time is None:
        end_time = datetime.utcnow()
    if start_time is None:
        start_time = end_time - timedelta(hours=1)
    dt = fake.date_time_between(start_date=start_time, end_date=end_time)
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')


def generate_sha256():
    return hashlib.sha256(fake.binary(length=32)).hexdigest()


def generate_md5():
    return hashlib.md5(fake.binary(length=16)).hexdigest()


def random_internal_ip():
    """Pick a Business Corp internal IP (192.168.1.x)."""
    return random.choice(INTERNAL_IPS)


def random_malicious_ip():
    """Pick one of the shared malicious C2 IPs."""
    return random.choice(MALICIOUS_IPS)


def random_user():
    """Pick a random Business Corp persona dict."""
    return random.choice(USERS)


def random_malicious_url():
    """Pick one of the shared malicious URLs."""
    return random.choice(MALICIOUS_URLS)


# ---------------------------------------------------------------------------
# TODO: add integration-specific helpers here
# ---------------------------------------------------------------------------
# Example:
#
# def my_custom_id():
#     return str(random.randint(100000000, 999999999))
