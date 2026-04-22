#!/usr/bin/env python3
"""
Tor User Scenario
=================

Generates Palo Alto Network Firewall TRAFFIC logs showing a user browsing
via Tor, followed by Okta authentication logs for the same user.

The Palo Alto logs are raw CSV (sent to /raw), NOT structured JSON.
The Okta logs are structured JSON (sent to /event).

Detection intent:
  - app_name = "tor" in Palo Alto firewall logs triggers a detection
  - Pivot from the PA user to Okta shows the same identity authenticating
"""

import os
import sys
import json
import random
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any

# ---------------------------------------------------------------------------
# Ensure event_generators are importable
# ---------------------------------------------------------------------------
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_BACKEND = os.path.dirname(_THIS_DIR)
_GEN_SHARED = os.path.join(_BACKEND, "event_generators", "shared")
_GEN_IDENTITY = os.path.join(_BACKEND, "event_generators", "identity_access")
for p in (_GEN_SHARED, _GEN_IDENTITY, _THIS_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

# okta_authentication_log no longer needed — events built from scratch below

# ---------------------------------------------------------------------------
# Scenario profile
# ---------------------------------------------------------------------------
SCENARIO_NAME = "Tor User"
SCENARIO_DESCRIPTION = (
    "A corporate user is observed browsing the internet via Tor in Palo Alto "
    "firewall logs.  The same user later authenticates through Okta.  "
    "Designed to trigger Tor-usage detections and enable cross-source pivoting."
)

# The user who is using Tor
TOR_USER = {
    "username": "reginald.barclay",
    "domain_user": "corp\\reginald.barclay",
    "email": "reginald.barclay@corp.local",
    "src_ip": "192.168.207.79",
}

# Tor-related destination IPs (known Tor exit-node style IPs)
TOR_EXIT_NODES = [
    "201.141.179.28",
    "185.220.101.42",
    "104.244.76.13",
    "199.249.230.163",
    "185.56.80.65",
    "162.247.74.27",
    "178.17.174.14",
    "95.211.230.211",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_scenario_time(base_time: datetime, day: int, hour: int,
                      minute: int, second: int = 0) -> str:
    event_time = base_time + timedelta(days=day, hours=hour,
                                       minutes=minute, seconds=second)
    return event_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def create_event(timestamp: str, source: str, phase: str,
                 event_data) -> Dict[str, Any]:
    """Wrap event data with scenario metadata.

    For raw products (paloalto_firewall) event_data is a plain string.
    For JSON products (okta_authentication) event_data is a dict or JSON str.
    """
    return {
        "timestamp": timestamp,
        "source": source,
        "phase": phase,
        "event": event_data,
    }


# ---------------------------------------------------------------------------
# Palo Alto TRAFFIC log builder — raw CSV, NOT JSON
# ---------------------------------------------------------------------------

def _pa_serial():
    return str(random.randint(100000000000000, 999999999999999))


def _pa_session_id():
    return str(random.randint(10000, 999999))


def generate_tor_traffic_log(receive_time: datetime,
                              start_time: datetime,
                              username: str = TOR_USER["domain_user"],
                              src_ip: str = TOR_USER["src_ip"],
                              dst_ip: str | None = None) -> str:
    """Build a single Palo Alto TRAFFIC CSV line with app=tor.

    This mirrors the format produced by
    ``event_generators/network_security/paloalto_firewall.py``
    but hard-codes the fields relevant to a Tor-usage detection.
    """
    if dst_ip is None:
        dst_ip = random.choice(TOR_EXIT_NODES)

    src_port = random.randint(1024, 65535)
    dst_port = random.choice([80, 443, 9001, 9030])
    bytes_total = random.randint(500000, 10000000)
    bytes_sent = int(bytes_total * random.uniform(0.3, 0.7))
    bytes_recv = bytes_total - bytes_sent
    packets = random.randint(100, 5000)
    elapsed = random.randint(30, 600)
    country = random.choice(["FR", "DE", "NL", "RO", "SE", "US", "CH"])

    fields = [
        "",                                                 # future_use_1
        receive_time.strftime("%Y/%m/%d %H:%M:%S"),         # receive_time
        _pa_serial(),                                       # serial_number
        "TRAFFIC",                                          # type
        "end",                                              # subtype
        "",                                                 # future_use_2
        start_time.strftime("%Y/%m/%d %H:%M:%S"),           # time_generated
        src_ip,                                             # src
        dst_ip,                                             # dst
        src_ip,                                             # natsrc
        dst_ip,                                             # natdst
        "allow-web-browsing",                               # rule
        username,                                           # srcuser
        "",                                                 # dstuser
        "tor",                                              # app  ← KEY FIELD
        "vsys1",                                            # vsys
        "trust",                                            # from
        "untrust",                                          # to
        f"ethernet1/{random.randint(1, 4)}",                # inbound_if
        f"ethernet1/{random.randint(5, 8)}",                # outbound_if
        "FORWARD",                                          # logset
        "",                                                 # future_use_3
        _pa_session_id(),                                   # sessionid
        "1",                                                # repeatcnt
        str(src_port),                                      # sport
        str(dst_port),                                      # dport
        str(src_port),                                      # natsport
        str(dst_port),                                      # natdport
        "0x0",                                              # flags
        "tcp",                                              # proto
        "allow",                                            # action
        str(bytes_total),                                   # bytes
        str(bytes_sent),                                    # bytes_sent
        str(bytes_recv),                                    # bytes_received
        str(packets),                                       # packets
        start_time.strftime("%Y/%m/%d %H:%M:%S"),           # start
        str(elapsed),                                       # elapsed
        "",                                                 # category
        "",                                                 # future_use_4
        str(random.randint(1, 1000000)),                    # seqno
        "0x0",                                              # actionflags
        country,                                            # srcloc
        country,                                            # dstloc
        "",                                                 # future_use_5
        str(int(packets * 0.6)),                            # pkts_sent
        str(int(packets * 0.4)),                            # pkts_received
        "aged-out",                                         # session_end_reason
    ]

    # Pad to 115 columns to match the marketplace PA parser expectation
    expected_fields = 115
    if len(fields) < expected_fields:
        fields.extend([""] * (expected_fields - len(fields)))

    return ",".join(fields)


# ---------------------------------------------------------------------------
# Okta authentication log with overrides for our scenario user
# ---------------------------------------------------------------------------

_OKTA_EVENT_TEMPLATES = [
    {
        "eventType": "user.authentication.sso",
        "legacyEventType": "core.user.auth.login_success",
        "displayMessage": "User single sign on to app",
        "outcome": {"reason": "VERIFICATION_SUCCESS", "result": "SUCCESS"},
        "severity": "INFO",
        "credentialType": "PASSWORD",
        "authenticationProvider": "OKTA_AUTHENTICATION_PROVIDER",
        "credentialProvider": "OKTA_CREDENTIAL_PROVIDER",
        "authenticationStep": 1,
    },
    {
        "eventType": "user.authentication.auth_via_mfa",
        "legacyEventType": "core.user.auth.mfa.verify_fail",
        "displayMessage": "User denied MFA verification",
        "outcome": {"reason": "OKTA_VERIFY_DENIED_ACCESS", "result": "FAILURE"},
        "severity": "DEBUG",
        "credentialType": "OTP",
        "authenticationProvider": "OKTA_AUTHENTICATION_PROVIDER",
        "credentialProvider": "OKTA_CREDENTIAL_PROVIDER",
        "authenticationStep": 1,
    },
    {
        "eventType": "user.session.start",
        "legacyEventType": "core.user.session.start",
        "displayMessage": "User login to Okta",
        "outcome": {"reason": "VERIFICATION_SUCCESS", "result": "SUCCESS"},
        "severity": "INFO",
        "credentialType": "PASSWORD",
        "authenticationProvider": "OKTA_AUTHENTICATION_PROVIDER",
        "credentialProvider": "OKTA_CREDENTIAL_PROVIDER",
        "authenticationStep": 0,
    },
]

_OKTA_GEO_CONTEXTS = [
    {"city": "Amsterdam", "country": "Netherlands", "state": "North Holland",
     "postalCode": "1012", "lat": 52.3702, "lon": 4.8952},
    {"city": "San Francisco", "country": "United States", "state": "California",
     "postalCode": "94105", "lat": 37.7749, "lon": -122.4194},
    {"city": "Tokyo", "country": "Japan", "state": "Tokyo",
     "postalCode": "100-0001", "lat": 35.6762, "lon": 139.6503},
    {"city": "London", "country": "United Kingdom", "state": "England",
     "postalCode": "EC1A", "lat": 51.5074, "lon": -0.1278},
    {"city": "Berlin", "country": "Germany", "state": "Berlin",
     "postalCode": "10115", "lat": 52.5200, "lon": 13.4050},
]

_OKTA_USER_AGENTS = [
    {"browser": "CHROME", "os": "Windows",
     "rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"},
    {"browser": "MOBILE_SAFARI", "os": "iOS",
     "rawUserAgent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15"},
    {"browser": "FIREFOX", "os": "Mac OS X",
     "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0"},
]

_OKTA_ISPS = [
    {"asNumber": 20473, "asOrg": "The Constant Company, LLC", "isp": "AS-CHOOPA"},
    {"asNumber": 15169, "asOrg": "Google LLC", "isp": "Google LLC"},
    {"asNumber": 136800, "asOrg": "Choopa, LLC", "isp": "Vultr Holdings LLC"},
    {"asNumber": 14618, "asOrg": "Amazon.com, Inc.", "isp": "Amazon Technologies Inc."},
]


def generate_okta_tor_user_log(timestamp_str: str) -> dict:
    """Return an Okta systemLog event dict for the Tor user.

    The output structure matches the native Okta System Log JSON format
    including ``_okta_event_type``, ``request.ipChain``, ``transaction``,
    ``debugContext``, ``securityContext``, and ``target`` fields.
    """
    tpl = random.choice(_OKTA_EVENT_TEMPLATES)
    geo = random.choice(_OKTA_GEO_CONTEXTS)
    ua = random.choice(_OKTA_USER_AGENTS)
    isp_info = random.choice(_OKTA_ISPS)
    request_id = str(uuid.uuid4())
    event_uuid = str(uuid.uuid4())
    session_id = uuid.uuid4().hex[:14]
    txn_id = uuid.uuid4().hex[:32]
    dt_hash = uuid.uuid4().hex + uuid.uuid4().hex[:24]
    user_okta_id = "00u" + uuid.uuid4().hex[:17]
    chain_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    geo_context = {
        "city": geo["city"],
        "country": geo["country"],
        "geolocation": {"lat": geo["lat"], "lon": geo["lon"]},
        "postalCode": geo["postalCode"],
        "state": geo["state"],
    }

    event = {
        "_okta_event_type": "systemLog",
        "actor": {
            "alternateId": TOR_USER["email"],
            "displayName": "Reginald Barclay",
            "id": user_okta_id,
            "type": "User",
        },
        "authenticationContext": {
            "authenticationProvider": tpl.get("authenticationProvider", "OKTA_AUTHENTICATION_PROVIDER"),
            "authenticationStep": tpl.get("authenticationStep", 0),
            "credentialProvider": tpl.get("credentialProvider", "OKTA_CREDENTIAL_PROVIDER"),
            "credentialType": tpl.get("credentialType", "PASSWORD"),
            "externalSessionId": session_id,
            "rootSessionId": session_id[:10],
        },
        "client": {
            "device": random.choice(["Computer", "Mobile", "Unknown"]),
            "geographicalContext": geo_context,
            "ipAddress": TOR_USER["src_ip"],
            "userAgent": {
                "browser": ua["browser"],
                "os": ua["os"],
                "rawUserAgent": ua["rawUserAgent"],
            },
            "zone": "null",
        },
        "debugContext": {
            "debugData": {
                "concurrencyPercentage": str(random.choice([10, 15, 25, 50])),
                "dtHash": dt_hash,
                "networkConnection": "ANYWHERE",
                "rateLimitPercentage": str(random.choice([5, 10, 15, 20])),
                "requestId": request_id,
                "requestUri": f"/api/v1/{tpl['eventType'].replace('.', '/')}",
                "url": f"/api/v1/{tpl['eventType'].replace('.', '/')}?rememberDevice=true",
            }
        },
        "displayMessage": tpl["displayMessage"],
        "eventType": tpl["eventType"],
        "legacyEventType": tpl["legacyEventType"],
        "outcome": tpl["outcome"],
        "published": timestamp_str,
        "request": {
            "ipChain": [
                {
                    "geographicalContext": geo_context,
                    "ip": chain_ip,
                    "version": "V4",
                }
            ]
        },
        "securityContext": {
            "asNumber": isp_info["asNumber"],
            "asOrg": isp_info["asOrg"],
            "isProxy": random.choice([True, False]),
            "isp": isp_info["isp"],
        },
        "severity": tpl["severity"],
        "target": [
            {
                "alternateId": TOR_USER["email"],
                "displayName": "Reginald Barclay",
                "id": user_okta_id,
                "type": "User",
            }
        ],
        "timestamp": timestamp_str,
        "transaction": {
            "detail": {},
            "id": txn_id,
            "type": "WEB",
        },
        "uuid": event_uuid,
        "version": "0",
    }

    return event


# ---------------------------------------------------------------------------
# Phase generators
# ---------------------------------------------------------------------------

def generate_tor_browsing_phase(base_time: datetime) -> List[Dict]:
    """Phase 1: Palo Alto TRAFFIC logs showing Tor usage over ~30 minutes."""
    events: List[Dict] = []

    for i in range(15):
        minute_offset = i * 2 + random.randint(0, 1)
        recv_time = base_time + timedelta(minutes=minute_offset + 5)
        start_time = base_time + timedelta(minutes=minute_offset)
        ts = get_scenario_time(base_time, 0, 0, minute_offset)

        csv_line = generate_tor_traffic_log(recv_time, start_time)
        events.append(create_event(ts, "paloalto_firewall", "tor_browsing", csv_line))

    return events


def generate_okta_auth_phase(base_time: datetime) -> List[Dict]:
    """Phase 2: Okta authentication logs for the same user ~45 min later."""
    events: List[Dict] = []

    # A few Okta auth events spread across 10 minutes
    for i in range(5):
        minute_offset = 45 + i * 2
        ts = get_scenario_time(base_time, 0, 0, minute_offset)
        okta_event = generate_okta_tor_user_log(ts)
        events.append(create_event(ts, "okta_authentication", "okta_login", okta_event))

    return events


# ---------------------------------------------------------------------------
# Main scenario generator
# ---------------------------------------------------------------------------

def generate_tor_user_scenario() -> Dict[str, Any]:
    """Build the complete Tor User scenario."""
    base_time = datetime.now(timezone.utc).replace(second=0, microsecond=0)

    all_events: List[Dict] = []
    all_events.extend(generate_tor_browsing_phase(base_time))
    all_events.extend(generate_okta_auth_phase(base_time))

    return {
        "scenario_name": SCENARIO_NAME,
        "description": SCENARIO_DESCRIPTION,
        "events": all_events,
        "base_time": base_time.isoformat(),
    }


if __name__ == "__main__":
    scenario = generate_tor_user_scenario()
    print(f"Scenario: {scenario['scenario_name']}")
    print(f"Events:   {len(scenario['events'])}")
    for e in scenario["events"]:
        src = e["source"]
        phase = e["phase"]
        preview = str(e["event"])[:120]
        print(f"  [{src:25s}] {phase:15s} | {preview}...")
