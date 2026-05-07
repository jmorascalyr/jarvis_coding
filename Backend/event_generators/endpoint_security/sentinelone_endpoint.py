#!/usr/bin/env python3
"""
SentinelOne Endpoint (Deep Visibility) event generator — V2
============================================================
Rewritten to match the **real** SentinelOne EDR export schema field-for-field.
Validated against production Deep Visibility JSON exports from agent v25.4.1.24.

Supports event types observed in real telemetry:
  Process Creation, DNS Resolved, DNS Unresolved, IP Connect,
  File Creation, File Modification, File Deletion, File Rename,
  Malware Detection, Suspicious Activity, Registry Modification,
  PowerShell Execution, Credential Access, Scheduled Task *,
  Duplicate Process, and any custom event.type via overrides.
"""
from __future__ import annotations
import json
import random
import hashlib
import uuid
import string
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional

# ---------------------------------------------------------------------------
# ATTR_FIELDS — used by scenario_hec_sender to tag events during HEC ingest
# ---------------------------------------------------------------------------
ATTR_FIELDS = {
    "dataSource.name": "SentinelOne",
    "dataSource.category": "security",
    "dataSource.vendor": "SentinelOne",
}

# ---------------------------------------------------------------------------
# Event‑type → (meta.event.name, event.category) mapping
# ---------------------------------------------------------------------------
EVENT_TYPE_MAP = {
    "Process Creation":    ("PROCESSCREATION",  "process"),
    "DNS Resolved":        ("DNS",              "dns"),
    "DNS Unresolved":      ("DNS",              "dns"),
    "IP Connect":          ("TCPV4",            "ip"),
    "File Creation":       ("FILECREATION",     "file"),
    "File Modification":   ("FILEMODIFICATION", "file"),
    "File Deletion":       ("FILEDELETION",     "file"),
    "File Rename":         ("FILERENAME",       "file"),
    "Malware Detection":   ("FILESCAN",         "threats"),
    "Suspicious Activity": ("PROCESSCREATION",  "process"),
    "Registry Modification": ("REGKEYCREATE",   "registry"),
    "PowerShell Execution":  ("SCRIPTS",        "process"),
    "Credential Access":     ("PROCESSCREATION","process"),
    "Scheduled Task Update": ("SCHEDTASKUPDATE","scheduledtask"),
    "Scheduled Task Start":  ("SCHEDTASKSTART", "scheduledtask"),
    "Scheduled Task Trigger":("SCHEDTASKTRIGGER","scheduledtask"),
    "Scheduled Task Delete": ("SCHEDTASKDELETE","scheduledtask"),
    "Duplicate Process":     ("DUPLICATEPROCESS","process"),
    "Network Connection":    ("TCPV4",          "ip"),
}

# ---------------------------------------------------------------------------
# Defaults for randomised fields
# ---------------------------------------------------------------------------
ENDPOINT_TYPES = ["server", "workstation", "laptop"]

LINUX_PROCESSES = [
    {"name": "systemd-executor", "displayName": "systemd-executor",
     "path": "/usr/lib/systemd/systemd-executor",
     "cmdline": "/usr/lib/systemd/systemd-executor --deserialize 60 --log-level info --log-target journal-or-kmsg",
     "sha1": "f621c455a0187f9942afb2c1334a1e636b30cee5",
     "sha256": "a76ebfd2120b7bd6590210c5b4b4de9051c2842daa37a323ef2bfc330ed7f39e",
     "size": 137792},
    {"name": "cron", "displayName": "cron",
     "path": "/usr/sbin/cron",
     "cmdline": "/usr/sbin/CRON -f -P",
     "sha1": "1acc15c347efc7c8e45e3147ef6f9e44de59df0e",
     "sha256": "6bd8593640af2413bce259fa0affc18dbf149892756ebe805bf316624f8b590f",
     "size": 60080},
    {"name": "dash", "displayName": "dash",
     "path": "/usr/bin/dash",
     "cmdline": "/bin/sh -c command -v debian-sa1 > /dev/null && debian-sa1 1 1",
     "sha1": "9697fc549039a25a859a827d00e5c97e9729e983",
     "sha256": "86d31f6fb799e91fa21bad341484564510ca287703a16e9e46c53338776f4f42",
     "size": 129784},
    {"name": "sadc", "displayName": "sadc",
     "path": "/usr/lib/sysstat/sadc",
     "cmdline": "/usr/lib/sysstat/sadc -F -L -S DISK 1 1 /var/log/sysstat",
     "sha1": "67254f4af657c4dea7201198c761f7e51910ddc1",
     "sha256": "d0dcaadc057b3791f3d3aa19e2f9b1243ad37714f4336a8be0b69b197bdf0397",
     "size": 83200},
    {"name": "amazon-ssm-agent", "displayName": "amazon-ssm-agent",
     "path": "/snap/amazon-ssm-agent/13009/amazon-ssm-agent",
     "cmdline": "/snap/amazon-ssm-agent/13009/amazon-ssm-agent",
     "sha1": "f4cbd6da4624875a72445e2b903aa867e7b0e8e8",
     "sha256": "0536cfa8f8bbc057f5d656aceac595391dd9f134f8dfd341e188c1d9714d1a45",
     "size": 15851456},
    {"name": "chronyd", "displayName": "chronyd",
     "path": "/usr/sbin/chronyd",
     "cmdline": "/usr/sbin/chronyd -F 1",
     "sha1": "ffa62bec079d1178ef9d9165d77ae79cd4e3539d",
     "sha256": "7a834e478d8a904c39a348606a5d0ac58fd1ccbca24f333a8170c786af8ca508",
     "size": 306232},
]

WINDOWS_PROCESSES = [
    {"name": "explorer.exe", "displayName": "Windows Explorer",
     "path": "C:\\Windows\\explorer.exe",
     "cmdline": "C:\\Windows\\Explorer.exe",
     "sha1": "", "sha256": "", "size": 5765120},
    {"name": "powershell.exe", "displayName": "Windows PowerShell",
     "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     "cmdline": "powershell.exe -ExecutionPolicy Bypass",
     "sha1": "", "sha256": "", "size": 491520},
    {"name": "cmd.exe", "displayName": "Windows Command Processor",
     "path": "C:\\Windows\\System32\\cmd.exe",
     "cmdline": "cmd.exe /c dir",
     "sha1": "", "sha256": "", "size": 323584},
    {"name": "svchost.exe", "displayName": "Host Process for Windows Services",
     "path": "C:\\Windows\\System32\\svchost.exe",
     "cmdline": "svchost.exe -k NetworkService",
     "sha1": "", "sha256": "", "size": 84992},
]

LINUX_PARENTS = [
    {"name": "systemd", "displayName": "systemd",
     "path": "/usr/lib/systemd/systemd",
     "cmdline": "/usr/lib/systemd/systemd --system --deserialize=72",
     "sha1": "950601befa0b55cead41e7a1ecb0de8833f4c2c8",
     "sha256": "40caa6565d996de5eae5c82e5fc8ef440f0d74e8f701210b2364d9b7b69329a3",
     "size": 100816, "pid": 1},
    {"name": "cron", "displayName": "cron",
     "path": "/usr/sbin/cron",
     "cmdline": "/usr/sbin/cron -f -P",
     "sha1": "1acc15c347efc7c8e45e3147ef6f9e44de59df0e",
     "sha256": "6bd8593640af2413bce259fa0affc18dbf149892756ebe805bf316624f8b590f",
     "size": 60080, "pid": 517},
]

WINDOWS_PARENTS = [
    {"name": "explorer.exe", "displayName": "Windows Explorer",
     "path": "C:\\Windows\\explorer.exe", "cmdline": "C:\\Windows\\Explorer.exe",
     "sha1": "", "sha256": "", "size": 5765120, "pid": 4580},
    {"name": "services.exe", "displayName": "Services and Controller app",
     "path": "C:\\Windows\\System32\\services.exe", "cmdline": "C:\\Windows\\System32\\services.exe",
     "sha1": "", "sha256": "", "size": 721920, "pid": 780},
]


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _generate_ulid_trace() -> str:
    """Generate a ULID-like trace ID matching real S1 format (26 uppercase alphanumeric)."""
    chars = string.ascii_uppercase + string.digits
    return "01" + "".join(random.choices(chars, k=24))


def _s1_uuid() -> str:
    """UUID matching the hex-with-dashes format used by S1 for storyline/process/packet IDs."""
    return str(uuid.uuid4())


def _format_s1_time(dt: datetime) -> str:
    """Format datetime as epoch nanoseconds for SentinelOne event.time."""
    return str(int(dt.timestamp() * 1_000_000_000))


def _format_s1_timestamp(dt: datetime) -> str:
    """Format datetime as S1 timestamp field: 'HH:MM:SS.mmm'"""
    return dt.strftime("%H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


def _generate_sha1() -> str:
    return hashlib.sha1(str(random.random()).encode()).hexdigest()


def _generate_sha256() -> str:
    return hashlib.sha256(str(random.random()).encode()).hexdigest()


def _generate_numeric_id() -> str:
    """Large numeric string matching real account.id / site.id format."""
    return str(random.randint(1000000000000000000, 9999999999999999999))


def _generate_ip() -> str:
    if random.random() < 0.7:
        return f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    return f"{random.randint(1,223)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------

def sentinelone_endpoint_log(custom_fields: Dict = None) -> Dict:
    """Generate a SentinelOne Deep Visibility event matching real export schema.

    The output dict contains every field observed in production S1 EDR JSON
    exports (agent v25.4.x, Linux & Windows).  Pass ``custom_fields`` to
    override any value — the override is applied **last** so it always wins.
    """
    cf = custom_fields or {}

    # Resolve event type early so we can derive meta.event.name / category
    event_type = cf.get("event.type", random.choice(list(EVENT_TYPE_MAP.keys())))
    meta_name, category = EVENT_TYPE_MAP.get(event_type, ("PROCESSCREATION", "process"))

    # Resolve OS from custom fields or random
    os_name = cf.get("os.name", random.choice(["Linux", "Windows"]))
    is_linux = os_name == "Linux"

    # Pick process profiles appropriate for OS
    proc = random.choice(LINUX_PROCESSES if is_linux else WINDOWS_PROCESSES)
    parent = random.choice(LINUX_PARENTS if is_linux else WINDOWS_PARENTS)

    # Timestamps
    event_time = datetime.now(timezone.utc) - timedelta(minutes=random.randint(0, 1440))
    start_time = event_time - timedelta(seconds=random.randint(1, 86400))
    parent_start = event_time - timedelta(days=random.randint(1, 30))

    # Stable IDs per event
    trace_id = _generate_ulid_trace()
    storyline_id = _s1_uuid()
    parent_storyline_id = _s1_uuid()
    src_uid = _s1_uuid()
    parent_uid = _s1_uuid()
    packet_id = _s1_uuid()
    group_id = storyline_id
    process_unique_key = src_uid
    image_uid = _s1_uuid()
    parent_image_uid = _s1_uuid()
    event_seq = random.randint(0, 99)

    event = {
        # --- Envelope / trace ---
        "timestamp": _format_s1_timestamp(event_time),
        "task.runScript.stdData": "",
        "trace.id": trace_id,

        # --- Account / site ---
        "account.id": _generate_numeric_id(),
        "account.name": "FinanceCorp",
        "site.id": _generate_numeric_id(),
        "site.name": "Main Site",

        # --- Agent / endpoint ---
        "agent.uuid": _s1_uuid(),
        "agent.version": "25.4.1.24",
        "endpoint.name": f"{'srv' if is_linux else 'WS'}-{random.randint(100,999)}",
        "endpoint.os": os_name.lower(),
        "endpoint.type": random.choice(["server", "workstation"]) if is_linux else "workstation",

        # --- Data source ---
        "dataSource.category": "security",
        "dataSource.name": "SentinelOne",
        "dataSource.vendor": "SentinelOne",

        # --- Event core ---
        "event.category": category,
        "event.id": f"{trace_id}_{event_seq}",
        "event.time": _format_s1_time(event_time),
        "event.type": event_type,
        "meta.event.name": meta_name,

        # --- Management ---
        "mgmt.id": str(random.randint(10000, 99999)),
        "mgmt.osRevision": "Ubuntu 24.04.4 LTS 6.17.0-1007-aws" if is_linux else "Windows 10 Enterprise 22H2",
        "mgmt.url": "usea1-purple.sentinelone.net",
        "os.name": os_name,

        # --- Grouping / tracking ---
        "group.id": group_id,
        "i.scheme": "edr",
        "i.version": "preprocess-lib-1.0",
        "packet.id": packet_id,
        "process.unique.key": process_unique_key,
        "session": "",
        "severity": 3,
        "threadId": "default",
        "threadName": "",

        # --- Source process ---
        "src.process.name": proc["name"],
        "src.process.displayName": proc["displayName"],
        "src.process.cmdline": proc["cmdline"],
        "src.process.pid": random.randint(1000, 999999),
        "src.process.uid": src_uid,
        "src.process.image.path": proc["path"],
        "src.process.image.sha1": proc["sha1"] or _generate_sha1(),
        "src.process.image.sha256": proc["sha256"] or _generate_sha256(),
        "src.process.image.size": proc["size"],
        "src.process.image.type": "FT_UNKNOWN",
        "src.process.image.uid": image_uid,
        "src.process.image.binaryIsExecutable": True if proc["sha1"] else "",
        "src.process.startTime": _format_s1_time(start_time),
        "src.process.storyline.id": storyline_id,
        "src.process.signedStatus": "unsigned",
        "src.process.integrityLevel": "INTEGRITY_LEVEL_UNKNOWN",
        "src.process.isNative64Bit": False,
        "src.process.isRedirectCmdProcessor": False,
        "src.process.isStorylineRoot": False,
        "src.process.subsystem": "SUBSYSTEM_UNKNOWN",
        "src.process.sessionId": 0,
        "src.process.eUserUid": 0,
        "src.process.rUserUid": 0,

        # --- Source process counters ---
        "src.process.childProcCount": 0,
        "src.process.crossProcessCount": 0,
        "src.process.crossProcessDupRemoteProcessHandleCount": 0,
        "src.process.crossProcessDupThreadHandleCount": 0,
        "src.process.crossProcessOpenProcessCount": 0,
        "src.process.crossProcessOutOfStorylineCount": 0,
        "src.process.crossProcessThreadCreateCount": 0,
        "src.process.dnsCount": 0,
        "src.process.moduleCount": 0,
        "src.process.netConnCount": 0,
        "src.process.netConnInCount": 0,
        "src.process.netConnOutCount": 0,
        "src.process.registryChangeCount": 0,
        "src.process.tgtFileCreationCount": 0,
        "src.process.tgtFileDeletionCount": 0,
        "src.process.tgtFileModificationCount": 0,

        # --- Source process indicator counters ---
        "src.process.indicatorBootConfigurationUpdateCount": 0,
        "src.process.indicatorEvasionCount": 0,
        "src.process.indicatorExploitationCount": 0,
        "src.process.indicatorGeneralCount": 0,
        "src.process.indicatorInfostealerCount": 0,
        "src.process.indicatorInjectionCount": 0,
        "src.process.indicatorPersistenceCount": 0,
        "src.process.indicatorPostExploitationCount": 0,
        "src.process.indicatorRansomwareCount": 0,
        "src.process.indicatorReconnaissanceCount": 0,

        # --- Parent process ---
        "src.process.parent.name": parent["name"],
        "src.process.parent.displayName": parent["displayName"],
        "src.process.parent.cmdline": parent["cmdline"],
        "src.process.parent.pid": parent["pid"],
        "src.process.parent.image.path": parent["path"],
        "src.process.parent.image.sha1": parent["sha1"] or _generate_sha1(),
        "src.process.parent.image.sha256": parent["sha256"] or _generate_sha256(),
        "src.process.parent.image.size": parent["size"],
        "src.process.parent.image.type": "FT_UNKNOWN",
        "src.process.parent.image.uid": parent_image_uid,
        "src.process.parent.startTime": _format_s1_time(parent_start),
        "src.process.parent.storyline.id": parent_storyline_id,
        "src.process.parent.signedStatus": "unsigned",
        "src.process.parent.integrityLevel": "INTEGRITY_LEVEL_UNKNOWN",
        "src.process.parent.isNative64Bit": False,
        "src.process.parent.isRedirectCmdProcessor": False,
        "src.process.parent.isStorylineRoot": False,
        "src.process.parent.sessionId": 0,
        "src.process.parent.eUserUid": 0,
        "src.process.parent.rUserUid": 0,
    }

    # Apply custom_fields last — any caller override wins
    if cf:
        event.update(cf)

    return event


# ---------------------------------------------------------------------------
# Convenience wrappers for common event types
# ---------------------------------------------------------------------------

def generate_endpoint_name(endpoint_type: str = "server", os_info: Dict = None) -> str:
    """Generate realistic endpoint names (kept for backward compat)."""
    os_info = os_info or {"os": "Linux"}
    prefix = {"server": "srv", "workstation": "ws", "laptop": "lt"}.get(endpoint_type, "ep")
    suffix = random.randint(100, 999)
    if os_info.get("os") == "Linux":
        return f"{prefix}-{suffix}"
    return f"{prefix.upper()}-{suffix}"


def generate_sha256() -> str:
    return _generate_sha256()


def generate_ip_address() -> str:
    return _generate_ip()


def format_timestamp(dt: datetime) -> str:
    """Return S1 human-readable time string (replaces old epoch-ms helper)."""
    return _format_s1_time(dt)


if __name__ == "__main__":
    import json as _json
    print("Sample SentinelOne Endpoint Events (V2 — real schema):")
    print("=" * 60)
    for i in range(3):
        evt = sentinelone_endpoint_log()
        print(f"\nEvent {i+1} ({evt['event.type']}):")
        print(_json.dumps(evt, indent=2))
