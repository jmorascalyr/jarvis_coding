#!/usr/bin/env python3
"""
Microsoft Defender EDR Scenario
================================

Streams realistic Microsoft Defender XDR Advanced Hunting telemetry to
SentinelOne (HEC) and surfaces three EDR-focused Graph-shaped alerts to the
SentinelOne Unified Alert Management (UAM) portal.

Story (single Defender XDR incident, ``incidentId = "28293"``)
---------------------------------------------------------------
``alex.morgan@contoso.com`` on ``ws-fin-042.contoso.corp`` is targeted by a
phishing campaign:

  1. ``EmailEvents`` / ``EmailUrlInfo`` — phish lands (MDO).
  2. ``UrlClickEvents`` — user clicks Safe Links.
  3. ``DeviceFileEvents`` — ZIP + LNK drop on disk (MDE).
  4. ``DeviceProcessEvents`` — LNK -> cmd -> ``powershell -enc`` (MDE).
  5. ``DeviceEvents`` — AMSI catches encoded reverse shell, AV quarantines (MDE).
  6. ``DeviceNetworkEvents`` — TCP beacon to 195.201.59.127:4443 (MDE).
  7. ``DeviceEvents`` — ``LsassAccess`` via rundll32 (MDE).
  8. ``DeviceRegistryEvents`` — ``HKCU\\...\\Run`` persistence (MDE).
  9. ``DeviceLogonEvents`` — failed RDP attempt to ``dc01`` (MDE).
 10. ``IdentityLogonEvents`` — RC4-HMAC Kerberos SPN tickets (MDI).
 11. ``EntraIdSignInEvents`` — interactive sign-in from a Tor exit (Entra ID Protection).
 12. ``CloudAppEvents`` — malicious ``HideReceiptsRule`` inbox rule (MDA).

Three EDR alerts are sent to UAM (all share ``incidentId 28293``):

  * ``defender_mde_lnk_powershell`` — Suspicious Bovter backdoor prevented.
  * ``defender_mde_c2_beacon``      — Outbound C2 to 195.201.59.127:4443.
  * ``defender_mde_amsi_av``        — AMSI + AV + LSASS access on the host.
"""
from __future__ import annotations

import argparse
import copy
import gzip
import json
import os
import sys
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

import requests

script_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.dirname(script_dir)
sys.path.insert(0, backend_dir)
sys.path.insert(0, os.path.join(backend_dir, "event_generators"))
sys.path.insert(0, os.path.join(backend_dir, "event_generators", "shared"))
sys.path.insert(0, os.path.join(backend_dir, "event_generators", "identity_access"))
sys.path.insert(0, os.path.join(backend_dir, "event_generators", "email_security"))

# Generator imports (per-table Advanced Hunting functions)
import microsoft_365_defender as mde  # type: ignore
import microsoft_defender_email as mdo  # type: ignore

HEC_AVAILABLE = False
try:
    from hec_sender import send_one  # type: ignore

    HEC_AVAILABLE = True
except (ImportError, RuntimeError):
    pass

# ---------------------------------------------------------------------------
# Scenario constants — kept in sync with microsoft_defender_telemetry_and_alerts.md
# ---------------------------------------------------------------------------

SCENARIO_NAME = "Microsoft Defender EDR Scenario"
INCIDENT_ID = "28293"
TENANT_ID = "b3c1b5fc-828c-45fa-a1e1-10d74f6d6e9c"

VICTIM_PROFILE = {
    "name": "alex.morgan",
    "upn": "alex.morgan@contoso.com",
    "domain": "contoso",
    "domain_fqdn": "contoso.corp",
    "display_name": "Alex Morgan",
    "object_id": "9a8b7c6d-1234-5678-90ab-cdef01234567",
    "sid": "S-1-5-21-1004336348-1177238915-682003330-1284",
    "azure_ad_user_id": "a8f3b1d2-7e4c-49a0-b5d8-2c3e4f5a6b71",
}

DEVICE_PROFILE = {
    "id": "47f8a3c2e9b14d6580f1ce7a9b3d2e5814f7c0a2",
    "name": "ws-fin-042.contoso.corp",
    "local_ip": "10.84.17.42",
    "azure_ad_device_id": "1f2e3d4c-5b6a-7980-1a2b-3c4d5e6f7081",
    "os_platform": "Windows11",
    "os_version": "10.0.22631.3737",
    "os_build": 22631,
    "rbac_group_id": 42,
    "rbac_group_name": "Finance Endpoints",
}

ATTACKER_PROFILE = {
    "tor_ip": "185.220.101.10",
    "c2_ip": "195.201.59.127",
    "c2_port": 4443,
    "lnk_sha256": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
}

# Phases: (delta_seconds, generator_fn, source_product, table_name, extra_overrides)
PHASES: List[tuple] = [
    # (seconds_from_base, generator, source product label, AH table, overrides)
    (-1140.0, mdo.email_events_log, "microsoft_defender_email", "EmailEvents", None),
    (-1140.0, mdo.email_url_info_log, "microsoft_defender_email", "EmailUrlInfo", None),
    (-614.0, mdo.url_click_events_log, "microsoft_defender_email", "UrlClickEvents", None),
    (-609.0, mde.device_file_events_log, "microsoft_365_defender", "DeviceFileEvents", None),
    (-594.0, mde.device_file_events_log, "microsoft_365_defender", "DeviceFileEvents", None),
    (0.0, mde.device_process_events_log, "microsoft_365_defender", "DeviceProcessEvents", None),
    (0.4, mde.device_events_log, "microsoft_365_defender", "DeviceEvents/AMSI", {"ActionType": "AmsiScriptDetection"}),
    (1.2, mde.device_network_events_log, "microsoft_365_defender", "DeviceNetworkEvents", None),
    (2.8, mde.device_events_log, "microsoft_365_defender", "DeviceEvents/AV", {"ActionType": "AntivirusDetection"}),
    (78.3, mde.device_events_log, "microsoft_365_defender", "DeviceEvents/LsassAccess", {"ActionType": "LsassAccess"}),
    (122.0, mde.device_registry_events_log, "microsoft_365_defender", "DeviceRegistryEvents", None),
    (254.0, mde.device_logon_events_log, "microsoft_365_defender", "DeviceLogonEvents", None),
    (342.0, mde.identity_logon_events_log, "microsoft_365_defender", "IdentityLogonEvents", None),
    (638.0, mde.entra_id_signin_events_log, "microsoft_365_defender", "EntraIdSignInEvents", None),
    (687.0, mde.cloud_app_events_log, "microsoft_365_defender", "CloudAppEvents", None),
]

# UAM alert timing — relative to the same ``base_time`` (PROCESS spawn)
ALERT_PHASE_MAPPING: Dict[str, Dict[str, Any]] = {
    "defender_mde_lnk_powershell": {
        "template": "defender_mde_lnk_powershell",
        "offset_seconds": 3.0,  # MDE alert raised ~3s after process spawn
        "target": "device",
    },
    "defender_mde_c2_beacon": {
        "template": "defender_mde_c2_beacon",
        "offset_seconds": 4.5,  # C2 alert ~1.5s after network connection
        "target": "device",
    },
    "defender_mde_amsi_av": {
        "template": "defender_mde_amsi_av",
        "offset_seconds": 79.0,  # AMSI+AV+LsassAccess composite — fires after LsassAccess
        "target": "device",
    },
}

# Threat-intel IOCs (optional --with-ti)
TI_IOCS: List[Dict[str, str]] = [
    {"type": "IPV4", "value": "195.201.59.127", "description": "Bovter C2 server (DE)"},
    {"type": "IPV4", "value": "185.220.101.10", "description": "Tor exit node used for Entra sign-in"},
    {"type": "SHA256", "value": ATTACKER_PROFILE["lnk_sha256"], "description": "Malicious LNK shortcut"},
]


# ---------------------------------------------------------------------------
# Time helpers / event builders
# ---------------------------------------------------------------------------


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_z(dt: datetime) -> str:
    """ISO-8601 with 7-digit fractional second + Z suffix (Defender format)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    base = dt.strftime("%Y-%m-%dT%H:%M:%S")
    frac = f"{dt.microsecond:06d}0"
    return f"{base}.{frac}Z"


def build_events(base_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """Build the full list of telemetry events in chronological order.

    Returns a list of envelopes::

        {"timestamp": "<iso>", "source": "<product>", "table": "<AH table>",
         "phase": "<phase id>", "event": {...}}
    """
    base = base_time or _utc_now()
    events: List[Dict[str, Any]] = []

    for delta_s, fn, source, table, extra in PHASES:
        evt_time = base + timedelta(seconds=delta_s)
        overrides: Dict[str, Any] = {}
        if extra:
            overrides.update(extra)
        event = fn(overrides if overrides else None)
        # Force the timestamp to the scripted phase time so ordering is exact.
        event["Timestamp"] = _iso_z(evt_time)
        events.append(
            {
                "timestamp": evt_time.isoformat(),
                "source": source,
                "table": table,
                "phase": table.lower().replace("/", "_"),
                "event": event,
            }
        )

    events.sort(key=lambda e: e["timestamp"])
    return events


# ---------------------------------------------------------------------------
# UAM alert helpers (mirrors apollo_ransomware_scenario.send_phase_alert)
# ---------------------------------------------------------------------------


def _stamp_dynamic(node: Any, iso_ts: str) -> None:
    """Recursively replace every ``"DYNAMIC"`` string in *node* with *iso_ts*.

    Used to stamp Graph alert lifecycle timestamps (``createdDateTime``,
    ``lastUpdateDateTime``, ``firstActivityDateTime``, ``lastActivityDateTime``,
    per-evidence ``createdDateTime``, and process creation times) so that the
    embedded ``additional_data.graph_alert`` block has timestamps consistent
    with the OCSF ``time``/``metadata.logged_time``.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, str) and value == "DYNAMIC":
                node[key] = iso_ts
            else:
                _stamp_dynamic(value, iso_ts)
    elif isinstance(node, list):
        for item in node:
            _stamp_dynamic(item, iso_ts)


def _apply_asset_data(
    alert: Dict[str, Any],
    *,
    victim: Dict[str, Any],
    device: Dict[str, Any],
    attacker: Dict[str, Any],
    uam_config: Dict[str, Any],
) -> None:
    """Hydrate the alert with live asset/identity data from the scenario profiles.

    Patches three locations so they stay consistent:

    * ``resources[0]`` — device asset block (``uid``, ``name``, ``type``,
      ``version``, ``hostname``, ``owner.email_addr``).
    * ``additional_data.graph_alert.evidence[]`` — per-kind evidence rows are
      rewritten with the scenario's ``DEVICE_PROFILE`` / ``VICTIM_PROFILE`` /
      ``ATTACKER_PROFILE`` values so the embedded Graph alert is internally
      consistent with the EDR telemetry.
    * ``observables[]`` — top-level OCSF observables whose ``name`` matches a
      Graph field are refreshed with the live value, so SDL pivot queries on
      ``azureAdDeviceId`` / ``azureAdUserId`` / ``ipAddress`` / etc. resolve to
      the same identifiers the EDR rows carry.
    """
    # ---- resources[0] enrichment --------------------------------------
    res_uid = uam_config.get("xdr_asset_id_device") or str(uuid.uuid4())
    res_name = uam_config.get("xdr_asset_name_device") or device["name"]
    resource0 = (alert.get("resources") or [{}])[0]
    if not isinstance(resource0, dict):
        resource0 = {}
    resource0["uid"] = res_uid
    resource0["name"] = res_name
    resource0["hostname"] = device["name"]
    resource0["type"] = device.get("os_platform", resource0.get("type", "Windows11"))
    resource0["version"] = device.get("os_version", resource0.get("version"))
    resource0.setdefault("owner", {})
    if isinstance(resource0["owner"], dict):
        resource0["owner"]["email_addr"] = victim["upn"]
        resource0["owner"]["name"] = victim.get("display_name", victim["name"])
    alert["resources"] = [resource0]

    aad_device_id = (
        uam_config.get("xdr_azure_ad_device_id")
        or device.get("azure_ad_device_id")
    )
    aad_user_id = (
        uam_config.get("xdr_azure_ad_user_id")
        or victim.get("azure_ad_user_id")
    )

    # ---- graph_alert.evidence[] hydration -----------------------------
    graph_alert = alert.get("additional_data", {}).get("graph_alert")
    if isinstance(graph_alert, dict):
        for ev in graph_alert.get("evidence", []) or []:
            if not isinstance(ev, dict):
                continue
            kind = ev.get("@odata.type", "")
            if kind.endswith("deviceEvidence"):
                ev["mdeDeviceId"] = device["id"]
                ev["deviceDnsName"] = device["name"]
                if aad_device_id:
                    ev["azureAdDeviceId"] = aad_device_id
                ev["osPlatform"] = device.get("os_platform", ev.get("osPlatform"))
                if device.get("os_version") is not None:
                    ev["version"] = device["os_version"]
                if device.get("os_build") is not None:
                    ev["osBuild"] = device["os_build"]
                ev["ipInterfaces"] = [device["local_ip"]]
                ev["loggedOnUsers"] = [
                    {"accountName": victim["name"], "domainName": victim["domain"]}
                ]
            elif kind.endswith("userEvidence") or kind.endswith("processEvidence"):
                ua = ev.get("userAccount")
                if isinstance(ua, dict):
                    ua["accountName"] = victim["name"]
                    ua["domainName"] = victim["domain"]
                    ua["userPrincipalName"] = victim["upn"]
                    ua["userSid"] = victim["sid"]
                    if aad_user_id:
                        ua["azureAdUserId"] = aad_user_id
                if kind.endswith("processEvidence"):
                    ev["mdeDeviceId"] = device["id"]
            elif kind.endswith("fileEvidence"):
                ev["mdeDeviceId"] = device["id"]
            elif kind.endswith("ipEvidence"):
                ev["ipAddress"] = attacker["c2_ip"]
            elif kind.endswith("registryValueEvidence") or kind.endswith("registryKeyEvidence"):
                ev["mdeDeviceId"] = device["id"]

    # ---- observables[] refresh ----------------------------------------
    obs_lookup = {
        "azureAdDeviceId": aad_device_id,
        "azureAdUserId": aad_user_id,
        "mdeDeviceId": device["id"],
        "ipInterfaces": device["local_ip"],
        "loggedOnUsers": victim["name"],
        "osPlatform": device.get("os_platform"),
        "ipAddress": attacker.get("c2_ip"),
    }
    for obs in alert.get("observables", []) or []:
        if not isinstance(obs, dict):
            continue
        new_val = obs_lookup.get(obs.get("name"))
        if new_val is not None:
            obs["value"] = new_val


def load_alert_template(template_id: str) -> Optional[Dict[str, Any]]:
    """Load an alert template JSON from disk (handles dev + Docker layouts)."""
    candidate_dirs = [
        os.path.join(backend_dir, "api", "app", "alerts", "templates"),
        os.path.join(backend_dir, "app", "alerts", "templates"),
    ]
    for templates_dir in candidate_dirs:
        path = os.path.join(templates_dir, f"{template_id}.json")
        if os.path.exists(path):
            with open(path, "r") as f:
                return json.load(f)
    print(f"   ⚠️  Template not found: {template_id}.json (searched {candidate_dirs})")
    return None


def send_phase_alert(
    phase_name: str,
    base_time: datetime,
    uam_config: Dict[str, Any],
) -> bool:
    """Render a Defender alert template and POST it to S1 UAM ingest."""
    if phase_name not in ALERT_PHASE_MAPPING:
        return False

    mapping = ALERT_PHASE_MAPPING[phase_name]
    template = load_alert_template(mapping["template"])
    if not template:
        return False

    alert = copy.deepcopy(template)

    alert_time = base_time + timedelta(seconds=mapping["offset_seconds"])
    time_ms = int(alert_time.timestamp() * 1000)
    alert_iso = alert_time.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    alert.setdefault("finding_info", {})["uid"] = str(uuid.uuid4())
    alert["time"] = time_ms
    meta = alert.setdefault("metadata", {})
    meta["logged_time"] = time_ms
    meta["modified_time"] = time_ms

    # Hydrate resources[0], evidence[], and observables[] with live asset data
    # from the scenario's DEVICE_PROFILE / VICTIM_PROFILE / ATTACKER_PROFILE so
    # the alert is internally consistent with the EDR telemetry it accompanies.
    _apply_asset_data(
        alert,
        victim=VICTIM_PROFILE,
        device=DEVICE_PROFILE,
        attacker=ATTACKER_PROFILE,
        uam_config=uam_config,
    )

    # Stamp every "DYNAMIC" string under additional_data.graph_alert with the ISO
    # timestamp so the embedded Graph alert lifecycle fields line up with `time`.
    graph_alert = (
        alert.get("additional_data", {}).get("graph_alert")
        if isinstance(alert.get("additional_data"), dict)
        else None
    )
    if isinstance(graph_alert, dict):
        _stamp_dynamic(graph_alert, alert_iso)
        # Faithful provenance: raw_data is the JSON-stringified original Graph
        # alert — captured AFTER both asset hydration and timestamp stamping so
        # the verbatim copy reflects everything the consumer would see.
        alert["raw_data"] = json.dumps(graph_alert, separators=(",", ":"))

    try:
        ingest_url = uam_config["uam_ingest_url"].rstrip("/") + "/v1/alerts"
        scope = uam_config["uam_account_id"]
        if uam_config.get("uam_site_id"):
            scope = f"{scope}:{uam_config['uam_site_id']}"

        headers = {
            "Authorization": f"Bearer {uam_config['uam_service_token']}",
            "S1-Scope": scope,
            "Content-Encoding": "gzip",
            "Content-Type": "application/json",
            # The ``:alwayslog`` suffix is required — it disables S1's UAM
            # sampling and guarantees downstream ingest-pipeline processing.
            # Without it, the endpoint can return 202 and silently drop the
            # alert. The prefix is just a free-form correlation label.
            "S1-Trace-Id": "defender-edr-uam:alwayslog",
        }

        payload = json.dumps(alert).encode("utf-8")
        gzipped = gzip.compress(payload)

        print(f"\n      📤 Alert Details:")
        print(f"         Template: {mapping['template']}")
        print(f"         Title: {alert.get('finding_info', {}).get('title', 'N/A')}")
        print(f"         Device: {DEVICE_PROFILE['name']}")
        print(f"         Time: {alert_time.isoformat()} ({time_ms}ms)")
        print(f"         URL: {ingest_url}")
        print(f"         Scope: {scope}")
        print(f"         Payload: {len(payload)} bytes -> {len(gzipped)} bytes (gzip)")
        if os.getenv("DEFENDER_EDR_DEBUG_ALERTS"):
            print(f"         Full JSON: {json.dumps(alert, indent=2)}")

        resp = requests.post(ingest_url, headers=headers, data=gzipped, timeout=30)
        print(f"         Response: {resp.status_code} {resp.reason}")
        if resp.content:
            print(f"         Body: {resp.text[:200]}")

        return resp.status_code == 202
    except Exception as e:  # pragma: no cover - network errors
        print(f"   ✗ Alert send failed: {e}")
        import traceback

        traceback.print_exc()
        return False


# ---------------------------------------------------------------------------
# HEC sending
# ---------------------------------------------------------------------------


def _attr_fields(product: str, table: str, trace_id: Optional[str]) -> Dict[str, Any]:
    fields: Dict[str, Any] = {
        "dataSource.vendor": "Microsoft",
        "dataSource.name": (
            "Microsoft 365 Defender"
            if product == "microsoft_365_defender"
            else "Microsoft Defender for Office 365"
        ),
        "dataSource.category": "security",
        "defender.ah_table": table,
        "scenario.id": "defender_edr_scenario",
        "scenario.incident_id": INCIDENT_ID,
    }
    if trace_id:
        fields["scenario.trace_id"] = trace_id
    return fields


def send_to_hec(envelope: Dict[str, Any], trace_id: Optional[str]) -> bool:
    product = envelope["source"]
    attr_fields = _attr_fields(product, envelope["table"], trace_id)
    try:
        send_one(envelope["event"], product, attr_fields)
        return True
    except Exception as e:  # pragma: no cover - network errors
        print(f"\n   error sending {envelope['table']}: {e}")
        return False


# ---------------------------------------------------------------------------
# Threat-intel push (optional)
# ---------------------------------------------------------------------------


def send_ti_iocs(ti_config: Dict[str, Any]) -> bool:
    """POST the scenario IOCs to S1 Threat Intelligence (best-effort)."""
    url = ti_config["s1_management_url"].rstrip("/") + "/web/api/v2.1/threat-intelligence/iocs"
    headers = {
        "Authorization": f"ApiToken {ti_config['s1_api_token']}",
        "Content-Type": "application/json",
    }
    params: Dict[str, Any] = {}
    if ti_config.get("site_id"):
        params["siteIds"] = ti_config["site_id"]
    elif ti_config.get("account_id"):
        params["accountIds"] = ti_config["account_id"]

    iocs = []
    for entry in TI_IOCS:
        iocs.append(
            {
                "type": entry["type"],
                "value": entry["value"],
                "method": "EQUALS",
                "source": "defender_edr_scenario",
                "description": entry["description"],
                "name": f"defender-edr-{entry['type'].lower()}-{entry['value'][:12]}",
            }
        )
    body = {"filter": {}, "data": iocs}
    try:
        resp = requests.post(url, headers=headers, params=params, json=body, timeout=30)
        print(f"   TI response: {resp.status_code} {resp.text[:200]}")
        return resp.ok
    except Exception as e:  # pragma: no cover
        print(f"   ✗ TI push failed: {e}")
        return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _summary(events: List[Dict[str, Any]]) -> Dict[str, int]:
    table_counts: Dict[str, int] = {}
    for e in events:
        table_counts[e["table"]] = table_counts.get(e["table"], 0) + 1
    return table_counts


def main() -> int:
    parser = argparse.ArgumentParser(description=SCENARIO_NAME)
    parser.add_argument(
        "--dry-run", action="store_true", help="Build events but do not send to HEC/UAM."
    )
    parser.add_argument(
        "--no-alerts", action="store_true", help="Skip sending UAM alerts."
    )
    parser.add_argument(
        "--with-ti", action="store_true", help="Push IOCs to S1 Threat Intelligence."
    )
    parser.add_argument(
        "--workers", type=int, default=10, help="HEC worker concurrency (default 10)."
    )
    default_output_dir = os.getenv("SCENARIO_OUTPUT_DIR", os.path.join(script_dir, "configs"))
    parser.add_argument(
        "--output",
        default=os.path.join(default_output_dir, "defender_edr_scenario.json"),
        help="Where to write the rendered scenario JSON.",
    )
    args = parser.parse_args()

    base_time = _utc_now()
    events = build_events(base_time)

    print("=" * 80)
    print(SCENARIO_NAME)
    print("=" * 80)
    print(f"Incident ID:    {INCIDENT_ID}")
    print(f"Tenant ID:      {TENANT_ID}")
    print(f"Victim:         {VICTIM_PROFILE['upn']}")
    print(f"Device:         {DEVICE_PROFILE['name']} ({DEVICE_PROFILE['id']})")
    print(f"C2:             {ATTACKER_PROFILE['c2_ip']}:{ATTACKER_PROFILE['c2_port']}")
    print(f"Base time:      {base_time.isoformat()}")
    print(f"Total events:   {len(events)} across {len(_summary(events))} tables")
    for tbl, n in _summary(events).items():
        print(f"   - {tbl}: {n}")
    print("=" * 80)

    scenario = {
        "scenario_id": f"defender-edr-{base_time.strftime('%Y%m%d-%H%M%S')}",
        "scenario_name": SCENARIO_NAME,
        "incident_id": INCIDENT_ID,
        "tenant_id": TENANT_ID,
        "generated_at": _utc_now().isoformat(),
        "base_time": base_time.isoformat(),
        "victim": VICTIM_PROFILE,
        "device": DEVICE_PROFILE,
        "attacker": ATTACKER_PROFILE,
        "alerts": list(ALERT_PHASE_MAPPING.keys()),
        "events": events,
    }

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(scenario, f, indent=2, default=str)
    print(f"\n💾 Scenario JSON written to: {args.output}")

    if args.dry_run:
        print("\n--dry-run set, exiting before HEC/UAM send.")
        return 0

    # ------------------------------------------------------------------
    # HEC send
    # ------------------------------------------------------------------
    hec_token = os.getenv("S1_HEC_TOKEN")
    if HEC_AVAILABLE and hec_token:
        trace_id = os.getenv(
            "S1_TRACE_ID", f"defender-edr-{base_time.strftime('%Y%m%d-%H%M%S')}"
        )
        print("\n" + "=" * 80)
        print(f"📤 SENDING {len(events)} EVENTS TO HEC (workers={args.workers})")
        print("=" * 80)

        counts = {"ok": 0, "err": 0}
        lock = threading.Lock()

        def _worker(envelope: Dict[str, Any]) -> None:
            ok = send_to_hec(envelope, trace_id)
            with lock:
                if ok:
                    counts["ok"] += 1
                    print(".", end="", flush=True)
                else:
                    counts["err"] += 1
                    print("E", end="", flush=True)

        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            list(ex.map(_worker, events))
        print(f"\n\n✅ HEC complete — ok={counts['ok']} err={counts['err']}\n")
    else:
        print("\n⚠️  S1_HEC_TOKEN not set or hec_sender unavailable — skipping HEC send.")

    # ------------------------------------------------------------------
    # UAM alerts
    # ------------------------------------------------------------------
    if not args.no_alerts:
        uam_config = {
            "uam_ingest_url": os.getenv("S1_UAM_INGEST_URL")
            or os.getenv("UAM_INGEST_URL", ""),
            "uam_account_id": os.getenv("S1_UAM_ACCOUNT_ID")
            or os.getenv("UAM_ACCOUNT_ID", ""),
            "uam_site_id": os.getenv("S1_UAM_SITE_ID")
            or os.getenv("UAM_SITE_ID", ""),
            "uam_service_token": os.getenv("S1_UAM_SERVICE_TOKEN")
            or os.getenv("UAM_SERVICE_TOKEN", ""),
            "xdr_asset_id_device": os.getenv("S1_XDR_ASSET_ID_DEVICE", ""),
            "xdr_asset_name_device": os.getenv(
                "S1_XDR_ASSET_NAME_DEVICE", DEVICE_PROFILE["name"]
            ),
            "xdr_azure_ad_device_id": os.getenv(
                "S1_XDR_AZURE_AD_DEVICE_ID", DEVICE_PROFILE.get("azure_ad_device_id", "")
            ),
            "xdr_azure_ad_user_id": os.getenv(
                "S1_XDR_AZURE_AD_USER_ID", VICTIM_PROFILE.get("azure_ad_user_id", "")
            ),
        }
        if uam_config["uam_ingest_url"] and uam_config["uam_service_token"]:
            print("\n" + "=" * 80)
            print(f"🔔 SENDING {len(ALERT_PHASE_MAPPING)} UAM ALERTS")
            print("=" * 80)
            for phase_name in ALERT_PHASE_MAPPING:
                print(f"\n   📤 {phase_name}...")
                ok = send_phase_alert(phase_name, base_time, uam_config)
                print(f"      {'✓' if ok else '✗'}")
        else:
            print(
                "\n⚠️  UAM environment not configured "
                "(set S1_UAM_INGEST_URL / S1_UAM_ACCOUNT_ID / S1_UAM_SERVICE_TOKEN). "
                "Skipping UAM alerts."
            )

    # ------------------------------------------------------------------
    # Threat intel (optional)
    # ------------------------------------------------------------------
    if args.with_ti:
        ti_config = {
            "s1_management_url": os.getenv("S1_MANAGEMENT_URL", ""),
            "s1_api_token": os.getenv("S1_API_TOKEN", ""),
            "account_id": os.getenv("S1_UAM_ACCOUNT_ID", ""),
            "site_id": os.getenv("S1_UAM_SITE_ID", ""),
        }
        if ti_config["s1_management_url"] and ti_config["s1_api_token"]:
            print("\n" + "=" * 80)
            print(f"🛡  PUSHING {len(TI_IOCS)} IOCS TO S1 THREAT INTELLIGENCE")
            print("=" * 80)
            send_ti_iocs(ti_config)
        else:
            print(
                "\n⚠️  TI not configured (set S1_MANAGEMENT_URL / S1_API_TOKEN). "
                "Skipping TI push."
            )

    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
