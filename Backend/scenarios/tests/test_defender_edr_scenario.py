"""Tests for the Microsoft Defender EDR scenario + generators."""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

import pytest

# Set up imports the same way the scenario does.
BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, BACKEND_DIR)
sys.path.insert(0, os.path.join(BACKEND_DIR, "scenarios"))
sys.path.insert(0, os.path.join(BACKEND_DIR, "event_generators"))
sys.path.insert(0, os.path.join(BACKEND_DIR, "event_generators", "shared"))
sys.path.insert(0, os.path.join(BACKEND_DIR, "event_generators", "identity_access"))
sys.path.insert(0, os.path.join(BACKEND_DIR, "event_generators", "email_security"))

import microsoft_365_defender as mde  # noqa: E402
import microsoft_defender_email as mdo  # noqa: E402
import defender_edr_scenario as scen  # noqa: E402


# ---------------------------------------------------------------------------
# Generator schema sanity checks
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fn, expected_table, required_keys",
    [
        (
            mde.device_file_events_log,
            "DeviceFileEvents",
            {"DeviceId", "DeviceName", "ActionType", "FileName", "SHA1", "SHA256", "ReportId"},
        ),
        (
            mde.device_process_events_log,
            "DeviceProcessEvents",
            {"FileName", "FolderPath", "ProcessCommandLine", "InitiatingProcessFileName", "ProcessUniqueId"},
        ),
        (
            mde.device_network_events_log,
            "DeviceNetworkEvents",
            {"RemoteIP", "RemotePort", "LocalIP", "LocalPort", "Protocol", "InitiatingProcessFileName"},
        ),
        (
            mde.device_registry_events_log,
            "DeviceRegistryEvents",
            {"RegistryKey", "RegistryValueName", "RegistryValueData", "InitiatingProcessFileName"},
        ),
        (
            mde.device_logon_events_log,
            "DeviceLogonEvents",
            {"ActionType", "LogonType", "RemoteIP", "RemoteDeviceName", "AccountName"},
        ),
        (
            mde.identity_logon_events_log,
            "IdentityLogonEvents",
            {"Application", "Protocol", "DestinationDeviceName", "AccountUpn"},
        ),
        (
            mde.entra_id_signin_events_log,
            "EntraIdSignInEvents",
            {"AccountUpn", "IPAddress", "RiskLevelAggregated", "ConditionalAccessStatus"},
        ),
        (
            mde.cloud_app_events_log,
            "CloudAppEvents",
            {"ActionType", "Application", "ObjectName", "IPAddress", "RawEventData"},
        ),
        (
            mdo.email_events_log,
            "EmailEvents",
            {"NetworkMessageId", "SenderFromAddress", "RecipientEmailAddress", "ThreatTypes"},
        ),
        (
            mdo.email_url_info_log,
            "EmailUrlInfo",
            {"NetworkMessageId", "Url", "UrlDomain"},
        ),
        (
            mdo.url_click_events_log,
            "UrlClickEvents",
            {"Url", "ActionType", "AccountUpn", "IsClickedThrough", "UrlChain"},
        ),
    ],
)
def test_generator_returns_required_keys(fn, expected_table, required_keys):
    event = fn()
    assert event["_table"] == expected_table
    missing = required_keys - set(event.keys())
    assert not missing, f"{expected_table} missing keys: {missing}"


def test_device_events_action_type_override():
    for at in ["AmsiScriptDetection", "AntivirusDetection", "LsassAccess"]:
        evt = mde.device_events_log({"ActionType": at})
        assert evt["ActionType"] == at
        assert evt["_table"] == "DeviceEvents"


def test_back_compat_shim_rotates_tables():
    seen = {mde.microsoft_365_defender_log()["_table"] for _ in range(20)}
    # The shim should produce at least 3 different tables in 20 calls.
    assert len(seen) >= 3


# ---------------------------------------------------------------------------
# Alert template validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "template_id",
    [
        "defender_mde_lnk_powershell",
        "defender_mde_c2_beacon",
        "defender_mde_amsi_av",
    ],
)
def test_alert_templates_valid(template_id):
    template = scen.load_alert_template(template_id)
    assert template is not None, f"Template {template_id} not found"
    # S1 envelope fields — must match the proven-working schema exactly
    # (apollo's proofpoint_email_alert.json / wel_*.json). Any drift here
    # causes UAM to 202 the request but silently drop the alert downstream.
    assert template["class_uid"] == 99602001
    assert template["s1_classification_id"] == 28
    assert template["state_id"] == 1, "must be state_id (not status_id)"
    assert template["time"] == "DYNAMIC"
    assert template["metadata"]["version"] == "1.1.0"
    md_ext = template["metadata"]["extension"]
    assert isinstance(md_ext, dict), "metadata.extension must be singular object"
    assert md_ext["uid"] == "998"
    assert template["metadata"]["logged_time"] == "DYNAMIC"
    assert template["metadata"]["modified_time"] == "DYNAMIC"
    assert template["resources"][0]["uid"] == "DYNAMIC_RESOURCE_UID"


# ---------------------------------------------------------------------------
# Scenario timeline checks
# ---------------------------------------------------------------------------


def test_build_events_produces_all_tables():
    base = datetime(2026, 5, 29, 13, 52, 1, tzinfo=timezone.utc)
    events = scen.build_events(base)

    # Expect one event per phase entry (15 total per current PHASES table)
    assert len(events) == len(scen.PHASES)

    # All tables represented
    tables = {e["table"] for e in events}
    expected_required = {
        "EmailEvents",
        "EmailUrlInfo",
        "UrlClickEvents",
        "DeviceFileEvents",
        "DeviceProcessEvents",
        "DeviceNetworkEvents",
        "DeviceRegistryEvents",
        "DeviceLogonEvents",
        "IdentityLogonEvents",
        "EntraIdSignInEvents",
        "CloudAppEvents",
    }
    assert expected_required.issubset(tables), f"missing tables: {expected_required - tables}"
    # And at least one DeviceEvents/* variant
    assert any(t.startswith("DeviceEvents") for t in tables)


def test_build_events_is_chronological():
    base = datetime(2026, 5, 29, 13, 52, 1, tzinfo=timezone.utc)
    events = scen.build_events(base)
    times = [datetime.fromisoformat(e["timestamp"]) for e in events]
    assert times == sorted(times)


def test_ps_command_is_valid_base64_and_decodes():
    """The encoded PowerShell payload baked into the generator must be a
    legitimate UTF-16LE base64 string that PowerShell's ``-enc`` flag can
    actually decode — otherwise demos error out with
    ``Invalid Base64 string``.
    """
    import base64

    cmd = mde.DEFAULT_PROFILE["malware"]["ps_command"]
    assert cmd.startswith("powershell.exe -nop -w hidden -ep bypass -enc ")
    b64 = cmd.split(" -enc ", 1)[1]
    # Whitespace-clean, multiple of 4, no stray chars.
    assert b64 == b64.strip()
    assert len(b64) % 4 == 0, "base64 length must be a multiple of 4"
    decoded = base64.b64decode(b64, validate=True).decode("utf-16-le")
    # Sanity: must contain the C2 endpoint and the reverse-shell shape.
    assert "195.201.59.127" in decoded
    assert "4443" in decoded
    assert "TCPClient" in decoded


def test_parser_emits_src_process_displayname_and_storyline_id():
    """The S1 PowerQuery hunts for ``src.process.displayName == 'Windows
    PowerShell'`` and projects ``src.process.storyline.id``. Both rely on
    generator fields (``InitiatingProcessVersionInfoFileDescription`` /
    ``InitiatingProcessUniqueId``) that historically were missing from the
    DeviceEvents AMSI branch.
    """
    parser_path = os.path.join(
        BACKEND_DIR,
        "parsers",
        "community",
        "microsoft_365_defender-latest",
        "microsoft_365_defender.json",
    )
    with open(parser_path) as fp:
        parser = json.load(fp)
    copies = [
        t["copy"]
        for t in parser["mappings"]["mappings"][0]["transformations"]
        if "copy" in t
    ]
    pairs = {(c["from"], c["to"]) for c in copies}
    assert (
        "InitiatingProcessVersionInfoFileDescription",
        "src.process.displayName",
    ) in pairs
    assert (
        "InitiatingProcessUniqueId",
        "src.process.storyline.id",
    ) in pairs

    # And the generator must actually emit those source fields on AMSI rows.
    amsi = mde.device_events_log({"ActionType": "AmsiScriptDetection"})
    assert amsi["InitiatingProcessVersionInfoFileDescription"] == "Windows PowerShell"
    assert amsi["InitiatingProcessUniqueId"].startswith("PRSTKEY_")


def test_parser_routes_process_image_to_tgt_process_not_tgt_file():
    """In Defender Advanced Hunting, the top-level ``FileName/FolderPath/
    SHA1/SHA256/MD5/FileSize`` columns describe the *target file* in
    ``DeviceFileEvents`` but describe the *target process image* in
    ``DeviceProcessEvents`` / ``DeviceEvents``. The parser must gate the
    ``tgt.file.*`` mapping on ``DeviceFileEvents`` and provide a parallel
    ``tgt.process.image.*`` mapping for the process tables.
    """
    parser_path = os.path.join(
        BACKEND_DIR,
        "parsers",
        "community",
        "microsoft_365_defender-latest",
        "microsoft_365_defender.json",
    )
    with open(parser_path) as fp:
        parser = json.load(fp)
    transforms = parser["mappings"]["mappings"][0]["transformations"]
    copies = [t["copy"] for t in transforms if "copy" in t]

    def rules_for(src):
        return [c for c in copies if c["from"] == src]

    for col in ("FileName", "FolderPath", "FileSize", "SHA1", "SHA256", "MD5"):
        rs = rules_for(col)
        # Every routing of these columns must be table-gated — none may be
        # an unconditional copy, otherwise process binaries leak into
        # tgt.file.* and target files leak into tgt.process.image.*.
        for r in rs:
            assert "predicate" in r, (
                f"{col} mapping to {r['to']} is unconditional; "
                "must gate on _table"
            )
        tos = {r["to"] for r in rs}
        # Both target families must be represented.
        assert any(t.startswith("tgt.file.") for t in tos), (
            f"{col} missing tgt.file.* mapping"
        )
        assert any(t.startswith("tgt.process.") for t in tos), (
            f"{col} missing tgt.process.* mapping"
        )


def test_build_events_contains_c2_indicator():
    events = scen.build_events()
    nets = [e["event"] for e in events if e["table"] == "DeviceNetworkEvents"]
    assert nets, "DeviceNetworkEvents missing"
    assert nets[0]["RemoteIP"] == scen.ATTACKER_PROFILE["c2_ip"]
    assert nets[0]["RemotePort"] == scen.ATTACKER_PROFILE["c2_port"]


def test_apply_asset_data_hydrates_minimal_envelope():
    """Templates are intentionally minimal (no observables/evidence) to match
    the proven UAM-accepted schema. The asset-data helper must still hydrate
    ``resources[0]`` and must be a no-op for any absent rich sections.
    """
    import copy as _copy

    template = scen.load_alert_template("defender_mde_c2_beacon")
    alert = _copy.deepcopy(template)

    uam = {
        "xdr_asset_id_device": "11111111-2222-3333-4444-555555555555",
        "xdr_asset_name_device": scen.DEVICE_PROFILE["name"],
        "xdr_azure_ad_device_id": "aaaa1111-bbbb-2222-cccc-333333333333",
        "xdr_azure_ad_user_id": "uuuu1111-vvvv-2222-wwww-333333333333",
    }
    # Must not raise even when observables/evidences/graph_alert are absent.
    scen._apply_asset_data(
        alert,
        victim=scen.VICTIM_PROFILE,
        device=scen.DEVICE_PROFILE,
        attacker=scen.ATTACKER_PROFILE,
        uam_config=uam,
    )

    r0 = alert["resources"][0]
    assert r0["uid"] == uam["xdr_asset_id_device"]
    assert r0["name"] == scen.DEVICE_PROFILE["name"]
    assert r0["hostname"] == scen.DEVICE_PROFILE["name"]
    assert r0["type"] == scen.DEVICE_PROFILE["os_platform"]
    assert r0["version"] == scen.DEVICE_PROFILE["os_version"]
    assert r0["owner"]["email_addr"] == scen.VICTIM_PROFILE["upn"]

    # No observables / evidences / additional_data should be added to the
    # template by the asset-data helper. The minimal envelope must stay
    # minimal so the S1 UAM normalizer accepts it.
    assert "observables" not in alert
    assert "evidences" not in alert
    assert "additional_data" not in alert


def test_alert_phase_mapping_covers_three_edr_alerts():
    assert set(scen.ALERT_PHASE_MAPPING.keys()) == {
        "defender_mde_lnk_powershell",
        "defender_mde_c2_beacon",
        "defender_mde_amsi_av",
    }
