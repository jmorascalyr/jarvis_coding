#!/usr/bin/env python3
"""
Tor User Scenario Sender
=========================

Generates and sends the Tor User scenario events to SentinelOne AI-SIEM.

Key design choice:
  - Palo Alto firewall logs are **raw CSV strings** and must be sent to the
    ``/raw`` HEC endpoint.  They are stored as plain strings in the event
    list (not wrapped in ``{"raw": ...}``).
  - Okta authentication logs are structured JSON and go to ``/event``.

The ``send_one`` function in ``hec_sender.py`` already routes correctly
based on whether the product is in ``JSON_PRODUCTS``.  We just need to
make sure we pass the right payload type.
"""

import os
import sys
import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any

# ---------------------------------------------------------------------------
# Ensure imports work
# ---------------------------------------------------------------------------
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_BACKEND = os.path.dirname(_THIS_DIR)
_GEN_SHARED = os.path.join(_BACKEND, "event_generators", "shared")
for p in (_GEN_SHARED, _THIS_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

from hec_sender import send_one, SOURCETYPE_MAP
from tor_user_scenario import generate_tor_user_scenario

_debug_env = os.getenv("S1_HEC_DEBUG")
_DEBUG_SEND = bool(_debug_env) and _debug_env.lower() not in ("0", "false", "no", "off")

# ---------------------------------------------------------------------------
# Attribute fields builder
# ---------------------------------------------------------------------------

def _attr_fields(source: str, trace_id: str, phase: str,
                 scenario_name: str) -> Dict[str, Any]:
    """Build the HEC attribute fields envelope."""
    fields: Dict[str, Any] = {
        "scenario.trace_id": trace_id,
        "scenario.phase": phase,
        "scenario.name": scenario_name,
    }
    return fields


# ---------------------------------------------------------------------------
# Event sender — handles raw vs. structured payloads
# ---------------------------------------------------------------------------

def _send_event(entry: Dict[str, Any], trace_id: str,
                scenario_name: str) -> bool:
    source = entry.get("source", "unknown")
    phase = entry.get("phase", "unknown")
    event = entry.get("event")

    # Palo Alto events are raw CSV strings — pass directly to send_one
    # so they go to /raw (paloalto_firewall is NOT in JSON_PRODUCTS).
    if source == "paloalto_firewall":
        if isinstance(event, dict) and "raw" in event:
            # Legacy wrapper format from other scenarios
            payload = event["raw"]
        elif isinstance(event, str):
            payload = event
        else:
            # Fallback: serialise whatever we got
            payload = json.dumps(event, separators=(",", ":"))
    else:
        # JSON products (okta_authentication, etc.)
        if isinstance(event, str):
            payload = event            # Already a JSON string
        elif isinstance(event, dict):
            payload = event             # send_one will wrap in /event envelope
        else:
            payload = json.dumps(event, separators=(",", ":"))

    fields = _attr_fields(source, trace_id, phase, scenario_name)
    result = send_one(payload, source, fields)
    if _DEBUG_SEND and source == "okta_authentication":
        if isinstance(event, dict):
            event_type = event.get("eventType", "")
            event_uuid = event.get("uuid", "")
        else:
            event_type = ""
            event_uuid = ""
        sourcetype = SOURCETYPE_MAP.get(source, source)
        print(
            f"[DEBUG][OKTA SEND] sourcetype={sourcetype} eventType={event_type} uuid={event_uuid} response={result}",
            flush=True,
        )
    return True


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def send_tor_user(worker_count: int = 4) -> None:
    """Generate and send the Tor User scenario."""
    scenario = generate_tor_user_scenario()
    events = scenario.get("events", [])
    scenario_name = scenario.get("scenario_name", "Tor User")
    trace_id = os.getenv("S1_TRACE_ID") or str(uuid.uuid4())

    print("\n" + "=" * 70)
    print(f"  SENDING TOR USER SCENARIO | Events: {len(events)} | Workers: {worker_count}")
    print(f"  Trace ID: {trace_id}")
    print("=" * 70)

    start = time.time()
    sent = 0

    def worker(i: int, e: Dict[str, Any]):
        ok = _send_event(e, trace_id, scenario_name)
        return (i, ok, e.get("source"), e.get("phase"))

    with ThreadPoolExecutor(max_workers=worker_count) as ex:
        futures = {ex.submit(worker, i, e): i for i, e in enumerate(events, 1)}
        for fut in as_completed(futures):
            i, ok, source, phase = fut.result()
            sent += 1 if ok else 0
            if sent % 5 == 0 or sent == len(events):
                elapsed = time.time() - start
                eps = sent / elapsed if elapsed > 0 else 0
                print(f"  [{sent:3d}/{len(events)}] EPS: {eps:6.1f} | {source} | {phase}")

    elapsed = time.time() - start
    print("\n" + "=" * 70)
    print(f"  COMPLETE | Delivered: {sent}/{len(events)} "
          f"| {elapsed:.1f}s | Trace: {trace_id}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    send_tor_user()
