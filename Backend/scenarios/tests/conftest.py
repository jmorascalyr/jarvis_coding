"""Shared fixtures for Lua scenario + sender tests.

Sets up sys.path so we can import:
  * ``lua_scenario_runner`` and ``scenario_hec_sender`` from ``Backend/scenarios/``
  * ``hec_sender`` (and per-category generator modules) from
    ``Backend/event_generators/shared/`` & sibling category dirs
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_TESTS_DIR = Path(__file__).resolve().parent
_SCENARIOS_DIR = _TESTS_DIR.parent
_BACKEND_DIR = _SCENARIOS_DIR.parent
_GENERATOR_ROOT = _BACKEND_DIR / "event_generators"

for path in (
    _SCENARIOS_DIR,
    _GENERATOR_ROOT / "shared",
    _GENERATOR_ROOT / "cloud_infrastructure",
    _GENERATOR_ROOT / "network_security",
    _GENERATOR_ROOT / "endpoint_security",
    _GENERATOR_ROOT / "identity_access",
    _GENERATOR_ROOT / "email_security",
    _GENERATOR_ROOT / "web_security",
    _GENERATOR_ROOT / "infrastructure",
):
    p = str(path)
    if path.exists() and p not in sys.path:
        sys.path.insert(0, p)

# hec_sender raises on import if S1_HEC_TOKEN is missing.
os.environ.setdefault("S1_HEC_TOKEN", "test-token")
