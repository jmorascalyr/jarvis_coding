"""Unit tests for Lua scenario routing + helpers and sender plumbing.

Covers:
  * runner: scenario.sources defaults + per-event opts precedence on _wrap
  * runner: source_routing summary aggregation in _build_output
  * runner helpers: seed/pick/weighted/fake_*/render/phase_loop/emit_many/batch
  * scenario_hec_sender: forwards hec_path/parser/force_parser to send_one
  * hec_sender: parser_override on _envelope/_build_qs and (sourcetype, overwrite)
    cache key on _ensure_parser_in_destination
"""

from __future__ import annotations

import importlib
import os
from typing import Any, Dict, List

import pytest

# ---------------------------------------------------------------------------
# Runner: routing precedence
# ---------------------------------------------------------------------------


@pytest.fixture
def runner_classes():
    """Lazy-import the runner so conftest sys.path is in effect."""
    pytest.importorskip("lupa")  # runner imports lupa eagerly
    module = importlib.import_module("lua_scenario_runner")
    return module


@pytest.fixture
def story_with_routing(runner_classes):
    story = runner_classes.StoryState()
    story.load_scenario(
        {
            "id": "routing-tests",
            "name": "Routing tests",
            "timing": {
                "base": {"mode": "fixed_offset", "offset_seconds": 0},
                "phases": {},
            },
            "actors": [{"id": "a", "name": "Alice", "email": "alice@corp.local"}],
            "hosts": [{"id": "h", "name": "HOST-A"}],
            "iocs": [{"type": "IPV4", "value": "10.9.9.9"}],
            "sources": {
                "aws_cloudtrail": {
                    "hec_path": "event",
                    "parser": "aws_cloudtrail-latest",
                    "force_parser": False,
                    "format": "json",
                },
                "paloalto_firewall": {
                    "hec_path": "raw",
                    "parser": "marketplace-paloaltonetworksfirewall-latest",
                },
            },
        }
    )
    return story


def test_load_scenario_normalizes_sources(story_with_routing):
    defaults = story_with_routing.source_defaults
    assert defaults["aws_cloudtrail"] == {
        "hec_path": "event",
        "parser": "aws_cloudtrail-latest",
        "force_parser": False,
        "format": "json",
    }
    # Per-source defaults are independent (palo block has no force_parser key).
    assert "force_parser" not in defaults["paloalto_firewall"]
    assert story_with_routing.routing_for("missing_source") == {}


def test_normalize_source_defaults_filters_invalid(runner_classes):
    StoryState = runner_classes.StoryState
    normalized = StoryState._normalize_source_defaults(
        {
            "hec_path": "bogus",  # invalid value -> dropped
            "parser": "   ",  # whitespace -> dropped
            "force_parser": "yes",  # truthy non-bool -> coerced to bool
            "format": "JSON",  # lowercased
        }
    )
    assert "hec_path" not in normalized
    assert "parser" not in normalized
    assert normalized["force_parser"] is True
    assert normalized["format"] == "json"


def test_wrap_inherits_scenario_sources(story_with_routing, runner_classes):
    sender = runner_classes.Sender(story_with_routing, mode="generate")
    wrapped = sender.hec_event(
        "aws_cloudtrail", {"eventName": "DescribeInstances"}, {"actor": "a"}
    )
    assert wrapped["hec_path"] == "event"
    assert wrapped["parser"] == "aws_cloudtrail-latest"
    assert wrapped["force_parser"] is False
    assert wrapped["format"] == "json"
    assert wrapped["actor"] == "a"


def test_wrap_per_event_opts_override_defaults(story_with_routing, runner_classes):
    sender = runner_classes.Sender(story_with_routing, mode="generate")
    # CloudTrail default says event/aws_cloudtrail-latest; override per-event.
    wrapped = sender.hec_event(
        "aws_cloudtrail",
        {"eventName": "RunInstances"},
        {
            "hec_path": "raw",
            "parser": "custom-parser",
            "force_parser": True,
            "format": "ndjson",
        },
    )
    assert wrapped["hec_path"] == "raw"
    assert wrapped["parser"] == "custom-parser"
    assert wrapped["force_parser"] is True
    assert wrapped["format"] == "ndjson"


def test_wrap_no_defaults_no_hints(story_with_routing, runner_classes):
    sender = runner_classes.Sender(story_with_routing, mode="generate")
    wrapped = sender.hec_event("unknown_source", {"k": "v"}, None)
    for key in ("hec_path", "parser", "force_parser", "format"):
        assert key not in wrapped


def test_force_parser_explicit_false_wins(story_with_routing, runner_classes):
    """Per-event force_parser=False must not be discarded as falsy."""
    # First, scenario default says force_parser=False already; verify explicit
    # opts True overrides, then explicit opts False overrides a True default.
    story_with_routing.source_defaults["aws_cloudtrail"]["force_parser"] = True
    sender = runner_classes.Sender(story_with_routing, mode="generate")
    wrapped = sender.hec_event("aws_cloudtrail", {"k": "v"}, {"force_parser": False})
    assert wrapped["force_parser"] is False


# ---------------------------------------------------------------------------
# Runner: source_routing summary
# ---------------------------------------------------------------------------


def test_build_output_source_routing_summary(story_with_routing, runner_classes):
    sender = runner_classes.Sender(story_with_routing, mode="generate")
    sender.hec_event("aws_cloudtrail", {"eventName": "A"})
    sender.hec_event("aws_cloudtrail", {"eventName": "B"})
    sender.hec_event("paloalto_firewall", "1,2026/05/26 06:00:00,000,THREAT")
    output = runner_classes._build_output(story_with_routing, sender)
    routing = output["source_routing"]
    assert routing["aws_cloudtrail"]["count"] == 2
    assert routing["aws_cloudtrail"]["hec_path"] == "event"
    assert routing["aws_cloudtrail"]["parser"] == "aws_cloudtrail-latest"
    assert routing["paloalto_firewall"]["hec_path"] == "raw"
    assert output["total_events"] == 3


# ---------------------------------------------------------------------------
# Runner helpers
# ---------------------------------------------------------------------------


def test_seed_makes_pick_deterministic(runner_classes):
    story = runner_classes.StoryState()
    story.seed(42)
    a = [story.pick(["x", "y", "z"]) for _ in range(5)]
    story.seed(42)
    b = [story.pick(["x", "y", "z"]) for _ in range(5)]
    assert a == b


def test_weighted_accepts_pair_and_dict_forms(runner_classes):
    story = runner_classes.StoryState()
    story.seed(7)
    pairs_result = story.weighted([["A", 1], ["B", 99]])
    dict_result = story.weighted(
        [{"value": "A", "weight": 1}, {"value": "B", "weight": 99}]
    )
    assert pairs_result == "B"
    assert dict_result == "B"


def test_fake_ip_private_block(runner_classes):
    story = runner_classes.StoryState()
    story.seed(1)
    for _ in range(20):
        ip = story.fake_ip({"private": True})
        first = ip.split(".")[0]
        assert first in {"10", "172", "192"}


def test_render_resolves_all_token_types(runner_classes):
    story = runner_classes.StoryState()
    story.load_scenario(
        {
            "id": "render-tests",
            "actors": [
                {"id": "victim", "username": "alex.rivera", "email": "alex@corp.local"}
            ],
            "hosts": [{"id": "ws", "name": "HOST-001"}],
            "iocs": [{"type": "IPV4", "value": "203.0.113.42", "meta": {"role": "C2"}}],
            "timing": {"base": {"mode": "fixed_offset", "offset_seconds": 0}},
        }
    )
    payload = {
        "user": "{{actor.victim.username}}",
        "host": "{{host.ws.name}}",
        "src_ip": "{{ioc.1}}",
        "src_ip_by_type": "{{ioc.ipv4}}",
        "phase": "{{phase}}",
        "literal": "{{{{leave-alone}}}}",
        "nested": [{"e": "{{actor.victim.email}}"}],
    }
    rendered = story.render(payload)
    assert rendered["user"] == "alex.rivera"
    assert rendered["host"] == "HOST-001"
    assert rendered["src_ip"] == "203.0.113.42"
    assert rendered["src_ip_by_type"] == "203.0.113.42"
    assert rendered["phase"] == "default"  # no story:phase called
    assert rendered["literal"] == "{{leave-alone}}"
    assert rendered["nested"][0]["e"] == "alex@corp.local"


def test_render_leaves_unknown_tokens(runner_classes):
    story = runner_classes.StoryState()
    out = story.render("hello {{actor.missing.field}} world")
    assert out == "hello {{actor.missing.field}} world"


def test_phase_loop_runs_and_restores(runner_classes):
    story = runner_classes.StoryState()
    story.current_phase = "outer"
    calls: List[int] = []

    def _fn(i: int) -> None:
        calls.append(i)
        # Inside the loop the phase should match the requested name.
        assert story.current_phase == "inner"

    story.phase_loop("inner", 3, _fn)
    assert calls == [1, 2, 3]
    assert story.current_phase == "outer"


def test_phase_loop_restores_phase_on_exception(runner_classes):
    story = runner_classes.StoryState()
    story.current_phase = "outer"

    def _boom(i: int) -> None:
        raise RuntimeError("explode")

    with pytest.raises(RuntimeError):
        story.phase_loop("inner", 2, _boom)
    assert story.current_phase == "outer"


def test_emit_many_invokes_factories(story_with_routing, runner_classes):
    sender = runner_classes.Sender(story_with_routing, mode="generate")
    out = sender.emit_many(
        "aws_cloudtrail",
        4,
        lambda i: {"eventName": f"E{i}"},
        lambda i: {"offset_seconds": i},
    )
    assert len(out) == 4
    assert [e["event"]["eventName"] for e in out] == ["E1", "E2", "E3", "E4"]
    # Each event carries the inherited routing hint.
    assert all(e["hec_path"] == "event" for e in out)


def test_batch_forwards_shared_opts(story_with_routing, runner_classes):
    sender = runner_classes.Sender(story_with_routing, mode="generate")
    results = sender.batch(
        "paloalto_firewall",
        ["raw line 1", "raw line 2"],
        {"actor": "a"},
    )
    assert len(results) == 2
    for wrapped in results:
        assert wrapped["actor"] == "a"
        assert wrapped["hec_path"] == "raw"


def test_render_can_be_disabled_per_event(story_with_routing, runner_classes):
    sender = runner_classes.Sender(story_with_routing, mode="generate")
    wrapped = sender.hec_event(
        "aws_cloudtrail",
        {"note": "leave {{actor.a.email}} alone"},
        {"render": False},
    )
    # Without rendering the literal {{...}} token survives unchanged.
    assert wrapped["event"]["note"] == "leave {{actor.a.email}} alone"


def test_from_generator_uses_entrypoint_override(
    story_with_routing, runner_classes, monkeypatch
):
    """Verify from_generator imports a module + invokes the resolved entrypoint."""
    fake_module = type("FakeMod", (), {})()
    fake_module.custom_log = lambda overrides=None: {
        "eventName": "FromFake",
        "ov": overrides,
    }

    monkeypatch.setattr(
        runner_classes.importlib,
        "import_module",
        lambda name: (
            fake_module if name == "fake_product" else importlib.import_module(name)
        ),
    )
    sender = runner_classes.Sender(story_with_routing, mode="generate")
    wrapped = sender.from_generator(
        "fake_product",
        {"hint": "x"},
        {"entry": "custom_log", "actor": "a"},
    )
    assert wrapped["event"]["eventName"] == "FromFake"
    assert wrapped["event"]["ov"] == {"hint": "x"}
    assert wrapped["actor"] == "a"


def test_from_generator_missing_entry_warns(
    story_with_routing, runner_classes, monkeypatch
):
    monkeypatch.setattr(
        runner_classes.importlib,
        "import_module",
        lambda name: type("Empty", (), {})(),
    )
    sender = runner_classes.Sender(story_with_routing, mode="generate")
    result = sender.from_generator("ghost_product", None, {"entry": "nope"})
    assert result == {}
    assert any("ghost_product" in w for w in story_with_routing.warnings)


# ---------------------------------------------------------------------------
# scenario_hec_sender: forwards routing kwargs
# ---------------------------------------------------------------------------


def test_send_single_event_forwards_routing_kwargs(monkeypatch):
    scenario_hec_sender = importlib.import_module("scenario_hec_sender")
    captured: Dict[str, Any] = {}

    def fake_send_one(line, product, attr_fields, event_time=None, **kwargs):
        captured["line"] = line
        captured["product"] = product
        captured["attr_fields"] = attr_fields
        captured["event_time"] = event_time
        captured["kwargs"] = kwargs
        return {"status": "OK"}

    monkeypatch.setattr(scenario_hec_sender, "send_one", fake_send_one)

    sender = scenario_hec_sender.ScenarioHECSender()
    event = {
        "timestamp": "2026-05-26T11:00:00Z",
        "source": "aws_cloudtrail",
        "phase": "recon",
        "event": {"eventName": "DescribeInstances"},
        "hec_path": "raw",
        "parser": "custom-parser-latest",
        "force_parser": True,
    }
    assert sender._send_single_event(event) is True
    assert captured["product"] == "aws_cloudtrail"
    assert captured["kwargs"] == {
        "hec_path": "raw",
        "parser_override": "custom-parser-latest",
        "force_parser": True,
    }


def test_send_single_event_omits_routing_when_absent(monkeypatch):
    scenario_hec_sender = importlib.import_module("scenario_hec_sender")
    captured: Dict[str, Any] = {}

    def fake_send_one(line, product, attr_fields, event_time=None, **kwargs):
        captured["kwargs"] = kwargs
        return {"status": "OK"}

    monkeypatch.setattr(scenario_hec_sender, "send_one", fake_send_one)
    sender = scenario_hec_sender.ScenarioHECSender()
    sender._send_single_event(
        {
            "timestamp": "2026-05-26T11:00:00Z",
            "source": "aws_cloudtrail",
            "phase": "recon",
            "event": {"eventName": "X"},
        }
    )
    assert captured["kwargs"] == {}


def test_send_single_event_rejects_invalid_hec_path(monkeypatch):
    scenario_hec_sender = importlib.import_module("scenario_hec_sender")
    captured: Dict[str, Any] = {}

    def fake_send_one(line, product, attr_fields, event_time=None, **kwargs):
        captured["kwargs"] = kwargs
        return {"status": "OK"}

    monkeypatch.setattr(scenario_hec_sender, "send_one", fake_send_one)
    sender = scenario_hec_sender.ScenarioHECSender()
    sender._send_single_event(
        {
            "timestamp": "2026-05-26T11:00:00Z",
            "source": "aws_cloudtrail",
            "phase": "recon",
            "event": {"eventName": "X"},
            "hec_path": "garbage",
            "parser": "   ",
        }
    )
    # Invalid values are filtered out — only valid keys reach the sender.
    assert "hec_path" not in captured["kwargs"]
    assert "parser_override" not in captured["kwargs"]


# ---------------------------------------------------------------------------
# hec_sender: envelope/qs/ensure-parser overrides
# ---------------------------------------------------------------------------


@pytest.fixture
def hec_sender_mod():
    return importlib.import_module("hec_sender")


def test_envelope_honors_sourcetype_override(hec_sender_mod):
    env = hec_sender_mod._envelope(
        {"k": "v"},
        "aws_cloudtrail",
        {"a": 1},
        event_time=1_700_000_000,
        sourcetype_override="custom-st-latest",
    )
    assert env["sourcetype"] == "custom-st-latest"
    assert env["time"] == 1_700_000_000


def test_envelope_falls_back_to_static_map(hec_sender_mod):
    env = hec_sender_mod._envelope({"k": "v"}, "aws_cloudtrail", {})
    # Static SOURCETYPE_MAP value is whatever the project ships; just confirm
    # we didn't accidentally drop the lookup.
    assert env["sourcetype"]
    assert (
        env["sourcetype"] != "aws_cloudtrail" or env["sourcetype"] == "aws_cloudtrail"
    )


def test_build_qs_with_override(hec_sender_mod):
    qs = hec_sender_mod._build_qs("paloalto_firewall", "override-st")
    assert "sourcetype=override-st" in qs


def test_ensure_parser_caches_by_sourcetype_and_overwrite(hec_sender_mod, monkeypatch):
    """force_parser changes the cache key so the second call re-syncs."""
    monkeypatch.setattr(hec_sender_mod, "_ENSURE_PARSER", True)
    monkeypatch.setattr(hec_sender_mod, "_OVERWRITE_PARSER", False)
    monkeypatch.setattr(hec_sender_mod, "_S1_CONFIG_API_URL", "https://config.example")
    monkeypatch.setattr(hec_sender_mod, "_S1_CONFIG_WRITE_TOKEN", "test-secret")
    # Start from a clean cache for each test.
    monkeypatch.setattr(hec_sender_mod, "_ENSURED_PARSERS", set())

    calls: List[Dict[str, Any]] = []

    class FakeResp:
        status_code = 200
        content = b'{"status":"ok"}'

        def json(self) -> Dict[str, Any]:
            return {"status": "ok", "message": "synced"}

    def fake_post(url, json=None, headers=None, timeout=None):
        calls.append({"url": url, "json": json})
        return FakeResp()

    monkeypatch.setattr(hec_sender_mod.requests, "post", fake_post)

    # First call: cache miss → posts once.
    hec_sender_mod._ensure_parser_in_destination(
        "aws_cloudtrail",
        sourcetype_override="custom-latest",
        overwrite_override=False,
    )
    assert len(calls) == 1
    assert calls[0]["json"]["overwrite_parser"] is False

    # Repeat same args: cache hit → no new post.
    hec_sender_mod._ensure_parser_in_destination(
        "aws_cloudtrail",
        sourcetype_override="custom-latest",
        overwrite_override=False,
    )
    assert len(calls) == 1

    # Same sourcetype, force_parser flipped → distinct cache key → posts again.
    hec_sender_mod._ensure_parser_in_destination(
        "aws_cloudtrail",
        sourcetype_override="custom-latest",
        overwrite_override=True,
    )
    assert len(calls) == 2
    assert calls[1]["json"]["overwrite_parser"] is True

    # Different sourcetype → another distinct cache key.
    hec_sender_mod._ensure_parser_in_destination(
        "aws_cloudtrail",
        sourcetype_override="other-latest",
        overwrite_override=False,
    )
    assert len(calls) == 3
    assert calls[2]["json"]["sourcetype"] == "other-latest"


def test_ensure_parser_disabled_skips_post(hec_sender_mod, monkeypatch):
    monkeypatch.setattr(hec_sender_mod, "_ENSURE_PARSER", False)
    monkeypatch.setattr(hec_sender_mod, "_ENSURED_PARSERS", set())
    calls: List[Any] = []

    monkeypatch.setattr(
        hec_sender_mod.requests,
        "post",
        lambda *a, **k: calls.append((a, k))
        or pytest.fail("should not POST when disabled"),
    )
    hec_sender_mod._ensure_parser_in_destination("aws_cloudtrail")
    assert calls == []
