#!/usr/bin/env python3
import argparse
import copy
import gzip
import hashlib
import json
import os
import random
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from lupa import LuaRuntime
except ModuleNotFoundError as exc:
    raise SystemExit("Missing dependency: install the latest lupa with `pip install lupa`.") from exc

try:
    import requests
except ModuleNotFoundError:
    requests = None

AUTO_UUID = "AUTO_UUID"


class AttrDict(dict):
    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __setattr__(self, name: str, value: Any) -> None:
        self[name] = value


def _to_attr(value: Any) -> Any:
    if isinstance(value, dict):
        return AttrDict({k: _to_attr(v) for k, v in value.items()})
    if isinstance(value, list):
        return [_to_attr(v) for v in value]
    return value


def _lua_to_python(value: Any) -> Any:
    if hasattr(value, "items"):
        items = list(value.items())
        if items and all(isinstance(k, int) for k, _ in items):
            ordered = sorted(items, key=lambda item: item[0])
            if [k for k, _ in ordered] == list(range(1, len(ordered) + 1)):
                return [_lua_to_python(v) for _, v in ordered]
        return {k: _lua_to_python(v) for k, v in items}
    return value


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _stable_uuid(name: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, name))


def _deep_set(target: Dict[str, Any], dotted_key: str, value: Any) -> None:
    cur = target
    parts = dotted_key.split(".")
    for part in parts[:-1]:
        if part not in cur or not isinstance(cur[part], dict):
            cur[part] = {}
        cur = cur[part]
    cur[parts[-1]] = value


def _apply_overrides(target: Dict[str, Any], overrides: Dict[str, Any]) -> None:
    for key, value in overrides.items():
        if "." in key:
            _deep_set(target, key, value)
        else:
            target[key] = value


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _load_alert_template(template_id: str) -> Optional[Dict[str, Any]]:
    backend_dir = Path(__file__).resolve().parents[1]
    for base in (backend_dir / "api" / "app" / "alerts" / "templates", backend_dir / "app" / "alerts" / "templates"):
        candidate = base / f"{template_id}.json"
        if candidate.exists():
            return _load_json(candidate)
    return None


class StoryState:
    def __init__(self) -> None:
        self.scenario: Dict[str, Any] = {}
        self.actors: Dict[str, AttrDict] = {}
        self.hosts: Dict[str, AttrDict] = {}
        self.ioc_list: List[Dict[str, Any]] = []
        self.timing: Dict[str, Any] = {}
        self.current_phase = "default"
        self.base_dt = datetime.now(timezone.utc).replace(hour=10, minute=0, second=0, microsecond=0)
        self.correlations: Dict[str, Any] = {}
        self.mitre_list: List[str] = []
        self.warnings: List[str] = []

    def load_scenario(self, scenario: Dict[str, Any], base_time: Optional[str] = None) -> None:
        self.scenario = scenario
        self.timing = scenario.get("timing") or {}
        if base_time:
            self.base_dt = _parse_iso(base_time)
        else:
            self.base_dt = self._resolve_base_time(self.timing.get("base") or {})
        for actor in scenario.get("actors") or []:
            self.register_actor(actor.get("id"), actor)
        for host in scenario.get("hosts") or []:
            self.register_host(host.get("id"), host)
        for ioc in scenario.get("iocs") or []:
            self.ioc_list.append(_to_attr(self._resolve_auto_values(ioc)))
        for technique in scenario.get("mitre") or []:
            self.mitre(technique)

    def _resolve_base_time(self, base: Dict[str, Any]) -> datetime:
        mode = base.get("mode", "fixed_offset")
        if mode == "absolute" and base.get("absolute"):
            return _parse_iso(base["absolute"])
        if mode == "now":
            return datetime.now(timezone.utc)
        offset = int(base.get("offset_seconds", 0) or 0)
        return datetime.now(timezone.utc).replace(hour=10, minute=0, second=0, microsecond=0) + timedelta(seconds=offset)

    def _resolve_auto_values(self, value: Any) -> Any:
        if value == AUTO_UUID:
            return str(uuid.uuid4())
        if isinstance(value, dict):
            return {k: self._resolve_auto_values(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._resolve_auto_values(v) for v in value]
        return value

    def register_actor(self, actor_id: str, profile: Dict[str, Any]) -> AttrDict:
        resolved = _to_attr(self._resolve_auto_values(profile))
        self.actors[actor_id] = resolved
        return resolved

    def register_host(self, host_id: str, profile: Dict[str, Any]) -> AttrDict:
        resolved = _to_attr(self._resolve_auto_values(profile))
        self.hosts[host_id] = resolved
        return resolved

    def actor(self, actor_id: str, profile: Optional[Any] = None) -> AttrDict:
        if profile is not None:
            return self.register_actor(actor_id, _lua_to_python(profile))
        return self.actors[actor_id]

    def host(self, host_id: str, profile: Optional[Any] = None) -> AttrDict:
        if profile is not None:
            return self.register_host(host_id, _lua_to_python(profile))
        return self.hosts[host_id]

    def phase(self, name: str) -> str:
        self.current_phase = name
        print(f"\n{name}")
        return name

    def base_time(self, iso_value: Optional[str] = None) -> str:
        if iso_value:
            self.base_dt = _parse_iso(iso_value)
        return _iso(self.base_dt)

    def resolve_time(self, opts: Optional[Dict[str, Any]] = None) -> datetime:
        opts = opts or {}
        phase_name = opts.get("phase") or self.current_phase
        phases = (self.timing.get("phases") or {})
        phase_cfg = phases.get(phase_name) or {}
        minutes = float(phase_cfg.get("offset_minutes", 0) or 0) + float(opts.get("offset_minutes", 0) or 0)
        seconds = float(phase_cfg.get("offset_seconds", 0) or 0) + float(opts.get("offset_seconds", 0) or 0)
        jitter = int(self.timing.get("jitter_seconds", 0) or 0)
        if jitter:
            seconds += random.randint(-jitter, jitter)
        return self.base_dt + timedelta(minutes=minutes, seconds=seconds)

    def at(self, minutes: int = 0, seconds: int = 0) -> str:
        return _iso(self.base_dt + timedelta(minutes=minutes, seconds=seconds))

    def ts_ns(self, minutes: int = 0, seconds: int = 0) -> str:
        dt = self.base_dt + timedelta(minutes=minutes, seconds=seconds)
        return str(int(dt.timestamp() * 1_000_000_000))

    def uuid(self) -> str:
        return str(uuid.uuid4())

    def uuid5(self, name: str) -> str:
        return _stable_uuid(name)

    def sha256(self, value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def sha1(self, value: str) -> str:
        return hashlib.sha1(value.encode("utf-8")).hexdigest()

    def md5(self, value: str) -> str:
        return hashlib.md5(value.encode("utf-8")).hexdigest()

    def rand_int(self, lo: int, hi: int) -> int:
        return random.randint(lo, hi)

    def ioc(self, ioc_type: str, value: str, meta: Optional[Any] = None) -> Dict[str, Any]:
        entry = {"type": ioc_type, "value": value, "meta": _lua_to_python(meta) if meta is not None else {}}
        self.ioc_list.append(entry)
        return entry

    def iocs(self) -> List[Dict[str, Any]]:
        return self.ioc_list

    def correlate(self, key: str, value: Any) -> None:
        self.correlations[key] = _lua_to_python(value)

    def mitre(self, tag: str) -> None:
        if tag not in self.mitre_list:
            self.mitre_list.append(tag)


class Sender:
    def __init__(self, story: StoryState, mode: str = "generate", live_config: Optional[Dict[str, Any]] = None) -> None:
        self.story = story
        self.mode = mode
        self.live_config = live_config or {}
        self.events: List[Dict[str, Any]] = []
        self.alert_results: List[Dict[str, Any]] = []
        self.ti_results: List[Dict[str, Any]] = []

    def _wrap(self, source: str, payload: Any, opts: Optional[Any]) -> Dict[str, Any]:
        py_opts = _lua_to_python(opts) if opts is not None else {}
        dt = self.story.resolve_time(py_opts)
        event = _lua_to_python(payload)
        event = copy.deepcopy(event)
        if isinstance(event, str):
            event = event.replace("{{TS}}", _iso(dt)).replace("{{HOST}}", self._host_name(py_opts))
        elif isinstance(event, dict):
            if source == "sentinelone_endpoint" and "event.time" not in event:
                event["event.time"] = str(int(dt.timestamp() * 1_000_000_000))
            if source == "okta_authentication" and "published" not in event:
                event["published"] = _iso(dt)
            self._autofill_identity(source, event, py_opts)
        wrapped = {
            "timestamp": _iso(dt),
            "source": source,
            "phase": py_opts.get("phase") or self.story.current_phase,
            "event": event,
        }
        if py_opts.get("actor"):
            wrapped["actor"] = py_opts["actor"]
        if py_opts.get("host"):
            wrapped["host"] = py_opts["host"]
        self._validate_binding(wrapped)
        return wrapped

    def _host_name(self, opts: Dict[str, Any]) -> str:
        host_id = opts.get("host")
        if host_id and host_id in self.story.hosts:
            return self.story.hosts[host_id].get("name", "")
        return ""

    def _autofill_identity(self, source: str, event: Dict[str, Any], opts: Dict[str, Any]) -> None:
        actor = self.story.actors.get(opts.get("actor")) if opts.get("actor") else None
        host = self.story.hosts.get(opts.get("host")) if opts.get("host") else None
        if source == "sentinelone_endpoint" and host and "endpoint.name" not in event:
            event["endpoint.name"] = host.get("name")
        if source == "okta_authentication" and actor:
            event.setdefault("actor", {})
            event["actor"].setdefault("alternateId", actor.get("email") or actor.get("username"))
            event["actor"].setdefault("displayName", actor.get("name") or actor.get("username"))
            if actor.get("okta_user_id"):
                event["actor"].setdefault("id", actor.get("okta_user_id"))

    def _validate_binding(self, wrapped: Dict[str, Any]) -> None:
        event = wrapped.get("event")
        if not isinstance(event, dict):
            return
        host_id = wrapped.get("host")
        if host_id and host_id in self.story.hosts and event.get("endpoint.name"):
            expected = self.story.hosts[host_id].get("name")
            if expected and event.get("endpoint.name") != expected:
                self.story.warnings.append(f"host mismatch: {wrapped['source']} bound to {host_id} but endpoint.name={event.get('endpoint.name')}")

    def hec_event(self, source: str, event: Any, opts: Optional[Any] = None) -> Dict[str, Any]:
        wrapped = self._wrap(source, event, opts)
        self.events.append(wrapped)
        return wrapped

    def hec_raw(self, source: str, payload: str, opts: Optional[Any] = None) -> Dict[str, Any]:
        return self.hec_event(source, {"raw": payload}, opts)

    def alert(self, template_id: str, overrides: Any, opts: Optional[Any] = None) -> Dict[str, Any]:
        py_opts = _lua_to_python(opts) if opts is not None else {}
        py_overrides = _lua_to_python(overrides) if overrides is not None else {}
        dt = self.story.resolve_time(py_opts)
        template = _load_alert_template(template_id)
        if not template:
            result = {"template": template_id, "success": False, "error": "template not found"}
            self.alert_results.append(result)
            return result
        alert = copy.deepcopy(template)
        time_ms = int(dt.timestamp() * 1000)
        alert.setdefault("finding_info", {})["uid"] = str(uuid.uuid4())
        alert["time"] = time_ms
        alert.setdefault("metadata", {})["logged_time"] = time_ms
        alert["metadata"]["modified_time"] = time_ms
        resource = self._alert_resource(py_opts)
        if resource:
            alert["resources"] = [resource]
        _apply_overrides(alert, py_overrides)
        if self.mode == "live":
            success = self._send_alert_live(alert)
        else:
            success = True
        result = {
            "template": template_id,
            "success": success,
            "phase": py_opts.get("phase") or self.story.current_phase,
            "timestamp": _iso(dt),
        }
        self.alert_results.append(result)
        return result

    def _alert_resource(self, opts: Dict[str, Any]) -> Optional[Dict[str, str]]:
        host_id = opts.get("host")
        actor_id = opts.get("actor")
        if host_id and host_id in self.story.hosts:
            name = self.story.hosts[host_id].get("name")
            return {"name": name, "uid": _stable_uuid(name)}
        if actor_id and actor_id in self.story.actors:
            actor = self.story.actors[actor_id]
            name = actor.get("email") or actor.get("username") or actor_id
            return {"name": name, "uid": _stable_uuid(name)}
        return None

    def _send_alert_live(self, alert: Dict[str, Any]) -> bool:
        if requests is None:
            print("ERROR: Missing 'requests' dependency – cannot send alerts in live mode")
            return False

        ingest_url = os.environ["UAM_INGEST_URL"].rstrip("/") + "/v1/alerts"
        account_id = os.environ["UAM_ACCOUNT_ID"]
        site_id = os.environ.get("UAM_SITE_ID", "")
        scope = f"{account_id}:{site_id}" if site_id else account_id
        headers = {
            "Authorization": f"Bearer {os.environ['UAM_SERVICE_TOKEN']}",
            "S1-Scope": scope,
            "Content-Encoding": "gzip",
            "Content-Type": "application/json",
            "S1-Trace-Id": "helios-ingest-uam:alwayslog",
        }

        resource = (alert.get("resources") or [{}])[0]
        title = alert.get("finding_info", {}).get("title", "N/A")
        print("\n      Alert Detonation")
        print(f"         Title: {title}")
        print(f"         Resource: {resource.get('name', 'unknown')}")
        print(f"         URL: {ingest_url}")
        print(f"         Scope: {scope}")

        try:
            payload = gzip.compress(json.dumps(alert).encode("utf-8"))
            resp = requests.post(ingest_url, headers=headers, data=payload, timeout=30)
            print(f"         Response: {resp.status_code} {resp.reason}")
            if resp.status_code != 202 and resp.text:
                print(f"         Body: {resp.text[:200]}")
            return resp.status_code == 202
        except Exception as exc:
            print(f"         Exception while sending alert: {exc}")
            return False

    def ti(self, iocs: Any, opts: Optional[Any] = None) -> Dict[str, Any]:
        py_iocs = _lua_to_python(iocs)
        result = {"count": len(py_iocs or []), "success": True, "mode": self.mode}
        self.ti_results.append(result)
        return result

    def sleep(self, ms: int) -> None:
        if self.mode == "live":
            time.sleep(ms / 1000)


def _build_output(story: StoryState, sender: Sender) -> Dict[str, Any]:
    events = sorted(sender.events, key=lambda e: e["timestamp"])
    source_counts: Dict[str, int] = {}
    phase_counts: Dict[str, int] = {}
    actor_counts: Dict[str, int] = {}
    host_counts: Dict[str, int] = {}
    for event in events:
        source_counts[event["source"]] = source_counts.get(event["source"], 0) + 1
        phase_counts[event["phase"]] = phase_counts.get(event["phase"], 0) + 1
        if event.get("actor"):
            actor_counts[event["actor"]] = actor_counts.get(event["actor"], 0) + 1
        if event.get("host"):
            host = story.hosts.get(event["host"], {}).get("name", event["host"])
            host_counts[host] = host_counts.get(host, 0) + 1
    scenario_id = story.scenario.get("id", "lua-scenario")
    return {
        "scenario_id": f"{scenario_id}-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "scenario_name": story.scenario.get("name", scenario_id),
        "description": story.scenario.get("description", ""),
        "generated_at": _iso(datetime.now(timezone.utc)),
        "timeline_start": _iso(story.base_dt),
        "total_events": len(events),
        "actors": list(story.actors.values()),
        "hosts": list(story.hosts.values()),
        "timing": story.timing,
        "correlation_details": story.correlations,
        "source_breakdown": source_counts,
        "phase_breakdown": phase_counts,
        "actor_breakdown": actor_counts,
        "host_breakdown": host_counts,
        "alerts": {"enabled": bool(sender.alert_results), "results": sender.alert_results},
        "threat_intel": {"enabled": bool(sender.ti_results), "results": sender.ti_results},
        "mitre_techniques": story.mitre_list,
        "warnings": story.warnings,
        "events": events,
    }


def _make_lua_runtime() -> LuaRuntime:
    lua = LuaRuntime(unpack_returned_tuples=True)
    lua.execute("""
        AUTO_UUID = "AUTO_UUID"
        function AUTO_SHA256(value) return story:sha256(value) end
        io = nil
        os = nil
        package = nil
        require = nil
        debug = nil
        dofile = nil
        loadfile = nil
    """)
    return lua


def run_lua_scenario(path: Path, mode: str, output: Optional[Path], base_time: Optional[str], auto_replay: bool) -> Dict[str, Any]:
    story = StoryState()
    sender = Sender(story, mode=mode)
    lua = _make_lua_runtime()
    lua.globals()["story"] = story
    lua.globals()["sender"] = sender
    scenario = _lua_to_python(lua.execute(path.read_text(encoding="utf-8")))
    if not isinstance(scenario, dict):
        raise RuntimeError("Lua scenario must return a table")
    story.load_scenario(scenario, base_time=base_time)
    run_fn = scenario.get("run")
    if run_fn is None:
        raise RuntimeError("Lua scenario must define run = function(sender, story) ... end")
    run_fn(sender, story)
    result = _build_output(story, sender)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"Scenario saved to: {output}")
    if auto_replay and output:
        replay = Path(__file__).with_name("scenario_hec_sender.py")
        subprocess.run([sys.executable, str(replay), "--scenario", str(output), "--auto", "--preserve-timestamps"], check=False)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Run portable Lua scenarios")
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--mode", choices=["generate", "live"], default="generate")
    parser.add_argument("--output")
    parser.add_argument("--base-time")
    parser.add_argument("--auto-replay", action="store_true")
    args = parser.parse_args()
    result = run_lua_scenario(Path(args.scenario), args.mode, Path(args.output) if args.output else None, args.base_time, args.auto_replay)
    print(json.dumps({"scenario_name": result["scenario_name"], "total_events": result["total_events"], "source_breakdown": result["source_breakdown"]}, indent=2))


if __name__ == "__main__":
    main()
