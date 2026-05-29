#!/usr/bin/env python3
import argparse
import copy
import gzip
import hashlib
import importlib
import json
import os
import random
import re
import string
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

try:
    from lupa import LuaRuntime
except ModuleNotFoundError as exc:
    raise SystemExit("Missing dependency: install the latest lupa with `pip install lupa`.") from exc

try:
    import requests
except ModuleNotFoundError:
    requests = None

AUTO_UUID = "AUTO_UUID"

# Ensure event_generators subdirectories are importable so sender:from_generator
# can lazily load vendor modules by short name (e.g., `aws_cloudtrail`).
def _ensure_generator_paths() -> None:
    backend_dir = Path(__file__).resolve().parents[1]
    generator_root = backend_dir / "event_generators"
    if not generator_root.is_dir():
        return
    for category in (
        "cloud_infrastructure",
        "network_security",
        "endpoint_security",
        "identity_access",
        "email_security",
        "web_security",
        "infrastructure",
    ):
        path = str(generator_root / category)
        if path not in sys.path:
            sys.path.insert(0, path)


_ensure_generator_paths()

# Generator modules that don't follow the `<product>_log` naming convention.
# Used as a hint by sender:from_generator when `opts.entry` isn't provided.
_GENERATOR_ENTRYPOINT_OVERRIDES: Dict[str, str] = {
    "aws_cloudtrail":     "cloudtrail_log",
    "aws_guardduty":      "guardduty_log",
    "aws_vpcflowlogs":    "vpcflow_log",
    "microsoft_azuread":  "azure_ad_log",
    "wiz_issue":          "wiz_issue_log",
    "okta_system_log":    "okta_system_log",
}


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
        self.source_defaults: Dict[str, Dict[str, Any]] = {}

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
        sources = scenario.get("sources") or {}
        if isinstance(sources, dict):
            self.source_defaults = {
                str(name): self._normalize_source_defaults(cfg)
                for name, cfg in sources.items()
                if isinstance(cfg, dict)
            }

    @staticmethod
    def _normalize_source_defaults(cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Coerce per-source routing/parser hints into a stable shape."""
        allowed_paths = {"event", "raw", "auto"}
        normalized: Dict[str, Any] = {}
        hec_path = cfg.get("hec_path")
        if isinstance(hec_path, str) and hec_path.lower() in allowed_paths:
            normalized["hec_path"] = hec_path.lower()
        parser = cfg.get("parser")
        if isinstance(parser, str) and parser.strip():
            normalized["parser"] = parser.strip()
        if "force_parser" in cfg:
            normalized["force_parser"] = bool(cfg.get("force_parser"))
        fmt = cfg.get("format")
        if isinstance(fmt, str) and fmt.strip():
            normalized["format"] = fmt.strip().lower()
        return normalized

    def routing_for(self, source: str) -> Dict[str, Any]:
        """Return a copy of declared routing/parser defaults for a source."""
        return dict(self.source_defaults.get(source, {}))

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

    def rand_float(self, lo: float = 0.0, hi: float = 1.0) -> float:
        return random.uniform(lo, hi)

    def seed(self, value: Any) -> None:
        """Deterministic mode: re-seeds the runner's RNG for reproducible scenarios."""
        if value is None:
            random.seed()
            return
        random.seed(value)

    def pick(self, items: Any) -> Any:
        py_items = _lua_to_python(items) or []
        if not isinstance(py_items, list) or not py_items:
            return None
        return random.choice(py_items)

    def weighted(self, items: Any) -> Any:
        """Weighted pick. Accepts a sequence of {value, weight} pairs."""
        py_items = _lua_to_python(items) or []
        if not isinstance(py_items, list) or not py_items:
            return None
        values: List[Any] = []
        weights: List[float] = []
        for entry in py_items:
            if isinstance(entry, list) and len(entry) >= 2:
                values.append(entry[0])
                try:
                    weights.append(float(entry[1]))
                except (TypeError, ValueError):
                    weights.append(0.0)
            elif isinstance(entry, dict):
                values.append(entry.get("value"))
                try:
                    weights.append(float(entry.get("weight", 0)))
                except (TypeError, ValueError):
                    weights.append(0.0)
        if not values or sum(weights) <= 0:
            return random.choice(values) if values else None
        return random.choices(values, weights=weights, k=1)[0]

    def fake_ip(self, opts: Optional[Any] = None) -> str:
        py_opts = _lua_to_python(opts) if opts is not None else {}
        if py_opts.get("private"):
            block = random.choice(("10", "172.16", "192.168"))
            if block == "10":
                return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            if block == "172.16":
                return f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            return f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    def fake_hostname(self, prefix: str = "host") -> str:
        suffix = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
        return f"{prefix}-{suffix}"

    def fake_domain(self, tld: str = "example") -> str:
        body = "".join(random.choices(string.ascii_lowercase, k=random.randint(5, 9)))
        return f"{body}.{tld}"

    def fake_user(self) -> str:
        first = random.choice(("alex", "casey", "jordan", "morgan", "taylor", "riley", "skyler", "drew", "harper", "logan"))
        last = random.choice(("rivera", "chen", "patel", "nguyen", "khan", "smith", "garcia", "kim", "ali", "okafor"))
        return f"{first}.{last}"

    def fake_email(self, domain: Optional[str] = None) -> str:
        user = self.fake_user()
        return f"{user}@{domain or self.fake_domain('corp')}"

    def jitter(self, lo_seconds: float = -5.0, hi_seconds: float = 5.0) -> float:
        """Returns a uniformly random float in the given range. Pair with opts.offset_seconds."""
        return random.uniform(lo_seconds, hi_seconds)

    # ── Templating ──────────────────────────────────────────────────────────
    _TEMPLATE_RE = re.compile(r"\{\{\s*([^}]+?)\s*\}\}")

    def render(self, value: Any) -> Any:
        """Recursively resolve `{{actor.id.field}}` / `{{host.id.field}}` /
        `{{ioc.<idx>}}` / `{{phase}}` / `{{now}}` / `{{uuid}}` tokens.
        Returns a fresh Python object (dict/list/str/etc.).
        """
        py_value = _lua_to_python(value)
        return self._render_walk(py_value)

    def _render_walk(self, value: Any) -> Any:
        if isinstance(value, str):
            return self._render_string(value)
        if isinstance(value, dict):
            return {k: self._render_walk(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._render_walk(v) for v in value]
        return value

    def _render_string(self, text: str) -> str:
        # Escape `{{{{x}}}}` → keep literal `{{x}}` without resolution.
        ESC_OPEN = "\x00LB\x00"
        ESC_CLOSE = "\x00RB\x00"
        protected = text.replace("{{{{", ESC_OPEN).replace("}}}}", ESC_CLOSE)

        def _sub(match: "re.Match[str]") -> str:
            token = match.group(1).strip()
            resolved = self._resolve_token(token)
            if resolved is None:
                return match.group(0)
            return str(resolved)

        rendered = self._TEMPLATE_RE.sub(_sub, protected)
        return rendered.replace(ESC_OPEN, "{{").replace(ESC_CLOSE, "}}")

    def _resolve_token(self, token: str) -> Optional[Any]:
        if token == "phase":
            return self.current_phase
        if token == "now":
            return _iso(self.base_dt)
        if token == "uuid":
            return str(uuid.uuid4())
        parts = token.split(".")
        head = parts[0]
        if head == "actor" and len(parts) >= 2:
            actor = self.actors.get(parts[1])
            return self._walk_attrs(actor, parts[2:]) if actor is not None else None
        if head == "host" and len(parts) >= 2:
            host = self.hosts.get(parts[1])
            return self._walk_attrs(host, parts[2:]) if host is not None else None
        if head == "ioc" and len(parts) >= 2:
            return self._resolve_ioc(parts[1], parts[2:])
        return None

    def _resolve_ioc(self, selector: str, attrs: List[str]) -> Optional[Any]:
        # Numeric index (1-based) or match by type/value.
        target: Optional[Dict[str, Any]] = None
        try:
            idx = int(selector)
            if 1 <= idx <= len(self.ioc_list):
                target = self.ioc_list[idx - 1]
        except ValueError:
            sel_lower = selector.lower()
            for entry in self.ioc_list:
                if str(entry.get("type", "")).lower() == sel_lower or str(entry.get("value", "")).lower() == sel_lower:
                    target = entry
                    break
        if target is None:
            return None
        if not attrs:
            return target.get("value")
        return self._walk_attrs(target, attrs)

    @staticmethod
    def _walk_attrs(node: Any, attrs: List[str]) -> Optional[Any]:
        cur = node
        for attr in attrs:
            if cur is None:
                return None
            if isinstance(cur, dict):
                cur = cur.get(attr)
            else:
                cur = getattr(cur, attr, None)
        return cur

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

    def phase_loop(self, name: str, count: int, fn: Callable[[int], Any]) -> None:
        """Set a phase, invoke `fn(i)` for i in 1..count, restore prior phase."""
        if not callable(fn) or count <= 0:
            return
        previous = self.current_phase
        self.phase(name)
        try:
            for i in range(1, int(count) + 1):
                fn(i)
        finally:
            self.current_phase = previous


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
        if py_opts.get("render") is not False:
            event = self.story._render_walk(event)
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
        self._apply_routing_hints(source, wrapped, py_opts)
        self._validate_binding(wrapped)
        return wrapped

    def _apply_routing_hints(self, source: str, wrapped: Dict[str, Any], opts: Dict[str, Any]) -> None:
        """Merge scenario.sources defaults with per-event opts onto the wrapper."""
        defaults = self.story.routing_for(source)
        allowed_paths = {"event", "raw", "auto"}
        # hec_path
        hec_path = opts.get("hec_path") or defaults.get("hec_path")
        if isinstance(hec_path, str) and hec_path.lower() in allowed_paths:
            wrapped["hec_path"] = hec_path.lower()
        # parser override
        parser = opts.get("parser") or defaults.get("parser")
        if isinstance(parser, str) and parser.strip():
            wrapped["parser"] = parser.strip()
        # force_parser (per-event opts win; explicit False allowed)
        if "force_parser" in opts:
            wrapped["force_parser"] = bool(opts.get("force_parser"))
        elif "force_parser" in defaults:
            wrapped["force_parser"] = bool(defaults.get("force_parser"))
        # format hint (informational; not enforced by sender today)
        fmt = opts.get("format") or defaults.get("format")
        if isinstance(fmt, str) and fmt.strip():
            wrapped["format"] = fmt.strip().lower()

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

    def emit_many(self, source: str, count: int, payload_fn: Callable[[int], Any],
                  opts_fn: Optional[Callable[[int], Any]] = None) -> List[Dict[str, Any]]:
        """Emit `count` events for a source by calling payload_fn(i) (and optional
        opts_fn(i)) for i in 1..count. Returns the list of wrapped events.

        Named `emit_many` (not `repeat`) because `repeat` is a Lua reserved keyword.
        """
        if not callable(payload_fn) or count <= 0:
            return []
        results: List[Dict[str, Any]] = []
        for i in range(1, int(count) + 1):
            payload = payload_fn(i)
            opts = opts_fn(i) if callable(opts_fn) else None
            results.append(self.hec_event(source, payload, opts))
        return results

    def batch(self, source: str, payloads: Any, opts: Optional[Any] = None) -> List[Dict[str, Any]]:
        """Send a pre-built list of payloads with shared opts."""
        py_payloads = _lua_to_python(payloads) or []
        if not isinstance(py_payloads, list):
            return []
        return [self.hec_event(source, payload, opts) for payload in py_payloads]

    def from_generator(self, product: str, overrides: Optional[Any] = None,
                       opts: Optional[Any] = None) -> Dict[str, Any]:
        """Invoke a Python event generator under Backend/event_generators/* and
        wrap its result through `hec_event` so routing/parser hints still apply.

        opts.entry:   explicit function name on the module (overrides default convention)
        opts.payload: dotted-path into the returned object (e.g. "data.event") if the
                      generator returns a nested envelope. Defaults to the full return.
        """
        py_opts = _lua_to_python(opts) if opts is not None else {}
        py_overrides = _lua_to_python(overrides) if overrides is not None else None

        try:
            module = importlib.import_module(product)
        except ModuleNotFoundError as exc:
            self.story.warnings.append(
                f"from_generator: module '{product}' not importable ({exc})"
            )
            return {}

        entry_name = py_opts.get("entry") or _GENERATOR_ENTRYPOINT_OVERRIDES.get(product) or f"{product}_log"
        entry = getattr(module, entry_name, None)
        if entry is None:
            self.story.warnings.append(
                f"from_generator: '{product}' has no entrypoint '{entry_name}'"
            )
            return {}

        try:
            result = entry(py_overrides) if py_overrides is not None else entry()
        except TypeError:
            # Older generators don't accept overrides; retry without them.
            try:
                result = entry()
            except Exception as exc:  # pragma: no cover
                self.story.warnings.append(f"from_generator: '{product}' raised {exc!r}")
                return {}
        except Exception as exc:  # pragma: no cover
            self.story.warnings.append(f"from_generator: '{product}' raised {exc!r}")
            return {}

        if isinstance(result, str):
            text = result.strip()
            if text.startswith("{") or text.startswith("["):
                try:
                    result = json.loads(text)
                except json.JSONDecodeError:
                    pass

        path = py_opts.get("payload")
        if isinstance(path, str) and path and isinstance(result, dict):
            cur: Any = result
            for part in path.split("."):
                if isinstance(cur, dict) and part in cur:
                    cur = cur[part]
                else:
                    cur = None
                    break
            if cur is not None:
                result = cur

        # Strip generator-emitted opts keys that would conflict with hec_event opts.
        forwarded_opts = {k: v for k, v in py_opts.items() if k not in ("entry", "payload")}
        return self.hec_event(product, result, forwarded_opts)

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
    routing_summary: Dict[str, Dict[str, Any]] = {}
    for event in events:
        src = event["source"]
        source_counts[src] = source_counts.get(src, 0) + 1
        phase_counts[event["phase"]] = phase_counts.get(event["phase"], 0) + 1
        if event.get("actor"):
            actor_counts[event["actor"]] = actor_counts.get(event["actor"], 0) + 1
        if event.get("host"):
            host = story.hosts.get(event["host"], {}).get("name", event["host"])
            host_counts[host] = host_counts.get(host, 0) + 1
        if any(k in event for k in ("hec_path", "parser", "force_parser", "format")):
            entry = routing_summary.setdefault(src, {"count": 0})
            entry["count"] += 1
            for key in ("hec_path", "parser", "force_parser", "format"):
                if key in event and key not in entry:
                    entry[key] = event[key]
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
        "source_routing": routing_summary,
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
