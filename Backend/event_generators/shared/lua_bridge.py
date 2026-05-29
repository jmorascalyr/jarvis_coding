"""Bridge for running single-file Lua generators as if they were Python generators.

Each Lua generator file must `return` a table that declares:

    return {
      id         = "aws_cloudtrail_lua",         -- canonical product id (must match filename)
      category   = "cloud_infrastructure",       -- one of the discovery categories
      name       = "AWS CloudTrail (Lua)",       -- optional display name
      sourcetype = "aws_cloudtrail-latest",      -- optional, used by hec_sender SOURCETYPE_MAP
      hec_path   = "event",                      -- "event" | "raw" | "auto"
      vendor     = "AWS",                        -- optional metadata
      product    = "CloudTrail",                 -- optional metadata
      emit       = function(state, i)            -- REQUIRED: returns one event per call
        return { ... }
      end,
    }

The runtime stitches in a `helpers` global with deterministic-ish utilities
(`uuid`, `sha256`, `rand_int`, `pick`, `fake_ip`, ...) so single-file Lua
generators don't have to re-implement them.

Two-tier loading:
  * `parse_header_metadata(path)` — text-only, runs without `lupa`. Lets the
    API service discover generators even when `lupa` isn't installed there.
  * `load(path)` — requires `lupa`; executes the file and returns a
    `LuaGeneratorHandle` whose `emit_one()` produces one event.
"""

from __future__ import annotations

import hashlib
import random
import re
import string
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Optional


class LuaBridgeUnavailable(RuntimeError):
    """Raised when `lupa` is required but not installed."""


_HEADER_FIELD_RE = re.compile(
    r"""^\s*(?P<key>id|category|name|sourcetype|hec_path|vendor|product|description)
        \s*=\s*
        (?P<quote>['"])(?P<value>.*?)(?P=quote)\s*,?\s*$""",
    re.VERBOSE | re.MULTILINE,
)


_RETURN_TABLE_RE = re.compile(r"return\s*\{", re.MULTILINE)


def parse_header_metadata(path: Path) -> Optional[Dict[str, str]]:
    """Best-effort scrape of the header table without invoking Lua.

    Convention: the header table is the table returned at the end of the file
    (``return { id = "...", category = "...", ... }``). We anchor the field
    scan to the **last** ``return {`` block so unrelated local tables earlier
    in the file (e.g. lookup constants with their own ``name = "..."`` keys)
    don't bleed into the metadata. Returns ``None`` when no ``id =`` field was
    found inside that block — that's the only required field.
    """
    try:
        source = path.read_text(encoding="utf-8")
    except OSError:
        return None

    return_matches = list(_RETURN_TABLE_RE.finditer(source))
    scope = source[return_matches[-1].start():] if return_matches else source

    metadata: Dict[str, str] = {}
    for match in _HEADER_FIELD_RE.finditer(scope):
        key = match.group("key")
        if key in metadata:
            continue  # keep first occurrence inside the header block
        metadata[key] = match.group("value")

    if "id" not in metadata:
        return None
    metadata["file_path"] = str(path)
    return metadata


# ─── Helpers exposed to Lua ────────────────────────────────────────────────


_FIRST_NAMES = (
    "alex", "casey", "jordan", "morgan", "taylor", "riley", "skyler",
    "drew", "harper", "logan",
)
_LAST_NAMES = (
    "rivera", "chen", "patel", "nguyen", "khan", "smith", "garcia",
    "kim", "ali", "okafor",
)


def _lua_to_python(value: Any) -> Any:
    """Recursively convert a Lua table to a Python dict/list."""
    if hasattr(value, "items"):
        items = list(value.items())
        if items and all(isinstance(k, int) for k, _ in items):
            ordered = sorted(items, key=lambda item: item[0])
            if [k for k, _ in ordered] == list(range(1, len(ordered) + 1)):
                return [_lua_to_python(v) for _, v in ordered]
        return {k: _lua_to_python(v) for k, v in items}
    return value


def _build_helpers() -> Dict[str, Callable[..., Any]]:
    """Returns the helper table exposed to Lua as a global `helpers`."""

    def _coerce_opts(opts: Any) -> Dict[str, Any]:
        py = _lua_to_python(opts) if opts is not None else {}
        return py if isinstance(py, dict) else {}

    def _rand_int(lo: int, hi: int) -> int:
        return random.randint(int(lo), int(hi))

    def _rand_float(lo: float = 0.0, hi: float = 1.0) -> float:
        return random.uniform(float(lo), float(hi))

    def _lua_seq_len(items: Any) -> int:
        """Return the sequence length of a Lua table or Python list."""
        if items is None:
            return 0
        if isinstance(items, (list, tuple)):
            return len(items)
        try:
            return len(items)  # lupa exposes __len__ for sequence-like tables
        except TypeError:
            return 0

    def _pick(items: Any) -> Any:
        length = _lua_seq_len(items)
        if length == 0:
            return None
        if isinstance(items, (list, tuple)):
            return random.choice(items)
        # Lua table — keep it Lua-native by indexing 1-based.
        return items[random.randint(1, length)]

    def _weighted(items: Any) -> Any:
        length = _lua_seq_len(items)
        if length == 0:
            return None

        def _entries():
            if isinstance(items, (list, tuple)):
                for entry in items:
                    yield entry
            else:
                for idx in range(1, length + 1):
                    yield items[idx]

        values, weights = [], []
        for entry in _entries():
            if hasattr(entry, "__getitem__") and not isinstance(entry, (str, bytes)):
                try:
                    value = entry[1]
                    weight = entry[2]
                except (KeyError, TypeError, IndexError):
                    # dict-style { value=..., weight=... }
                    value = entry["value"] if hasattr(entry, "__getitem__") else None
                    weight = entry["weight"] if hasattr(entry, "__getitem__") else 0
                values.append(value)
                try:
                    weights.append(float(weight))
                except (TypeError, ValueError):
                    weights.append(0.0)
        if not values or sum(weights) <= 0:
            return random.choice(values) if values else None
        return random.choices(values, weights=weights, k=1)[0]

    def _fake_ip(opts: Any = None) -> str:
        py = _coerce_opts(opts)
        if py.get("private"):
            block = random.choice(("10", "172.16", "192.168"))
            if block == "10":
                return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            if block == "172.16":
                return f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            return f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    def _fake_hostname(prefix: str = "host") -> str:
        suffix = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
        return f"{prefix}-{suffix}"

    def _fake_domain(tld: str = "example") -> str:
        body = "".join(random.choices(string.ascii_lowercase, k=random.randint(5, 9)))
        return f"{body}.{tld}"

    def _fake_user() -> str:
        return f"{random.choice(_FIRST_NAMES)}.{random.choice(_LAST_NAMES)}"

    def _fake_email(domain: Optional[str] = None) -> str:
        return f"{_fake_user()}@{domain or _fake_domain('corp')}"

    def _jitter(lo: float = -5.0, hi: float = 5.0) -> float:
        return random.uniform(float(lo), float(hi))

    return {
        "uuid": lambda: str(uuid.uuid4()),
        "uuid5": lambda name: str(uuid.uuid5(uuid.NAMESPACE_DNS, str(name))),
        "now_ms": lambda: int(time.time() * 1000),
        "now_iso": lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sha256": lambda v: hashlib.sha256(str(v).encode("utf-8")).hexdigest(),
        "sha1":   lambda v: hashlib.sha1(str(v).encode("utf-8")).hexdigest(),
        "md5":    lambda v: hashlib.md5(str(v).encode("utf-8")).hexdigest(),
        "rand_int":   _rand_int,
        "rand_float": _rand_float,
        "pick":       _pick,
        "weighted":   _weighted,
        "fake_ip":       _fake_ip,
        "fake_hostname": _fake_hostname,
        "fake_domain":   _fake_domain,
        "fake_user":     _fake_user,
        "fake_email":    _fake_email,
        "jitter":        _jitter,
    }


# ─── Loader ────────────────────────────────────────────────────────────────


@dataclass
class LuaGeneratorHandle:
    """Holds a loaded Lua generator and its sandbox."""
    path: Path
    metadata: Dict[str, Any]
    _runtime: Any
    _state: Any
    _emit: Callable[..., Any]
    _counter: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def id(self) -> str:
        return str(self.metadata.get("id") or self.path.stem)

    @property
    def category(self) -> str:
        return str(self.metadata.get("category") or "uncategorized")

    @property
    def sourcetype(self) -> Optional[str]:
        st = self.metadata.get("sourcetype")
        return str(st) if isinstance(st, str) and st.strip() else None

    @property
    def hec_path(self) -> str:
        hp = self.metadata.get("hec_path")
        if isinstance(hp, str) and hp.lower() in {"event", "raw", "auto"}:
            return hp.lower()
        return "auto"

    def emit_one(self) -> Any:
        """Invoke the Lua `emit(state, i)` callable. Returns a Python dict/str."""
        with self._lock:
            self._counter += 1
            result = self._emit(self._state, self._counter)
        return _lua_to_python(result)


_HANDLE_CACHE: Dict[str, LuaGeneratorHandle] = {}
_HANDLE_LOCK = threading.Lock()


def load(path: Path) -> LuaGeneratorHandle:
    """Load (or reuse cached) Lua generator handle.

    Raises :class:`LuaBridgeUnavailable` if `lupa` isn't installed.
    """
    abs_path = str(Path(path).resolve())
    cached = _HANDLE_CACHE.get(abs_path)
    if cached is not None:
        return cached

    try:
        from lupa import LuaRuntime
    except ImportError as exc:  # pragma: no cover - environment guard
        raise LuaBridgeUnavailable(
            "lupa is required to load Lua generators. Install with `pip install lupa`."
        ) from exc

    runtime = LuaRuntime(unpack_returned_tuples=True)
    runtime.execute(
        """
        -- Sandboxing: drop dangerous globals
        io = nil
        os = { time = function() return os_time_ms() / 1000 end,
               date = function(fmt) return helpers.now_iso() end,
               getenv = function() return nil end }
        package = nil
        require = nil
        debug = nil
        dofile = nil
        loadfile = nil
        """
    )

    helpers = _build_helpers()
    runtime.globals()["helpers"] = helpers
    runtime.globals()["os_time_ms"] = helpers["now_ms"]

    source = Path(path).read_text(encoding="utf-8")
    raw = runtime.execute(source)
    header = _lua_to_python(raw)
    if not isinstance(header, dict):
        raise ValueError(
            f"Lua generator at {path} must return a table; got {type(header).__name__}"
        )

    emit = raw["emit"] if hasattr(raw, "__getitem__") else None
    # `emit` survives only through the Lua runtime; re-fetch via the raw table
    # because _lua_to_python on the header would have flattened it to a Python
    # function reference that may detach from the runtime stack.
    if emit is None or not callable(emit):
        raise ValueError(
            f"Lua generator at {path} is missing a callable `emit(state, i)` field"
        )

    state_table = runtime.table_from({}) if hasattr(runtime, "table_from") else runtime.eval("{}")
    handle = LuaGeneratorHandle(
        path=Path(path),
        metadata={k: v for k, v in header.items() if k != "emit"},
        _runtime=runtime,
        _state=state_table,
        _emit=emit,
    )

    with _HANDLE_LOCK:
        _HANDLE_CACHE[abs_path] = handle
    return handle


def discover(generators_root: Path, categories: Optional[list] = None) -> Dict[str, Dict[str, str]]:
    """Scan ``<root>/lua/<category>/*.lua`` and return id -> metadata.

    Uses :func:`parse_header_metadata` so this is safe to call from
    environments where `lupa` isn't installed.
    """
    results: Dict[str, Dict[str, str]] = {}
    lua_root = Path(generators_root) / "lua"
    if not lua_root.is_dir():
        return results
    category_dirs = (
        [lua_root / c for c in categories]
        if categories
        else [p for p in lua_root.iterdir() if p.is_dir() and not p.name.startswith("_")]
    )
    for category_dir in category_dirs:
        if not category_dir.is_dir():
            continue
        for lua_file in sorted(category_dir.glob("*.lua")):
            if lua_file.name.startswith("_"):
                continue
            meta = parse_header_metadata(lua_file)
            if not meta:
                continue
            meta.setdefault("category", category_dir.name)
            results[meta["id"]] = meta
    return results


def reset_cache() -> None:
    """Clear the loaded-handle cache (intended for tests / hot-reload)."""
    with _HANDLE_LOCK:
        _HANDLE_CACHE.clear()
