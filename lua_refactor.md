# Lua Scenario Refactor Guide

**Goal:** Convert existing Python-based Jarvis scenarios (or their JSON outputs) into portable Lua scripts that run through `Backend/scenarios/lua_scenario_runner.py` and are manageable through the new frontend Lua Scenario UI.

> 🧠 TL;DR – Lua scenarios return a single table containing metadata (id/name/description/timing/actors/hosts/etc.), static event payloads, optional alert plans, and a `run(sender, story)` function that streams those payloads via the runner’s `sender` helpers.

---

## 1. Prerequisites

1. **Python environment** with `lupa` installed (already in project requirements).
2. **Baseline scenario output**
   - Either rerun the Python scenario module under `Backend/scenarios/` to regenerate its JSON config, _or_ export the exact telemetry set you want to port.
   - These JSON files typically land in `Backend/scenarios/configs/<scenario_id>.json`.
3. **Reference Lua runner + helpers**
   - `Backend/scenarios/lua_scenario_runner.py` exposes:
     - `story`: stateful context for actors, hosts, IOCs, timing, MITRE coverage.
     - `sender:hec_event`, `sender:hec_raw`, `sender:alert`, `sender:ti`, etc.
   - Existing Lua example: `Backend/scenarios/lua/identity_theft_ransomware.lua`.

---

## 2. Migration Workflow

### Step 0 – Capture canonical data

```bash
python Backend/scenarios/<python_scenario>.py \
  --output Backend/scenarios/configs/<scenario_id>.json
```

Double-check the JSON timeline: includes `actors`, `hosts`, `timing`, `events`, optional alert narratives, etc.

### Step 1 – Scaffold the Lua metadata

Create `Backend/scenarios/lua/<scenario_id>.lua` and start with:

```lua
local scenario = {
  id = "my_new_scenario",
  name = "My Scenario (Lua)",
  description = "Short pitch...",
  timing = {
    base = { mode = "now" },
    duration_minutes = 25,
    jitter_seconds = 0,
    phases = {
      reconnaissance = { offset_minutes = 0 },
      impact = { offset_minutes = 20 }
    }
  },
  actors = {
    { id = "victim", name = "Alex King", email = "alex@example.com" },
    { id = "attacker", ip = "203.0.113.42" }
  },
  hosts = {
    { id = "workstation", name = "HOST-01", os = "Windows" }
  },
  mitre = { "T1078", "T1486" },
  iocs = {
    { type = "IPV4", value = "203.0.113.42", meta = { role = "C2" } }
  },
  sources = {
    -- Per-source HEC routing + parser hints. Optional; declare only what you need.
    aws_cloudtrail = {
      hec_path = "event",                     -- "event" | "raw" | "auto"
      parser   = "aws_cloudtrail-latest",     -- explicit sourcetype/parser bundle
      force_parser = false,                   -- override JARVIS_OVERWRITE_PARSER for this source
      format   = "json"                       -- informational, surfaced in `source_routing`
    },
    paloalto_firewall = {
      hec_path = "raw",
      parser   = "marketplace-paloaltonetworksfirewall-latest"
    }
  }
}
```

> ✅ Populate from the Python scenario’s metadata dictionaries. Keep IDs stable; the runner uses them for correlation and UI display.

#### `scenario.sources` precedence

The runner merges three layers (highest to lowest priority) when wrapping each event:

1. **Per-event opts** — e.g. `sender:hec_event(src, payload, { hec_path = "raw" })`
2. **`scenario.sources[<src>]`** — the table above
3. **Static defaults** — `JSON_PRODUCTS` allowlist + `SOURCETYPE_MAP` in `Backend/event_generators/shared/hec_sender.py`

The runner output JSON includes a top-level **`source_routing`** summary (`{ source → { count, hec_path, parser, force_parser, format } }`) so you can preview the resolved routing decisions before going live.

### Step 2 – Port event payloads

You have two main options:

1. **Literal table copy (fastest for frozen scenarios)**
   - Paste each JSON event as a Lua table inside an `events = { ... }` array.
   - Replace JSON object keys with Lua table syntax. Pro tip: run a helper script:
     ```bash
     python - <<'PY'
     import json, sys
     data = json.load(open('Backend/scenarios/configs/my_scenario.json'))
     for event in data['events']:
         print('  {')
         for key, value in event.items():
             if isinstance(value, str):
                 value = value.replace('\"', '"')
                 print(f'    {key} = "{value}",')
             else:
                 print(f'    {key} = {json.dumps(value)},')
         print('  },')
     PY
     ```
   - Clean up quoting/indenting afterwards.

2. **Programmatic generation (optional)**
   - If the Python scenario called helper generators (Okta, SentinelOne, etc.), reimplement only the final payloads you care about using Lua helper functions, or keep them static.
   - Static data keeps the Lua deterministic and portable.

Store the result:

```lua
local events = {
  {
    timestamp = "2026-05-10T10:00:00Z",
    source = "sentinelone_endpoint",
    phase = "credential_theft",
    event = {
      ["event.id"] = "01ABC...",
      ["endpoint.name"] = "HOST-01",
      ...
    }
  },
  -- repeat for each payload
}
```

### Step 3 – Optional alert/TI plans

If the scenario’s Python version detonated alerts or threat intel:

```lua
local alerts = {
  {
    id = "phase1",
    template = "default_alert",
    phase = "recon",
    host = "workstation",
    actor = "victim",
    offset_minutes = 3,
    overrides = {
      ["finding_info.title"] = "Unauthorized remote tool",
      severity_id = 4
    }
  }
}

scenario.alerts = alerts
```

The runner’s `sender:alert()` will merge these overrides with the base template (see `_load_alert_template` inside the runner).

### Step 4 – Implement `run(sender, story)`

At the bottom of the file:

```lua
local function event_opts(item)
  local opts = { phase = item.phase or "default" }
  if item.source == "sentinelone_endpoint" then
    opts.host = (item.event["endpoint.name"] == "HOST-01") and "workstation" or nil
  end
  opts.actor = item.actor or "victim"
  return opts
end

scenario.run = function(sender, story)
  story:correlate("source_scenario", "<python_module>.py")
  for _, item in ipairs(events) do
    sender:hec_event(item.source, item.event, event_opts(item))
  end
  if scenario.alerts then
    for _, plan in ipairs(scenario.alerts) do
      sender:alert(plan.template, plan.overrides, {
        phase = plan.phase,
        actor = plan.actor,
        host = plan.host,
        offset_minutes = plan.offset_minutes or 0
      })
    end
  end
  sender:ti(story:iocs(), { phase = "impact" })
end

return scenario
```

Key tips:
- Call `story:phase("name")` whenever you shift MITRE phases—this produces readable console banners.
- Use helper methods like `story:actor()` or `story:host()` if you need dynamic lookups.

### Step 5 – Test locally

```bash
python Backend/scenarios/lua_scenario_runner.py \
  --scenario Backend/scenarios/lua/my_new_scenario.lua \
  --output /tmp/my_new_scenario.json \
  --auto-replay  # optional: automatically push to HEC via scenario_hec_sender
```

Validate console output + `/tmp/...json` contents. The output JSON's
`source_routing` block previews the resolved HEC path / parser per source so
you can spot misconfigurations before flipping to LIVE.

Run the unit suite to confirm runner + sender wiring stays intact:

```bash
pytest Backend/scenarios/tests/test_lua_routing_and_helpers.py -v
```

It covers `scenario.sources` precedence, the `source_routing` summary, every
helper (`seed`/`pick`/`weighted`/`fake_*`/`render`/`emit_many`/`batch`/
`from_generator`/`phase_loop`), the `force_parser` cache key, and the
`hec_path`/`parser_override` forwarding through `scenario_hec_sender` →
`hec_sender.send_one`.

### Step 6 – Surface in the UI

1. **Built-in scenario**
   - Place the Lua file under `Backend/scenarios/lua/`.
   - Update `OOTB_SCENARIOS` in `Backend/api/app/routers/lua_scenarios.py` if you want it pre-registered in the API response.

2. **User-managed scenario**
   - Drop the file into `Backend/scenarios/lua/user/<id>.lua`.
   - Use the frontend Settings → Lua Scenarios tab (new UI) to import/edit/delete it.

3. **Scenario dropdown**
   - Frontend automatically fetches `/api/v1/lua-scenarios`; no manual JS edits needed for user scripts.
   - Built-ins still require an entry in the `/scenarios` response to display metadata.

### Step 7 – Commit the Lua + docs (if applicable)

- Make sure `.gitignore` allows the new Lua file (the repo already tracks `Backend/scenarios/lua/*.lua` and keeps user uploads ignored, except `.gitkeep`).
- Document any nuances (e.g., new alert templates, dependencies) in `lua_refactor.md` or the relevant README.

---

## 3. Common Patterns & Helpers

### Timing & identity

| Need | Lua helper | Notes |
|------|------------|-------|
| Stable timestamps | `story:at(minutes, seconds)` | ISO strings relative to the base phase offset. |
| Nanosecond stamps | `story:ts_ns(minutes, seconds)` | Useful for SentinelOne `event.time`. |
| Set/move phase | `story:phase("name")` / `story:phase_loop("name", count, fn)` | `phase_loop` saves & restores the prior phase. |
| Random IDs | `story:uuid()` / `story:uuid5("namespace")` | uuid5 is deterministic per input string. |
| Hashes | `story:sha256(v)` / `story:sha1(v)` / `story:md5(v)` | |

### Randomization (deterministic when `story:seed(n)` is set)

| Need | Lua helper | Notes |
|------|------------|-------|
| Reproducible run | `story:seed(42)` | Re-seeds the underlying Python RNG. Call once at the top of `run()`. |
| Range int / float | `story:rand_int(lo, hi)` / `story:rand_float(lo, hi)` | |
| Pick one | `story:pick({ "a", "b", "c" })` | Returns nil for empty input. |
| Weighted pick | `story:weighted({ {"low", 1}, {"high", 9} })` | Accepts `{value, weight}` pairs or `{value=, weight=}` tables. |
| Faker primitives | `story:fake_ip({ private = true })`, `story:fake_user()`, `story:fake_email("corp.local")`, `story:fake_hostname("WS")`, `story:fake_domain("internal")` | All driven by the seeded RNG. |
| Timestamp jitter | `story:jitter(-5, 5)` | Pair with `opts.offset_seconds` for natural spread. |

### Templating

`sender:hec_event` automatically calls `story:render` on the payload (string or nested table). Tokens:

| Token | Resolves to |
|-------|-------------|
| `{{actor.<id>.<field>}}` | Field on a registered actor (e.g. `{{actor.victim.email}}`). |
| `{{host.<id>.<field>}}` | Field on a registered host. |
| `{{ioc.<n>}}` / `{{ioc.<n>.<field>}}` | Nth IOC (1-based) or by type (`{{ioc.IPV4}}`). Bare token returns `value`. |
| `{{phase}}` / `{{now}}` / `{{uuid}}` | Current phase name, base-time ISO, fresh UUID. |
| `{{{{literal}}}}` | Escaped — renders to `{{literal}}` (use this to avoid auto-render). |

Pass `opts = { render = false }` to disable auto-render for a single event (useful for raw / pre-built payloads).

### Bulk emission & generator passthrough

| Helper | Use |
|--------|-----|
| `sender:emit_many(src, count, payload_fn, opts_fn?)` | Loop helper. `payload_fn(i)` returns a Lua table; `opts_fn(i)` is optional. Returns the list of wrapped envelopes. |
| `sender:batch(src, { p1, p2, ... }, opts?)` | Same shared opts for a pre-built payload list. |
| `sender:from_generator(product, overrides?, opts?)` | Imports `Backend/event_generators/<category>/<product>.py`, calls its `<product>_log()` (overrides handled when supported), and wraps the result through `hec_event` so routing/parser hints still apply. Override the entrypoint with `opts.entry = "custom_log"`; drill into nested payloads with `opts.payload = "data.event"`. |

### Alerts & TI

| Helper | Notes |
|--------|-------|
| `sender:alert(template, overrides, opts)` | Auto-links `host` / `actor` IDs from opts; merges overrides into the alert template. |
| `sender:ti(story:iocs(), { phase = "..." })` | Replays IOCs declared on `scenario.iocs`. |

---

## 4. Checklist Before Shipping

- [ ] Scenario returns a Lua table with `id`, `name`, `description`, `timing`, `actors`, `hosts`, `mitre`, and (optional) `iocs`.
- [ ] `events` array covers every payload with accurate `source` + `phase` values.
- [ ] `scenario.run` sends events via `sender:hec_event` _and_ updates `story:phase` when phases change.
- [ ] Alerts/TI (if present) call `sender:alert` / `sender:ti` and handle errors (push `story.warnings`).
- [ ] `lua_scenario_runner.py --scenario ...` finishes without traceback and writes an output JSON.
- [ ] For built-ins: scenario ID listed in `/scenarios` API and (optionally) `OOTB_SCENARIOS` metadata.
- [ ] Documented any special instructions for operators (live mode env vars, etc.).

With these steps you can iteratively port every Python scenario—or even arbitrary JSON recordings—into a Lua runbook that’s editable in the Settings UI, executable via Dockerized frontend, and compatible with the alert/TI pipelines.
