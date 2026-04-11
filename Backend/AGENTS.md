# Repository Guidelines

## Project Structure & Module Organization
- `api/`: FastAPI service (`app/` with `routers/`, `models/`, `services/`, `utils/`).
- `event_generators/`: Scripts that emit sample/security events.
- `parsers/`: Parser definitions and metadata.
- `scenarios/`: Scenario configs used in validation and demos.
- `testing/`: Validation utilities and comprehensive generator tests.
- `docs/`: Project docs and guides.

## Build, Test, and Development
- Setup (recommended):
  - `python3 -m venv .venv && source .venv/bin/activate`
  - `pip install -r api/requirements.txt`
- Run API locally:
  - `python api/start_api.py` (http://localhost:8000)
  - Or: `cd api && uvicorn app.main:app --reload`
- Docker:
  - `docker-compose up --build` (uses `api/Dockerfile`)
  - Manual: `docker build -t jarvis-api -f api/Dockerfile . && docker run -p 8000:8000 jarvis-api`

## Coding Style & Naming Conventions
- Python 3.10+; 4‑space indentation; prefer type hints.
- Use tools pinned in `api/requirements.txt`:
  - Format: `black api`
  - Lint: `flake8 api`
  - Types: `mypy api/app`
- Naming: `snake_case` for files/functions, `PascalCase` for classes, module/package names in lowercase.

## Testing Guidelines
- Framework: `pytest` (+ `pytest-asyncio`, `pytest-cov`).
- Location: `api/tests/` and root‑level `api/test_*.py`.
- Naming: files `test_*.py`, tests `test_*` functions.
- Run: `cd api && pytest tests/`
- Coverage: `pytest tests/ --cov=app --cov-report=html` (HTML at `api/htmlcov/`).

## Commit & Pull Request Guidelines
- Commit style: follow Conventional Commits when possible (`feat:`, `fix:`, `docs:`, `chore:`). Keep messages imperative and scoped.
- Branches: short, hyphenated names (e.g., `feat/parser-download-retries`).
- PRs must include:
  - Clear description and rationale; link issues (e.g., `Closes #123`).
  - Scope of changes (files/areas touched) and testing notes.
  - For API changes, include curl examples and screenshots of `/api/v1/docs` if relevant.

## Security & Configuration
- Never commit secrets. Use `api/.env` (copy from `api/.env.example` via `cp api/.env.example api/.env`).
- Key vars: `DISABLE_AUTH`, `API_KEYS_*`, `SECRET_KEY`, `DATABASE_URL`.
- In Docker, data persists under `api/data/` (mounted to `/app/data`).
- Production: keep `DISABLE_AUTH=false`, use strong keys, configure CORS appropriately.

## Scenario Generation Playbook (Agent Instructions)
Use this workflow whenever creating a new attack scenario under `Backend/scenarios/`.

1) Implement the scenario script
- Create `Backend/scenarios/<scenario_id>.py` in `snake_case` (example: `identity_theft_ransomware_scenario.py`).
- Include profiles (`VICTIM_PROFILE`, `ATTACKER_PROFILE`) and phase/step generators.
- Return a top-level scenario object with:
  - `scenario_name`, `description`, `generated_at`, `total_events`, `events`
  - Each event formatted as: `{"timestamp", "source", "phase", "event"}`
- Save JSON output to `Backend/scenarios/configs/<scenario_id>.json` in `__main__`.

2) Reuse existing generators first
- Prefer functions from `event_generators/` over custom raw payloads.
- Common modules used by scenarios:
  - Endpoint: `event_generators/endpoint_security/sentinelone_endpoint.py`
  - Identity: `event_generators/identity_access/okta_authentication.py`
  - Network: `event_generators/network_security/paloalto_firewall.py`
  - Windows logs: `event_generators/endpoint_security/microsoft_windows_eventlog.py`
- Add new generator logic only if required fields cannot be represented with existing overrides.

3) Correlation-ready scenarios
- If scenario supports SIEM time anchoring, add `CORRELATION_CONFIG` in the scenario module.
- Include:
  - `scenario_id`, `name`, `description`, `default_query`
  - `time_anchors` and `phase_mapping`
  - `fallback_behavior` (typically `offset_from_now`)

4) Register in backend APIs
- Add scenario metadata to:
  - `api/app/services/scenario_service.py` (`self.scenario_templates`)
  - `api/app/routers/scenarios.py` (`/templates` payload)
- If correlation-enabled, also register import/append logic in:
  - `api/app/routers/scenarios.py` under `/correlation`

5) Register in frontend scenario dropdown
- Add scenario entry to `Frontend/log_generator_ui.py` route `GET /scenarios`.
- Ensure `id` exactly matches the scenario filename/module id.
- If the UI should auto-send generated JSON to HEC, include the scenario id in the auto-replay allowlist in `Frontend/log_generator_ui.py`.

6) Verify execution and HEC replay
- Validate import/compile:
  - `python3 -c "from <scenario_module> import <entry_fn>; print('Import OK')"`
- Generate scenario:
  - `python3 Backend/scenarios/<scenario_id>.py`
- Confirm JSON exists at `Backend/scenarios/configs/<scenario_id>.json`.
- Run replay manually if needed:
  - `python3 Backend/scenarios/scenario_hec_sender.py --scenario Backend/scenarios/configs/<scenario_id>.json --auto --preserve-timestamps`

7) Expected operator log signals
- During generation: phase banners + `Total Events` + `Scenario saved to ...`.
- During replay: sender analysis + progress + transmission summary.
- If generation completes but replay does not start, check frontend auto-replay allowlist for missing scenario id.

