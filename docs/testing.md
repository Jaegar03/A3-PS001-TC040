# Testing and CI

Everything documented here was executed against this repository on 2026-10-12 (Windows 11, backend `.venv` on Python 3.14, frontend on Node with `package-lock.json`). CI runs the same commands on Ubuntu with Python 3.12 and Node 22.

## Backend

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate    |    macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

- **No external service is required.** `backend/tests/conftest.py` creates a temporary SQLite database (`SENTIVRA_DATABASE_URL`), a temporary state directory, and explicit test clients with fixed test-only secrets. It never touches your `./sentivra.db` or `.sentivra/`, and it needs no real credentials.
- **ClamAV is optional.** No test requires `clamd`; `test_failure_semantics.py` pins the behaviour when it is missing (partial result, never a clean scan).
- **No network egress is required.** Webhook tests exercise Gmail/Telegram/WhatsApp verification with local fixtures; URL analysis is offline by design.
- The one skip on Windows is `test_auth.py`'s POSIX file-mode-bit case (state-file permissions cannot be reproduced on NTFS/ACLs); it runs on Linux CI.
- Lint: `ruff check .` (configured in `backend/pyproject.toml`).

## Frontend

```bash
cd frontend
npm ci                # or npm install
npm run lint          # eslint
npm run build         # production build (Next.js)
npx tsc --noEmit      # type check (needs the route types the build generates)
```

There is no frontend test framework in this repository; the checks above are the automated ones that exist. The dashboard needs a running backend to *display* data, but none of these checks contact it.

## Continuous integration

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs on:

- pushes to `master` or `main`;
- pull requests targeting `master` or `main`;
- manual dispatch (`workflow_dispatch`).

Two parallel jobs, least-privilege (`permissions: contents: read`), no secrets, no external services:

| Job | Steps |
|---|---|
| Backend | `pip install -e ".[dev]"` → `ruff check .` → `pytest -q` |
| Frontend | `npm ci` → `npm run lint` → `npx tsc --noEmit` → `npm run build` |

**Before merging:** both jobs must pass. A red check must not be ignored or re-run until it happens to go green; fix the cause.

## Synthetic and simulated data in tests

Several detectors are evaluated only on synthetic/simulated data, and their tests say so:

- `test_network.py` / `test_network_api.py` — synthetic flow samples, bundled fixtures and `DEMO_DATA` labels; they verify the pipeline and calibration behaviour, **not** real-traffic detection quality.
- `test_endpoint.py` / `test_endpoint_api.py` / `test_osquery.py` — osquery fixtures and the simulated fleet; they verify parsing, rules and labelling, not live endpoint ingestion.
- `test_text_detectors.py` / `test_text_analysis_api.py` — detection fixtures for the SQL-injection, prompt-injection and URL heuristics, including benign false-positive regressions; these detectors' optional ML artifacts are untrained (see [model-card.md](model-card.md)).

Real-dataset training and evaluation live under `research/` and are **not** part of CI: they need downloaded datasets and are deliberately run by hand.
