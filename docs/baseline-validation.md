# Baseline Validation

Recorded on 2026-10-11 on Windows 11, Python 3.14.2, using the clean audit
environment `backend/.venv-audit/` on branch `audit/ml-hardening`.

## Command

```powershell
cd backend
.venv-audit\Scripts\python -m pytest -q
```

## Result

```text
235 passed, 1 skipped, 1 warning in 54.65s
```

The warning is a Starlette deprecation warning from the installed test-client
compatibility layer (`httpx` integration). The skipped test is part of the
existing suite and was not changed by this audit branch.

This is the frozen application baseline before audit-hardening changes. It
proves the current regression suite passes; it does not prove detector quality
on external data, calibrated probabilities, or production readiness.
