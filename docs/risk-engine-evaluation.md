# Risk Engine Evaluation

## Current policy

`backend/app/risk/engine.py` computes each finding's contribution as:

```text
score × confidence × category reliability weight
```

The aggregate uses the maximum contribution, then adds a bounded corroboration
boost only when two or more distinct detector categories are at least MEDIUM.
This avoids adding two findings from the same detector category as independent
evidence. `risk_score` is a heuristic score from 0–100, not a probability.

## Evidence run

```powershell
cd backend
.venv-audit\Scripts\python -m pytest -q tests/test_risk_engine.py tests/test_failure_semantics.py
```

Result on 2026-10-11:

```text
13 passed in 0.77s
```

The tests cover no findings, a single weak finding, a strong single finding,
cross-category corroboration, duplicate same-category findings, evidence
schema enforcement, non-probability labeling, missing scanner state, and a
detector exception. A failed detector yields `analysis_status=partial_analysis`
and an explicit error list; it is not converted to a benign detector result.

## Remaining limitation

The current schema does not carry a formal shared-evidence graph between
detectors. Same-category duplicates are not boosted, but two different
categories that independently quote the same underlying fact could still
receive corroboration. A future change should add evidence provenance before
attempting more complex correlation; no such unmeasured change is shipped by
this branch yet.
