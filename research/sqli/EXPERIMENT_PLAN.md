# SQL Injection Experiment Plan

## Hypothesis

The existing normalized rule and lexical detector will catch high-signal SQLi
payloads with fewer false positives than a character TF-IDF classifier trained
on attack-only lists plus authored benign controls. A classifier is not shipped
unless it improves the predeclared held-out objective.

## Data and split

- Positive sources: local SecLists SQLi files listed in `raw/MANIFEST.json`.
- Negative controls: small hand-authored examples covering ordinary prose,
  SQL documentation, legitimate SQL, URLs, error messages, and code snippets.
- Source files are split by transformation/source family; generated variants
  never cross a split boundary.
- The first benchmark is an evidence baseline, not a claim about production
  traffic. Attack-only public sources and hand-authored negatives are a known
  sampling limitation.

## Metrics and budget

Primary: recall at FPR <= 1% on the held-out split. Secondary: precision, F1,
PR-AUC, confusion matrix, p50/p95 CPU latency, and model size. Thresholds are
selected on validation only. A rules-only baseline, ML-only baseline, and
hybrid disagreement table are reported separately.

## Release rule

Keep the existing rules as the primary signal unless the hybrid beats rules-only
on the held-out objective without leakage. A negative result is retained.
