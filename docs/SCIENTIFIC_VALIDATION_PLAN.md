# Scientific Validation Plan

## Scope

This phase evaluates existing SQL injection, prompt-injection, URL, network,
file, log/host and webhook paths without adding detector categories. A source
path is not called validated merely because it exists or raises a demo alert.

## Evidence levels

1. Source implementation exists.
2. Local execution succeeds.
3. Safe fixture behavior is regression-tested.
4. A held-out dataset evaluation exists with documented labels/splits.
5. Results are reproducible from a recorded command, version and checksum.
6. Representative operational telemetry validation exists.

The current checkout reaches levels 1–3 for most detectors. Text evaluation
reports exist for local Phase-4 datasets, but the small/attack-list datasets
do not establish production effectiveness. Network model metrics are synthetic
only. No representative live endpoint, provider, Suricata or Zeek telemetry is
available.

## Evaluation policy

- Deduplicate exact and normalized payloads before splitting.
- Group related transformations/templates when metadata exists.
- Fit learned preprocessing and choose thresholds on train/validation only.
- Score the final test set once and report confusion counts plus continuous-score
  PR-AUC where available.
- Preserve rule-only, ML-only and hybrid provenance.
- Never download or execute malware; use EICAR and authored fixtures only.
- Never contact submitted URLs or external services during detector evaluation.

## Current experiments

| Detector | Executed evidence | Status |
|---|---|---|
| SQL injection | Existing rules/lexical fixtures and prior local comparison report | Preliminary; attack-list benchmark, not operational FPR |
| Prompt injection | Existing heuristic fixtures and prior local comparison report | Preliminary; small publisher dataset |
| URL | Local parser/heuristic fixtures and prior local comparison report | Preliminary; sampled PhiUSIIL, no fetch/reputation |
| Network | Synthetic generator training/evaluation report | Pipeline demonstration, not real-traffic validation |
| Endpoint/host/log | Simulator and parser tests | Simulated/fixture evidence only |
| File/YARA/ClamAV | Safe fixture and availability tests | ClamAV operational status depends on local configuration |

Public CICIDS2017/UNSW-NB15 validation remains unverified until the dataset
access, compatibility and local resource plan is resolved.
