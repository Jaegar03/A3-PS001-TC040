# Reviewer Pack

## What is truly end to end

- File analysis: upload → static metadata/YARA/optional ClamAV → shared risk
  engine → persisted redacted evidence. Safe EICAR/benign fixtures and API
  tests exercise this path.
- Network demo/upload: flow parse → behavior/statistical/model layers →
  fusion → risk engine. The committed model evidence is synthetic only.
- SQL, prompt, and URL analysis: bounded input → local rule/heuristic detector
  → shared risk engine → alert. The local benchmark is in
  `research/evaluation/text/`; no optional text ML model is promoted.
- Webhooks: provider verification → normalization → in-memory detection →
  redacted persistence → audit. Provider configuration and public HTTPS are
  external requirements.

## Reproduction commands

```powershell
backend\.venv-audit\Scripts\python -m pytest -q
backend\.venv-audit\Scripts\python research\experiments\evaluate_text_detectors.py
backend\.venv-audit\Scripts\python research\experiments\evaluate_url_detector.py
backend\.venv-audit\Scripts\python research\run_all.py --network-synthetic
cd frontend; npm run lint; npx tsc --noEmit; npm run build
```

## Honest headline measurements

See `docs/detector-evaluation-report.md` and the JSON reports for dataset
checksums, splits and complete confusion matrices. The most important negative
results are prompt rules recall 0.0667 on the downloaded deepset test split,
the prompt TF-IDF baseline recall 0.0167 at the selected 1% FPR threshold, and
the SQL TF-IDF baseline recall 0.0938 against rules recall 1.0 on an attack-list
benchmark. These do not justify shipping ML as the primary detector.

The synthetic network rerun measured fused models precision 0.915, recall
0.849, F1 0.881, FPR 0.0070; fused models plus behavior rules measured
precision 0.927, recall 1.000, F1 0.962, FPR 0.0070. These numbers are not
real-traffic evidence.

## Explicitly out of scope

No Suricata/Zeek ingestion, native endpoint agent, automated remediation,
multi-tenant isolation, or production deployment infrastructure was added.
No external data is committed; all raw dataset directories are gitignored.
