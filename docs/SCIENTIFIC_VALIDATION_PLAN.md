# Scientific Validation Plan

Evaluate existing SQL injection, prompt-injection, URL, network, file, log/host
and webhook paths without adding detector categories. Evidence must distinguish
implementation, local execution, fixture regression, held-out evaluation and
representative telemetry.

Evaluation rules: deduplicate before splitting; group transformations when
metadata exists; fit preprocessing and choose thresholds on train/validation
only; report confusion counts and continuous-score metrics; preserve rule-only,
ML-only and hybrid provenance; use only safe local fixtures; never fetch URLs
or execute malware.

Current evidence is primarily levels 1–3, with preliminary local text/URL and
synthetic-network reports. No live endpoint, provider, Suricata or Zeek
telemetry is available in this workspace.
