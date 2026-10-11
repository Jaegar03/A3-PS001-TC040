# Hostile-Review Audit Triage

This triage checks the concerns in the audit brief against the current checkout.
Statuses mean:

- **CONFIRMED** — code/docs/tests provide direct evidence of the concern.
- **PARTIAL** — one layer addresses it, but the acceptance evidence is incomplete.
- **NOT APPLICABLE** — the audit claim does not match this checkout, with evidence.

| Finding | Status | Evidence in this checkout | Required follow-up |
|---|---|---|---|
| Network metrics are only synthetic | CONFIRMED | `models/network/*/metadata.json`, `research/evaluation/network/report.json`, and `docs/model-card.md` identify Sentivra synthetic flows. No public-data training/evaluation script exists. | Obtain/prepare CICIDS2017 and UNSW-NB15 only when licensing/access and local storage are resolved; report negative results honestly. |
| SQLi detector is rules/lexical only | CONFIRMED | `backend/app/detectors/sqli_detector.py` loads `detection-rules/custom/sql_injection.yaml` and the lexer/normalizer; `models/sql_injection/classifier/` has no `metadata.json`. | Build a labeled, grouped benchmark and compare frozen rules against classical ML; do not ship an ML model without release-gate evidence. |
| Prompt detector is heuristic only | CONFIRMED | `backend/app/detectors/prompt_detector.py` uses regex and Unicode inspection; `models/prompt/prompt_injection/` has no trained artifact metadata. | Score the current rules on a licensed, grouped benchmark; log gated/reference-model access limitations. |
| URL detector is local heuristic only | CONFIRMED | `backend/app/detectors/url_detector.py` parses without network access; `models/phishing/url_model/` has no `metadata.json`. | Keep local-only behavior; evaluate only with a documented, licensed dataset if obtainable. |
| README/docs overstate detector completeness | PARTIAL | Runtime paths exist, but `docs/architecture.md` still describes planned ML layers and `docs/api.md` contains stale webhook example text. | Correct claims after evidence artifacts are written; keep rule/heuristic implementation distinct from trained-model status. |
| “No finding” may look like “safe” when a dependency is unavailable | CONFIRMED | `YaraDetector.analyze()` and `ClamAVDetector.analyze()` return SAFE-shaped results when unavailable or missing input; availability is separately reported. | Add explicit detector status/failure semantics without breaking the existing public contract; add regression tests and UI wording. |
| Detector exceptions are swallowed by the pipeline | CONFIRMED | `backend/app/services/pipeline.py::_run_one` catches `Exception`, logs it, and returns `None`; the aggregate can become SAFE if all detectors fail. | Add degraded/unknown analysis metadata and tests so failure cannot become benign. |
| Risk engine can double-count correlated findings | PARTIAL | `backend/app/risk/engine.py` uses category-level corroboration but does not carry shared evidence provenance or deduplicate same-source findings. | Add tests first; make the smallest evidence-backed aggregation correction. |
| File scanner limits/timeouts/cleanup need audit evidence | PARTIAL | Upload/body limits and blob discard paths exist and have tests, but a complete timeout/cleanup matrix is not documented. | Add focused safe fixtures and evidence report. |
| Webhook verification/replay/redaction | PARTIAL | Provider verification, deterministic IDs, duplicate handling, and redaction have tests in `backend/tests/test_webhooks.py`. Rate-limit, DB-failure, malformed/oversized and log-redaction coverage is not fully mapped. | Add only missing safe tests; no provider secrets or real messages. |
| Suricata/Zeek ingestion | CONFIRMED | `backend/app/api/integrations.py` returns `Not implemented`; no ingestion module exists. | Leave planned; do not expand scope. |
| Native endpoint agent | CONFIRMED | `endpoint-agent/README.md` says native agent is future; current code accepts osquery/Wazuh/simulator inputs. | Leave planned; do not add endpoint ML or native agent. |
| Automation/remediation | CONFIRMED | `docs/future-automation.md` is design-only; no executor exists. | Leave out of scope. |
| Public-data access/licensing constraints | PARTIAL | Several requested sources require account/license acceptance or have unclear dataset terms; no audit branch data has been downloaded. | Record blockers in `docs/OPEN_QUESTIONS.md`; never bypass registration or license acceptance. |
