# Scientific Validation Report

This report distinguishes executed evidence from work not run.

## Executed and verified in the current checkout

The existing regression suite contains fixture-level tests for file/YARA,
SQL/prompt/URL, network, endpoint/log/Sigma, webhook and risk-engine paths.
The audit branch's earlier reports under `research/evaluation/` record prior
local text/URL and synthetic-network runs, with their checksums, limitations and
commands. Those reports are preliminary evidence, not deployment claims.

## Not sufficient for deployment claims

- SQL positives are largely attack-list data; benign controls are small.
- Prompt benchmark data is small and source/template overlap cannot be ruled
  out from the published split.
- PhiUSIIL legitimate URLs are homepage-heavy and the URL detector has no
  reputation, DNS or page-content signal.
- Network models are trained/evaluated on Sentivra's synthetic generator.
- Endpoint metrics are simulated-fleet results, not live endpoint telemetry.
- No ClamAV, Suricata or Zeek service is configured in this local workspace.

## Blocked or not run

No full public network benchmark, Prompt Guard comparison, production-telemetry
validation, or live-provider exercise was run in this phase. No metric is
reported for those items.
