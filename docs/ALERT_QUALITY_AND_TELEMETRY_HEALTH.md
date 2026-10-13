# Alert Quality and Telemetry Health

Alerts begin with `disposition = null`, represented as `PENDING_REVIEW` in
metrics. Analysts may record `TRUE_POSITIVE`, `FALSE_POSITIVE`,
`BENIGN_INTERESTING`, or `DUPLICATE`. Status and disposition remain separate;
status changes are audited and disposition metadata records actor, note and
time.

`GET /api/v1/metrics` reports generated, reviewed and pending counts plus
disposition counts. `reviewed_false_share` is false-positive dispositions
divided by reviewed alerts. It is not a ground-truth false-positive rate.

Telemetry readiness is reported honestly: available means an implemented input
path is ready, connected means a configured webhook has delivered an event,
and no observed data is not treated as a fabricated healthy/stale heartbeat.
Simulated, demo and live sources remain explicitly labeled.
