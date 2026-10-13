# Alert Quality and Telemetry Health

## Alert quality

Alerts begin with `disposition = null`, represented as `PENDING_REVIEW` in
metrics. An analyst may record one of:

- `TRUE_POSITIVE`
- `FALSE_POSITIVE`
- `BENIGN_INTERESTING`
- `DUPLICATE`

The existing alert status workflow remains separate from disposition. A status
change is still audited, and disposition metadata records the actor, note and
time in the alert row.

`GET /api/v1/metrics` reports the selected observation window's generated,
reviewed and pending counts, plus disposition counts. `reviewed_false_share` is
false-positive dispositions divided by reviewed alerts. It is **not** a
ground-truth false-positive rate because unreviewed alerts and unknown negative
cases are not in its denominator.

Example:

```json
{"status":"RESOLVED","disposition":"FALSE_POSITIVE","note":"Benign test fixture"}
```

## Telemetry health

The Integrations and Health APIs are capability/readiness views, not proof of
continuous telemetry. `Available` means an implemented input path is ready;
`Connected` means a configured messaging webhook has delivered at least one
event; `Not configured` means credentials/path are missing; `Not implemented`
means no reader exists. Endpoint demo data is `SIMULATED`, bundled network demo
data is `DEMO_DATA`, and uploaded/provider input is `LIVE`.

There is no universal heartbeat for file uploads, PCAP uploads, or webhook
providers in this local architecture. Therefore absence of a recent event is
reported as no observed data, not as a fabricated stale/healthy verdict.
Suricata and Zeek remain `Not implemented`, and native endpoint telemetry is
not available.
