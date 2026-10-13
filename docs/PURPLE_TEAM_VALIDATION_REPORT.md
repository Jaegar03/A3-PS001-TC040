# Controlled Purple-Team Validation Report

## Scope and authorization

Only local, benign fixtures and bundled synthetic/simulated data are in scope.
No public service, real account, real malware, live phishing URL or outbound
message was contacted.

## Scenario inventory

| Scenario | Required telemetry | Expected outcome | Result |
|---|---|---|---|
| SQL injection fixture | Direct analyze API | SQL rule/lexical finding and alert | Executed by existing text detector/API tests; fixture evidence only |
| Benign SQL prose | Direct analyze API | No SQLi finding | Executed by regression fixtures; not a production FPR estimate |
| Prompt override fixture | Direct analyze API | Prompt finding and alert | Executed by existing prompt/API tests |
| URL heuristic fixture | Direct analyze API | Local URL evidence; no network request | Executed by URL tests; no reputation claim |
| EICAR fixture | File upload/YARA | Safe antivirus-test signature finding | Executed by file/YARA/API tests; EICAR is not malware |
| Synthetic network anomalies | Bundled DEMO_DATA generator | Rules/model fusion findings | Executed by network demo tests; synthetic only |
| Simulated endpoint fleet | SIMULATED endpoint demo | Host/Sigma/auth rule findings | Executed by endpoint tests; not live telemetry |
| Webhook verification/replay | Provider-shaped local fixtures | Reject invalid proof; deduplicate valid replay | Executed by webhook tests; no provider connection |
| Missing ClamAV | No clamd configuration | Partial/unavailable state, not clean scan | Executed by failure-semantics tests |
| Detector exception | Injected test detector | Partial analysis, not benign success | Executed by failure-semantics tests |

## Not executed

No real endpoint agent, live provider webhook, Suricata/Zeek reader, public
network capture, real malware, or destructive operating-system scenario was
executed. These are unavailable or outside the authorized local scope.

## ATT&CK interpretation

Existing rule mappings are retained only where the rule input and evidence
support them. A scenario or mapping in the code is not counted as demonstrated
coverage when the required telemetry was simulated, absent or not executed.

## Cleanup

Fixtures are request-scoped or test-database scoped. No real database,
credential, provider account or external system was modified.
