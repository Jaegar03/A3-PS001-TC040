# Capability Matrix (Audit Baseline)

This matrix separates implemented code paths from trained-model validation.
“Implemented” means the path exists and has local tests; it does not mean
real-world detection quality is established.

| Capability | Status | Input | Code path | Existing tests | Metrics/evidence | Limits |
|---|---|---|---|---|---|---|
| File/static malware triage | Implemented, tested | multipart file | `backend/app/api/analyze.py`, `detectors/file/`, YARA/ClamAV | `test_api.py`, detector tests | EICAR/demo regression only | Static only; ClamAV optional; external malware performance not established |
| YARA | Implemented, tested | file bytes | `backend/app/detectors/yara_detector.py` | YARA tests | Rule compilation/fixture behavior | Missing engine must not be interpreted as clean |
| ClamAV | External dependency | file bytes | `backend/app/detectors/clamav_detector.py` | availability/error tests | None when clamd absent | Requires locally configured clamd |
| SQL/NoSQL injection | Implemented, tested; rules/lexical | bounded text | `backend/app/detectors/sqli_detector.py` | `test_text_detectors.py`, API tests | Handwritten fixture behavior | No trained classifier; dialect and second-order limits |
| Prompt injection | Implemented, tested; heuristic | bounded text/messages | `backend/app/detectors/prompt_detector.py` | `test_text_detectors.py`, API/webhook tests | Handwritten fixture behavior | No trained classifier; language and novel-phrasing limits |
| URL threat triage | Implemented, tested; local heuristic | URL/message URLs | `backend/app/detectors/url_detector.py` | `test_text_detectors.py`, API/webhook tests | Handwritten fixture behavior | No fetch, DNS, reputation or trained URL model |
| Network anomaly | Prototype-simulated | flow CSV/PCAP/demo | `backend/app/detectors/network/`, suite | network API/model tests | Synthetic report only | Real-world/public-data validation absent |
| Endpoint/log rules | Implemented, tested on simulator/fixtures | osquery/Wazuh/log batches | `detectors/endpoint/`, `sigma/`, `logs/` | endpoint/log/Sigma tests | Simulated fleet report only | No endpoint ML; native agent absent |
| Gmail webhook | Implemented, externally configured | provider webhook | `backend/app/integrations/gmail/` | webhook tests | Verification/redaction/idempotency tests | Requires Google OAuth/Pub/Sub and public HTTPS |
| Telegram webhook | Implemented, externally configured | provider webhook | `backend/app/integrations/telegram/` | webhook tests | Secret verification/redaction/idempotency tests | Bot sees only updates Telegram delivers |
| WhatsApp webhook | Implemented, externally configured | provider webhook | `backend/app/integrations/whatsapp/` | webhook tests | HMAC/handshake/redaction/idempotency tests | Requires Meta setup and public HTTPS |
| Suricata/Zeek ingestion | Planned-not-wired | EVE/Zeek logs | integration status only | status tests | No ingestion evidence | Explicitly out of scope for this audit scope |
| Automated remediation | Planned-not-wired | — | `docs/future-automation.md` only | none | none | No autonomous actions |
