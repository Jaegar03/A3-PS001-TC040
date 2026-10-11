# Integration Verification

The Gmail, Telegram, and WhatsApp paths are implemented provider-authenticated
webhooks. They are not automatically connected to a provider by code in this
repository. Credentials, provider-side webhook configuration, public HTTPS,
and operational rotation are external setup steps.

Each webhook test suite covers the provider proof, malformed/rejected input,
deterministic provider-event idempotency, redacted body persistence, and the
fact that findings are not echoed to the provider. Message bodies are analyzed
in memory and stored as hashes/metadata only.

osquery and Wazuh are implemented upload/ingest paths. Suricata and Zeek status
is deliberately `Not implemented`: no EVE or Zeek log reader exists in this
build. That status is not a failed configuration; it is an explicit scope
boundary.
