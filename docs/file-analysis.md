# File Analysis Verification

The file path is static triage only. It hashes bytes, inspects magic/type,
entropy and metadata, checks configured archive limits, and invokes YARA and
ClamAV only when available. Uploaded files are never executed. The transient
blob store is discarded in the API `finally` path after detector execution.

Evidence is limited to safe fixtures: benign bytes, malformed/extension-
mismatch content, archive limit cases, and the EICAR antivirus test string.
EICAR is a standard harmless test string, not malware.

Missing YARA/ClamAV is an explicit availability/degraded state. It must not be
read as proof that a file is clean. The structured detector status contract is
covered by `backend/tests/test_failure_semantics.py`.
