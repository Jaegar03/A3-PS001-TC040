# Controlled Purple-Team Validation Report

Only local benign fixtures and bundled simulated data are in scope. Existing
tests exercise SQL injection, benign SQL, prompt override, URL heuristics,
EICAR, synthetic network anomalies, simulated endpoint events, webhook proof
and replay handling, unavailable ClamAV, and detector failure semantics.

No real endpoint agent, live provider, public capture, real malware, live
phishing URL or destructive operating-system scenario was executed. Fixtures
are request- or test-database-scoped and no external system was modified.
