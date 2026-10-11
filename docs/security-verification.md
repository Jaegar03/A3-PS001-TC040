# Security Verification Status

This is an evidence map, not a blanket security certification.

| Control | Evidence | Status / residual risk |
|---|---|---|
| OAuth2 client credentials and scopes | `backend/app/security/auth.py`, `tests/test_auth.py` | Implemented and tested; client secrets are bootstrap/runtime credentials, not user accounts |
| Object-level alert access | alert routes and API tests | Local single-operator demo; no multi-tenant isolation claim |
| Invalid/expired/tampered tokens | `tests/test_auth.py` | Tested; signing-key rotation invalidates all tokens |
| CORS/CSP/security headers | `backend/app/security/headers.py`, `tests/test_security.py` | Implemented; dashboard CSP still permits required inline RSC payloads |
| Request-size limits | `body_limit.py`, `test_hardening.py` | Tested for declared/chunked bodies and uploads |
| Rate limiting | `rate_limit.py`, security tests | In-memory per-process only; proxy/client identity limits are documented |
| Secret handling | `.env`/`.sentivra/` ignored, auth tests | Never commit secrets; development bootstrap prints a one-time secret to local logs |
| Audit log | `audit/service.py`, audit tests | Append-only API path; host compromise can rewrite local SQLite |
| Model hash verification | `backend/app/ml/loader.py`, `test_model_loader.py` | SHA-256 checked before loading; source-control replacement remains out of scope |
| Upload path traversal | upload API and file metadata tests | Bytes are held transiently, filenames are metadata only |
| Archive expansion | `uploads.py`, `test_security.py` | Central-directory caps and nested-depth checks; native parser attack surface remains |
| Provider webhook verification | `tests/test_webhooks.py` | HMAC/secret/JWT paths and replay behavior tested; public deployment/IP allowlist gaps remain |

## Not established by this document

No claim is made that the application is secure against all attacks, that a
detector catches all threats, or that the synthetic model metrics transfer to
real environments.
