# Security

## Threat model

Local/demo report-and-investigate service. Not hardened for open internet without an edge proxy.

## Controls

- Cookie sessions (`httponly`, `samesite=lax`) + bcrypt passwords — not JWT.
- Roles: `employee` | `analyst`.
- Optional `X-API-Key` for machine clients.
- Pydantic validation, body size cap, per-IP rate limit.
- CORS allowlist with credentials.
- OpenAPI disabled when `ENVIRONMENT=production`.
- Models and allowlist only from configured paths / DB — never from untrusted uploads as model weights.
- QR images decoded in-process; no remote browser.

## Model artifacts

URL → ONNX Runtime; email → skops with trusted types. Fusion rules add explainable `reasons[]`.

## Out of scope

TLS, WAF, IdP SSO, Microsoft Graph ingest, AiTM session detection.
