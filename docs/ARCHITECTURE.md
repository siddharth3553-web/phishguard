# Architecture

```
Employee ──► React ──► URL / email / QR scan
                 │              │
                 ▼              ▼
           fused reasons   evidence card
                 │
                 └── report ──► Analyst queue ──► disposition / allowlist
```

| Layer | Responsibility |
| --- | --- |
| `web/` | Employee scan desk + analyst queue |
| `api/` | Auth sessions, scans-as-cases, allowlist, audit |
| `services/predictor.py` | ONNX + skops + intel fusion |
| `services/url_intel.py` / `email_intel.py` / `qr_decode.py` | Rule evidence |
| `db/` + Alembic | Users, scans, allowlist, audit |

Models load once in lifespan. `/ready` requires models **and** DB connectivity. Demo users seed on boot.
