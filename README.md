# AppSec Fusion Dashboard (PaaS-ready baseline)

A production-oriented baseline for aggregating AppSec findings (SAST, DAST, IaC, container, secrets, cloud posture, and mobile) into one dashboard.

## What makes this production-grade baseline

- Persistent **SQL database** via SQLAlchemy (`DATABASE_URL`) with PostgreSQL support.
- **OIDC login support** (Okta/Azure AD/Auth0/any OIDC provider) and role-based access control.
- Ingestion **API key protection** (`INGEST_API_KEY`) for machine-to-machine scanner/MCP write endpoints.
- Deduplication using deterministic finding fingerprints.
- Health probes for PaaS orchestration:
  - `GET /healthz`
  - `GET /readyz`
- Paged findings API (`limit`, `offset`) for scalable frontend/API clients.
- CORS configuration through `CORS_ALLOW_ORIGINS`.
- Optional OpenAI-powered insights with deterministic local fallback.

## Role-based access model

- `viewer`: dashboard + read APIs
- `ingestor`: ingestion endpoints (unless valid `x-api-key` matches `INGEST_API_KEY`)
- `admin`: destructive admin endpoints

Defaults can be changed with env vars: `VIEWER_ROLE`, `INGESTOR_ROLE`, `ADMIN_ROLE`, `ROLE_CLAIM`.

## Endpoints

- `GET /` dashboard UI (viewer)
- `GET /api/me` identity + roles (viewer)
- `GET /api/findings?limit=100&offset=0` (viewer)
- `POST /api/ingest/{scanner}` (ingestor or API key)
- `POST /api/mcp/ingest` (ingestor or API key)
- `GET /api/ai/insights` (viewer)
- `DELETE /api/admin/findings` (admin)
- `GET /auth/login` (OIDC login start)
- `GET /auth/callback` (OIDC callback)
- `GET /auth/logout` (clear local session)
- `GET /healthz`
- `GET /readyz`
- `WS /ws`

## Environment variables

- `DATABASE_URL` (default: `sqlite:///./appsec.db`)
- `AUTH_MODE` (`disabled` or `oidc`)
- `SESSION_SECRET_KEY` (required in OIDC mode)
- `OIDC_DISCOVERY_URL` (OIDC metadata URL)
- `OIDC_CLIENT_ID`
- `OIDC_CLIENT_SECRET`
- `OIDC_SCOPES` (default `openid profile email`)
- `ROLE_CLAIM` (default `roles`; also supports `groups`/`scp`/`scope`)
- `VIEWER_ROLE` (default `viewer`)
- `INGESTOR_ROLE` (default `ingestor`)
- `ADMIN_ROLE` (default `admin`)
- `INGEST_API_KEY` (recommended for CI scanners)
- `CORS_ALLOW_ORIGINS` (default `*`, comma-separated)
- `OPENAI_API_KEY` (optional)
- `OPENAI_MODEL` (default `gpt-4o-mini`)

## Local run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Test

```bash
pytest -q
```

## PaaS deployment notes

Use a managed Postgres and set `DATABASE_URL` + `INGEST_API_KEY` in your platform secrets.
Enable OIDC by setting `AUTH_MODE=oidc` and the OIDC client settings.


## Security hardening implemented

- WebSocket access check at `/ws` (viewer role required).
- Secure session cookies in OIDC mode (`SESSION_HTTPS_ONLY`, defaults to `true` for production).
- Security headers middleware (`X-Frame-Options`, `X-Content-Type-Options`, HSTS on HTTPS, etc.).
- Rate limiting + payload size enforcement for ingest endpoints (`INGEST_RATE_LIMIT_PER_MIN`, `INGEST_MAX_BODY_BYTES`).
- Audit logging for auth, ingestion, admin, and chaos updates (`LOG_LEVEL` configurable).
- CSRF protection for browser-session state-changing flows (OIDC mode) via `x-csrf-token` from `/api/me`.

## Chaos Engineering

- Admin-only chaos page: `GET /chaos`.
- Admin API controls: `GET /api/admin/chaos`, `POST /api/admin/chaos`.
- Chaos modes:
  - request latency injection (`latency_ms`)
  - random error injection (`error_percent`)
  - on/off toggle (`enabled`)
- Chaos affects API routes while excluding chaos-control endpoints.
