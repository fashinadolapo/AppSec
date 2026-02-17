# AppSec Fusion Dashboard

A practical AppSec aggregation platform for collecting SAST, DAST, IaC, container, secrets, cloud posture, and mobile findings into one real-time dashboard.

## What is implemented

- **Unified ingestion API** for SARIF and generic JSON scanner output (`POST /api/ingest/{scanner}`).
- **MCP ingestion endpoint** (`POST /api/mcp/ingest`) so MCP-connected agents/tools can push normalized findings.
- **AI remediation endpoint** (`GET /api/ai/insights`) with:
  - local heuristic prioritization (always available), and
  - optional OpenAI-powered insights when `OPENAI_API_KEY` is set.
- **Live dashboard** with WebSocket refresh showing:
  - scanner/severity summary,
  - finding table with source,
  - AI narrative and prioritized remediation actions.
- **Admin test endpoint** (`POST /api/admin/reset`) to clear in-memory state during tests.

## End-to-end flow supported

1. GitHub Actions runs scanners (CodeQL, Semgrep, SonarQube, Snyk Code, Horusec, ZAP, StackHawk, Nuclei, Trivy, Checkov, Gitleaks, etc.).
2. Workflow uploads or posts outputs to this API in SARIF/JSON.
3. Backend normalizes findings into a common model.
4. Dashboard updates in real time via WebSocket.
5. AI endpoint returns remediation priorities and recommendations.
6. MCP-enabled automation can push additional findings through the MCP ingestion endpoint.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open: `http://127.0.0.1:8000`.

## Optional AI configuration

```bash
export OPENAI_API_KEY=your_key
export OPENAI_MODEL=gpt-4o-mini
```

If no key is provided, the app still returns deterministic local AI insights.

## Test

```bash
pytest -q
```

## GitHub Actions example

See `.github/workflows/security-ingestion-example.yml` for the upload pattern.
