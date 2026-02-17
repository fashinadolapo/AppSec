import importlib
import json
import os
from pathlib import Path

from fastapi.testclient import TestClient


def test_end_to_end_ingestion_and_ai_insights(tmp_path: Path):
    db_path = tmp_path / "test.db"
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    os.environ["INGEST_API_KEY"] = "test-key"
    os.environ["AUTH_MODE"] = "disabled"

    import app.main as main

    importlib.reload(main)
    client = TestClient(main.app)

    reset = client.delete("/api/admin/findings")
    assert reset.status_code == 200

    generic_data = [{"severity": "high", "title": "Hardcoded secret", "file": "src/config.py", "line": 10, "recommendation": "Use a secrets manager"}]
    generic_res = client.post(
        "/api/ingest/gitleaks",
        files={"file": ("report.json", json.dumps(generic_data), "application/json")},
        headers={"x-api-key": "test-key"},
    )
    assert generic_res.status_code == 200
    assert generic_res.json()["ingested"] == 1

    sarif_report = {
        "runs": [{
            "tool": {"driver": {"rules": [{"id": "python/sql-injection", "name": "Potential SQL injection", "shortDescription": {"text": "Use parameterized queries"}}]}},
            "results": [{"ruleId": "python/sql-injection", "level": "error", "message": {"text": "User-controlled input reaches SQL query"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "api/db.py"}, "region": {"startLine": 42}}}]}],
        }]
    }
    sarif_res = client.post(
        "/api/ingest/codeql",
        files={"file": ("codeql.sarif", json.dumps(sarif_report), "application/json")},
        headers={"x-api-key": "test-key"},
    )
    assert sarif_res.status_code == 200

    mcp_res = client.post(
        "/api/mcp/ingest",
        json={"source": "mcp", "scanner": "checkov-mcp", "findings": [{"severity": "medium", "title": "S3 bucket versioning disabled", "file": "terraform/s3.tf", "line": 11, "recommendation": "Enable versioning"}]},
        headers={"x-api-key": "test-key"},
    )
    assert mcp_res.status_code == 200

    findings = client.get("/api/findings?limit=10&offset=0")
    assert findings.status_code == 200
    body = findings.json()
    assert body["summary"]["total"] == 3

    insights = client.get("/api/ai/insights")
    assert insights.status_code == 200
    assert insights.json()["provider"] in {"local-heuristic", "openai"}

    assert client.get("/api/me").status_code == 200
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code == 200

    unauthorized = client.post(
        "/api/mcp/ingest",
        json={"source": "mcp", "scanner": "x", "findings": []},
        headers={"x-api-key": "wrong"},
    )
    assert unauthorized.status_code == 401


def test_extract_roles_from_multiple_claim_shapes(tmp_path: Path):
    db_path = tmp_path / "roles.db"
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    os.environ["AUTH_MODE"] = "disabled"

    import app.main as main

    importlib.reload(main)
    roles = main.extract_roles({"roles": ["viewer", "admin"], "scp": "ingestor audit", "groups": ["soc"]})
    assert {"viewer", "admin", "ingestor", "audit", "soc"}.issubset(roles)
