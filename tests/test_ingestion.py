import json

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_end_to_end_ingestion_and_ai_insights():
    client.post("/api/admin/reset")

    generic_data = [
        {
            "severity": "high",
            "title": "Hardcoded secret",
            "file": "src/config.py",
            "line": 10,
            "recommendation": "Use a secrets manager",
        }
    ]

    generic_res = client.post(
        "/api/ingest/gitleaks",
        files={"file": ("report.json", json.dumps(generic_data), "application/json")},
    )

    assert generic_res.status_code == 200
    assert generic_res.json()["ingested"] == 1

    sarif_report = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {
                                "id": "python/sql-injection",
                                "name": "Potential SQL injection",
                                "shortDescription": {"text": "Use parameterized queries"},
                            }
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": "python/sql-injection",
                        "level": "error",
                        "message": {"text": "User-controlled input reaches SQL query"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "api/db.py"},
                                    "region": {"startLine": 42},
                                }
                            }
                        ],
                    }
                ],
            }
        ]
    }

    sarif_res = client.post(
        "/api/ingest/codeql",
        files={"file": ("codeql.sarif", json.dumps(sarif_report), "application/json")},
    )
    assert sarif_res.status_code == 200
    assert sarif_res.json()["ingested"] == 1

    mcp_res = client.post(
        "/api/mcp/ingest",
        json={
            "source": "mcp",
            "scanner": "checkov-mcp",
            "findings": [
                {
                    "severity": "medium",
                    "title": "S3 bucket versioning disabled",
                    "file": "terraform/s3.tf",
                    "line": 11,
                    "recommendation": "Enable versioning on state/data buckets",
                }
            ],
        },
    )
    assert mcp_res.status_code == 200
    assert mcp_res.json()["ingested"] == 1

    findings = client.get("/api/findings").json()
    assert findings["summary"]["total"] == 3
    assert findings["summary"]["by_scanner"]["gitleaks"] == 1
    assert findings["summary"]["by_scanner"]["codeql"] == 1
    assert findings["summary"]["by_scanner"]["checkov-mcp"] == 1

    insights = client.get("/api/ai/insights")
    assert insights.status_code == 200
    body = insights.json()
    assert body["provider"] in {"local-heuristic", "openai"}
    assert "actions" in body
    assert len(body["actions"]) >= 1
