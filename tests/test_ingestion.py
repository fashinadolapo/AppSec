import importlib
import json
import os
from pathlib import Path

from fastapi.testclient import TestClient


def load_app(db_path: Path, auth_mode: str = "disabled", api_key: str = "test-key"):
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    os.environ["INGEST_API_KEY"] = api_key
    os.environ["AUTH_MODE"] = auth_mode
    os.environ["INGEST_RATE_LIMIT_PER_MIN"] = "1000"
    os.environ["INGEST_MAX_BODY_BYTES"] = str(1024 * 1024)

    import app.main as main

    importlib.reload(main)
    return main, TestClient(main.app)


def test_end_to_end_ingestion_and_security_baseline(tmp_path: Path):
    _, client = load_app(tmp_path / "test.db")

    reset = client.delete("/api/admin/findings")
    assert reset.status_code == 200

    generic_data = [{"severity": "high", "title": "Hardcoded secret", "file": "src/config.py", "line": 10, "recommendation": "Use a secrets manager"}]
    generic_res = client.post(
        "/api/ingest/gitleaks",
        files={"file": ("report.json", json.dumps(generic_data), "application/json")},
        headers={"x-api-key": "test-key"},
    )
    assert generic_res.status_code == 200

    findings = client.get("/api/findings?limit=10&offset=0")
    assert findings.status_code == 200
    assert findings.json()["summary"]["total"] >= 1

    me = client.get("/api/me")
    assert me.status_code == 200
    assert "csrf_token" in me.json()

    unauthorized = client.post(
        "/api/mcp/ingest",
        json={"source": "mcp", "scanner": "x", "findings": []},
        headers={"x-api-key": "wrong"},
    )
    assert unauthorized.status_code == 401


def test_rate_limit_and_payload_limit(tmp_path: Path):
    os.environ["DATABASE_URL"] = f"sqlite:///{tmp_path / 'limits.db'}"
    os.environ["INGEST_API_KEY"] = "test-key"
    os.environ["AUTH_MODE"] = "disabled"
    os.environ["INGEST_RATE_LIMIT_PER_MIN"] = "1"
    os.environ["INGEST_MAX_BODY_BYTES"] = "10"

    import app.main as main

    importlib.reload(main)
    client = TestClient(main.app)

    too_big = client.post(
        "/api/ingest/gitleaks",
        files={"file": ("report.json", json.dumps([{"title": "x"}]), "application/json")},
        headers={"x-api-key": "test-key", "content-length": "100"},
    )
    assert too_big.status_code == 413

    os.environ["INGEST_MAX_BODY_BYTES"] = str(1024 * 1024)
    importlib.reload(main)
    client = TestClient(main.app)

    first = client.post(
        "/api/mcp/ingest",
        json={"source": "mcp", "scanner": "ok", "findings": []},
        headers={"x-api-key": "test-key"},
    )
    assert first.status_code in {200, 422}

    second = client.post(
        "/api/mcp/ingest",
        json={"source": "mcp", "scanner": "ok", "findings": []},
        headers={"x-api-key": "test-key"},
    )
    assert second.status_code == 429


def test_chaos_admin_api(tmp_path: Path):
    _, client = load_app(tmp_path / "chaos.db")

    current = client.get("/api/admin/chaos")
    assert current.status_code == 200

    token = client.get("/api/me").json().get("csrf_token")
    updated = client.post(
        "/api/admin/chaos",
        json={"enabled": True, "latency_ms": 5, "error_percent": 0},
        headers={"x-csrf-token": token},
    )
    assert updated.status_code == 200
    assert updated.json()["enabled"] is True

    no_csrf = client.post(
        "/api/admin/chaos",
        json={"enabled": False, "latency_ms": 0, "error_percent": 0},
    )
    # in disabled auth mode csrf is bypassed by design for local/dev, so this remains 200
    assert no_csrf.status_code == 200


def test_scanner_connector_pack_parsing(tmp_path: Path):
    _, client = load_app(tmp_path / "connectors.db")

    semgrep_report = {
        "results": [
            {
                "check_id": "python.lang.security.audit.eval",
                "path": "app/service.py",
                "start": {"line": 12},
                "extra": {"severity": "ERROR", "message": "Avoid eval", "metadata": {"fix": "Use safe parser"}},
            }
        ]
    }
    r1 = client.post(
        "/api/ingest/semgrep",
        files={"file": ("semgrep.json", json.dumps(semgrep_report), "application/json")},
        headers={"x-api-key": "test-key"},
    )
    assert r1.status_code == 200
    assert r1.json()["ingested"] == 1

    trivy_report = {
        "Results": [
            {
                "Target": "alpine:3.18",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-0001",
                        "Severity": "HIGH",
                        "Title": "openssl issue",
                        "Description": "A vuln",
                        "PrimaryURL": "https://example.test/cve",
                    }
                ],
            }
        ]
    }
    r2 = client.post(
        "/api/ingest/trivy",
        files={"file": ("trivy.json", json.dumps(trivy_report), "application/json")},
        headers={"x-api-key": "test-key"},
    )
    assert r2.status_code == 200
    assert r2.json()["ingested"] == 1

    checkov_report = {
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_20",
                    "check_name": "S3 Bucket has an ACL defined which allows public READ access",
                    "severity": "MEDIUM",
                    "guideline": "Restrict S3 ACL",
                    "file_path": "/terraform/main.tf",
                    "file_line_range": [14, 21],
                }
            ]
        }
    }
    r3 = client.post(
        "/api/ingest/checkov",
        files={"file": ("checkov.json", json.dumps(checkov_report), "application/json")},
        headers={"x-api-key": "test-key"},
    )
    assert r3.status_code == 200
    assert r3.json()["ingested"] == 1

    zap_report = {
        "site": [
            {
                "@name": "https://app.example.com",
                "alerts": [
                    {
                        "pluginid": "40012",
                        "name": "Cross Site Scripting (Reflected)",
                        "riskdesc": "High (High)",
                        "desc": "XSS found",
                        "solution": "Encode output",
                    }
                ],
            }
        ]
    }
    r4 = client.post(
        "/api/ingest/zap",
        files={"file": ("zap.json", json.dumps(zap_report), "application/json")},
        headers={"x-api-key": "test-key"},
    )
    assert r4.status_code == 200
    assert r4.json()["ingested"] == 1

    nuclei_report = [
        {
            "template-id": "http-missing-security-headers",
            "host": "https://app.example.com",
            "matched-at": "https://app.example.com",
            "info": {"name": "Missing Security Headers", "severity": "low", "reference": ["https://owasp.org"]},
        }
    ]
    r5 = client.post(
        "/api/ingest/nuclei",
        files={"file": ("nuclei.json", json.dumps(nuclei_report), "application/json")},
        headers={"x-api-key": "test-key"},
    )
    assert r5.status_code == 200
    assert r5.json()["ingested"] == 1

    findings = client.get("/api/findings?limit=30&offset=0").json()
    assert findings["summary"]["by_scanner"]["semgrep"] == 1
    assert findings["summary"]["by_scanner"]["trivy"] == 1
    assert findings["summary"]["by_scanner"]["checkov"] == 1
    assert findings["summary"]["by_scanner"]["zap"] == 1
    assert findings["summary"]["by_scanner"]["nuclei"] == 1
