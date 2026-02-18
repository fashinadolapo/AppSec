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
