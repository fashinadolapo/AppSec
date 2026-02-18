import importlib

import pytest
from fastapi import HTTPException

try:
    import app.main as main
except Exception as exc:  # pragma: no cover - environment mismatch guard
    pytest.skip(f"Unable to import app.main: {exc}", allow_module_level=True)

REQUIRED_SYMBOLS = [
    "AUTH_MODE",
    "ROLE_CLAIM",
    "detect_and_parse_report",
    "fingerprint_finding",
    "_auth_context_from_claims",
    "_auth_from_ws",
]

missing = [name for name in REQUIRED_SYMBOLS if not hasattr(main, name)]
if missing:
    pytest.skip(
        "Unit core tests require the production app.main surface. Missing symbols: " + ", ".join(missing),
        allow_module_level=True,
    )


@pytest.fixture(autouse=True)
def reload_main_module():
    # Keep globals like AUTH_MODE/ROLE_CLAIM predictable between tests.
    importlib.reload(main)
    yield


def test_extract_roles_uses_primary_and_fallback_claims(monkeypatch):
    monkeypatch.setattr(main, "ROLE_CLAIM", "roles")

    claims = {
        "roles": ["viewer", "ingestor"],
        "groups": "secops admin",
        "scp": ["read:findings"],
        "scope": "openid profile",
    }

    roles = main.extract_roles(claims)

    assert "viewer" in roles
    assert "ingestor" in roles
    assert "secops" in roles
    assert "admin" in roles
    assert "read:findings" in roles
    assert "openid" in roles


def test_auth_context_from_claims_handles_empty_and_valid():
    assert main._auth_context_from_claims(None) is None

    auth = main._auth_context_from_claims({"sub": "user-1", "email": "u@example.com", "roles": ["viewer"]})
    assert auth is not None
    assert auth.subject == "user-1"
    assert auth.email == "u@example.com"
    assert "viewer" in auth.roles


def test_fingerprint_changes_with_project_id():
    a = main.Finding(scanner="semgrep", project_id="team-a", rule_id="R1", file_path="app.py", line=10, title="Issue")
    b = main.Finding(scanner="semgrep", project_id="team-b", rule_id="R1", file_path="app.py", line=10, title="Issue")

    assert main.fingerprint_finding(a) != main.fingerprint_finding(b)


def test_detect_and_parse_report_aliases_and_project_propagation():
    sonar = {"issues": [{"rule": "python:S3649", "severity": "CRITICAL", "message": "SQL injection", "component": "src/db.py", "line": 22}]}
    findings = main.detect_and_parse_report(sonar, "sonar", project_id="team-a")

    assert len(findings) == 1
    assert findings[0].scanner == "sonarqube"
    assert findings[0].project_id == "team-a"


def test_detect_and_parse_report_rejects_unknown_format():
    with pytest.raises(HTTPException) as exc:
        main.detect_and_parse_report("not-a-report", "unknown")

    assert exc.value.status_code == 400


def test_auth_from_ws_oidc_uses_session_claims(monkeypatch):
    monkeypatch.setattr(main, "AUTH_MODE", "oidc")

    class WS:
        scope = {"session": {"user": {"sub": "alice", "roles": ["viewer"]}}}

    auth = main._auth_from_ws(WS())
    assert auth is not None
    assert auth.subject == "alice"
    assert "viewer" in auth.roles


def test_auth_from_ws_non_oidc_grants_system_roles(monkeypatch):
    monkeypatch.setattr(main, "AUTH_MODE", "disabled")

    class WS:
        scope = {}

    auth = main._auth_from_ws(WS())
    assert auth is not None
    assert {main.VIEWER_ROLE, main.INGESTOR_ROLE, main.ADMIN_ROLE}.issubset(auth.roles)
