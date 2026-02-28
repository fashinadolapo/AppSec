import asyncio
import importlib
import os
import pytest
from fastapi import HTTPException
from starlette.requests import Request

import app.main as main


@pytest.fixture(autouse=True)
def reload_main_module(monkeypatch):
    # Keep env-driven globals deterministic for each test in this module.
    monkeypatch.setenv("AUTH_MODE", "disabled")
    monkeypatch.delenv("OIDC_DISCOVERY_URL", raising=False)
    monkeypatch.delenv("OIDC_CLIENT_ID", raising=False)
    monkeypatch.delenv("OIDC_CLIENT_SECRET", raising=False)
    importlib.reload(main)
    yield


def _request(path: str = "/", session: dict | None = None):
    scope = {
        "type": "http",
        "method": "GET",
        "path": path,
        "headers": [],
        "client": ("127.0.0.1", 1234),
        "scheme": "http",
        "server": ("test", 80),
        "query_string": b"",
    }
    if session is not None:
        scope["session"] = session
    return Request(scope)


def test_connection_manager_connect_disconnect_and_broadcast_cleanup():
    mgr = main.ConnectionManager()

    class WS:
        def __init__(self, fail=False):
            self.fail = fail
            self.accepted = False
            self.payloads = []

        async def accept(self):
            self.accepted = True

        async def send_json(self, payload):
            if self.fail:
                raise RuntimeError("boom")
            self.payloads.append(payload)

    ok = WS()
    bad = WS(fail=True)

    asyncio.run(mgr.connect(ok))
    asyncio.run(mgr.connect(bad))
    assert ok.accepted and bad.accepted

    asyncio.run(mgr.broadcast({"type": "refresh"}))
    assert ok.payloads == [{"type": "refresh"}]
    assert bad not in mgr.active

    mgr.disconnect(ok)
    assert ok not in mgr.active


def test_security_headers_middleware_adds_hsts_for_https():
    mw = main.SecurityHeadersMiddleware(main.app)

    async def call_next(_request):
        from starlette.responses import Response

        return Response("ok")

    req = _request("/x")
    req.scope["scheme"] = "https"
    resp = asyncio.run(mw.dispatch(req, call_next))
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "Strict-Transport-Security" in resp.headers


def test_ingest_protection_middleware_chaos_injects_error(monkeypatch):
    mw = main.IngestProtectionMiddleware(main.app)
    monkeypatch.setattr(main.rate_limiter, "allow", lambda _key: True)
    main.chaos.enabled = True
    main.chaos.error_percent = 100
    main.chaos.latency_ms = 0

    async def call_next(_request):
        from starlette.responses import Response

        return Response("ok")

    req = _request("/api/findings")
    resp = asyncio.run(mw.dispatch(req, call_next))
    assert resp.status_code == 503


def test_claims_session_optional_auth_and_role_requirements(monkeypatch):
    req = _request("/", session={"user": {"sub": "u1", "email": "u@example.com", "roles": ["viewer"]}})

    monkeypatch.setattr(main, "AUTH_MODE", "oidc")
    claims = main._claims_from_session(req)
    assert claims and claims["sub"] == "u1"

    auth = main.optional_auth(req)
    assert auth is not None and "viewer" in auth.roles

    checker = main.require_role("admin")
    with pytest.raises(HTTPException):
        checker(auth)


def test_csrf_token_and_validation_paths(monkeypatch):
    req = _request("/", session={})
    monkeypatch.setattr(main, "AUTH_MODE", "oidc")

    token = main._csrf_token(req)
    assert token
    main.validate_csrf(req, x_csrf_token=token)

    with pytest.raises(HTTPException) as exc:
        main.validate_csrf(req, x_csrf_token="wrong")
    assert exc.value.status_code == 403


def test_require_ingestor_access_api_key_and_role_paths(monkeypatch):
    req = _request("/", session={"csrf_token": "t"})
    monkeypatch.setattr(main, "INGEST_API_KEY", "k1")
    monkeypatch.setattr(main, "AUTH_MODE", "oidc")

    auth = main.require_ingestor_access(req, x_api_key="k1", auth=None)
    assert auth.subject == "api-key"

    with pytest.raises(HTTPException):
        main.require_ingestor_access(req, x_api_key="bad", auth=main.AuthContext(subject="u", roles={"viewer"}))


def test_parse_sarif_record_to_schema_and_detect_generic_branches():
    sarif = {
        "runs": [
            {
                "tool": {"driver": {"rules": [{"id": "R1", "shortDescription": {"text": "desc"}}]}},
                "results": [
                    {
                        "ruleId": "R1",
                        "message": {"text": "msg"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 3}}}],
                        "level": "error",
                    }
                ],
            }
        ]
    }
    findings = main.parse_sarif_report(sarif, "semgrep", project_id="p1")
    assert len(findings) == 1 and findings[0].project_id == "p1"

    from datetime import datetime, timezone

    row = main.FindingRecord(
        id="id-1",
        fingerprint="f",
        scanner="semgrep",
        project_id="p1",
        category="sast",
        severity="high",
        rule_id="R1",
        title="T",
        description="D",
        recommendation="R",
        file_path="a.py",
        line=1,
        status="open",
        source="ci",
        detected_at=datetime.now(timezone.utc),
        raw={"k": "v"},
    )
    schema = main.record_to_schema(row)
    assert schema.project_id == "p1"

    findings2 = main.detect_and_parse_report({"findings": [{"title": "x"}]}, "custom", project_id="p2")
    assert findings2 and findings2[0].project_id == "p2"

    findings3 = main.detect_and_parse_report({"results": [{"title": "y"}]}, "custom", project_id="p3")
    assert findings3 and findings3[0].project_id == "p3"


def test_summary_from_db_and_ingest_updates_existing(tmp_path):
    os.environ["DATABASE_URL"] = f"sqlite:///{tmp_path / 'sum.db'}"
    importlib.reload(main)
    db = main.SessionLocal()
    try:
        finding = main.Finding(scanner="semgrep", project_id="p1", severity="high", rule_id="R1", title="A", description="d1")
        asyncio.run(main.ingest_findings(db, [finding]))
        finding2 = main.Finding(scanner="semgrep", project_id="p1", severity="low", rule_id="R1", title="A", description="d2")
        asyncio.run(main.ingest_findings(db, [finding2]))

        summary = main.summary_from_db(db, project_id="p1")
        assert summary["total"] == 1
        assert summary["by_scanner"]["semgrep"] == 1
        record = db.scalar(main.select(main.FindingRecord).where(main.FindingRecord.project_id == "p1"))
        assert record is not None and record.description == "d2"
    finally:
        db.close()


def test_build_openai_ai_insights_local_and_remote(monkeypatch):
    findings = [main.Finding(scanner="semgrep", severity="high", title="Issue", recommendation="Fix")]
    summary = {"total": 1, "by_severity": {"high": 1}, "by_scanner": {"semgrep": 1}}

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    local = asyncio.run(main.build_openai_ai_insights(findings, summary))
    assert local["provider"] == "local-heuristic"

    monkeypatch.setenv("OPENAI_API_KEY", "token")

    class Resp:
        status_code = 200

        def json(self):
            return {"choices": [{"message": {"content": '{"narrative":"n","actions":["a"]}'}}]}

    class DummyClient:
        def __init__(self, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, *_args, **_kwargs):
            return Resp()

    monkeypatch.setattr(main.httpx, "AsyncClient", DummyClient)
    remote = asyncio.run(main.build_openai_ai_insights(findings, summary))
    assert remote["provider"] == "openai"


def test_template_render_auth_routes_and_health_ready(monkeypatch):
    rendered = main._render_template("templates/index.html", "user@example.com")
    assert "user@example.com" in rendered.body.decode("utf-8")

    viewer = main.AuthContext(subject="s", email="v@example.com", roles={main.VIEWER_ROLE})
    admin = main.AuthContext(subject="s", email="a@example.com", roles={main.ADMIN_ROLE})
    assert main.dashboard(viewer).status_code == 200
    assert main.chaos_page(admin).status_code == 200

    monkeypatch.setattr(main, "AUTH_MODE", "disabled")
    login_redirect = asyncio.run(main.auth_login(_request("/auth/login")))
    assert login_redirect.status_code == 302

    callback_redirect = asyncio.run(main.auth_callback(_request("/auth/callback", session={})))
    assert callback_redirect.status_code == 302

    logout_redirect = main.auth_logout(_request("/auth/logout", session={"user": {"sub": "u1"}}))
    assert logout_redirect.status_code == 302

    assert main.healthz()["status"] == "ok"

    class DummyDB:
        def scalar(self, _query):
            return 1

    assert main.readyz(DummyDB())["status"] == "ready"


def test_oidc_login_and_callback_with_mock_client(monkeypatch):
    monkeypatch.setattr(main, "AUTH_MODE", "oidc")

    class DummyClient:
        async def authorize_redirect(self, _request, redirect_uri):
            assert "auth/callback" in str(redirect_uri)
            from fastapi.responses import RedirectResponse

            return RedirectResponse("/idp", status_code=302)

        async def authorize_access_token(self, _request):
            return {"userinfo": {"sub": "u1", "email": "u@example.com", "roles": ["viewer"]}}

        async def parse_id_token(self, _request, _token):
            return {"sub": "u2", "email": "u2@example.com", "roles": ["viewer"]}

    monkeypatch.setattr(main.oauth, "create_client", lambda _name: DummyClient())

    req_login = _request("/auth/login", session={})
    req_login.scope["router"] = main.app.router
    login_resp = asyncio.run(main.auth_login(req_login))
    assert login_resp.status_code == 302

    req_callback = _request("/auth/callback", session={})
    req_callback.scope["router"] = main.app.router
    callback_resp = asyncio.run(main.auth_callback(req_callback))
    assert callback_resp.status_code == 302
    assert req_callback.session.get("user", {}).get("sub") == "u1"


def test_extract_roles_string_claim_path(monkeypatch):
    monkeypatch.setattr(main, "ROLE_CLAIM", "roles")
    roles = main.extract_roles({"roles": "viewer admin"})
    assert {"viewer", "admin"}.issubset(roles)


def test_ingest_protection_middleware_latency_branch(monkeypatch):
    mw = main.IngestProtectionMiddleware(main.app)
    monkeypatch.setattr(main.rate_limiter, "allow", lambda _key: True)
    main.chaos.enabled = True
    main.chaos.error_percent = 0
    main.chaos.latency_ms = 1

    called = {"sleep": False}

    async def fake_sleep(_sec):
        called["sleep"] = True

    monkeypatch.setattr(__import__("asyncio"), "sleep", fake_sleep)

    async def call_next(_request):
        from starlette.responses import Response

        return Response("ok")

    req = _request("/api/findings")
    resp = asyncio.run(mw.dispatch(req, call_next))
    assert resp.status_code == 200
    assert called["sleep"] is True


def test_require_ingestor_access_role_and_no_api_key_paths(monkeypatch):
    req = _request("/", session={"csrf_token": "token"})
    monkeypatch.setattr(main, "AUTH_MODE", "oidc")
    monkeypatch.setattr(main, "INGEST_API_KEY", "")

    monkeypatch.setattr(main, "validate_csrf", lambda *_args, **_kwargs: None)
    auth = main.AuthContext(subject="u", roles={main.INGESTOR_ROLE})
    assert main.require_ingestor_access(req, x_api_key=None, auth=auth).subject == "u"

    with pytest.raises(HTTPException):
        main.require_ingestor_access(req, x_api_key=None, auth=main.AuthContext(subject="u", roles={"viewer"}))


def test_detect_and_parse_report_sarif_branch():
    report = {"runs": [{"tool": {"driver": {"rules": []}}, "results": []}]}
    findings = main.detect_and_parse_report(report, "any", project_id="p")
    assert findings == []


def test_openai_fallback_on_error(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "token")
    findings = [main.Finding(scanner="semgrep", severity="high", title="Issue")]
    summary = {"total": 1, "by_severity": {"high": 1}, "by_scanner": {"semgrep": 1}}

    class Resp:
        status_code = 500

        def json(self):
            return {}

    class DummyClient:
        def __init__(self, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, *_args, **_kwargs):
            return Resp()

    monkeypatch.setattr(main.httpx, "AsyncClient", DummyClient)
    out = asyncio.run(main.build_openai_ai_insights(findings, summary))
    assert out["provider"] == "local-heuristic"


def test_auth_login_and_callback_raise_when_oidc_client_missing(monkeypatch):
    monkeypatch.setattr(main, "AUTH_MODE", "oidc")
    monkeypatch.setattr(main.oauth, "create_client", lambda _name: None)

    req_login = _request("/auth/login", session={})
    req_login.scope["router"] = main.app.router
    with pytest.raises(HTTPException) as exc_login:
        asyncio.run(main.auth_login(req_login))
    assert exc_login.value.status_code == 500

    req_cb = _request("/auth/callback", session={})
    req_cb.scope["router"] = main.app.router
    with pytest.raises(HTTPException) as exc_cb:
        asyncio.run(main.auth_callback(req_cb))
    assert exc_cb.value.status_code == 500


def test_auth_callback_parse_id_token_branch(monkeypatch):
    monkeypatch.setattr(main, "AUTH_MODE", "oidc")

    class DummyClient:
        async def authorize_access_token(self, _request):
            return {"access_token": "x"}

        async def parse_id_token(self, _request, _token):
            return {"sub": "from-id-token", "email": "id@example.com", "roles": ["viewer"]}

    monkeypatch.setattr(main.oauth, "create_client", lambda _name: DummyClient())

    req = _request("/auth/callback", session={})
    req.scope["router"] = main.app.router
    resp = asyncio.run(main.auth_callback(req))
    assert resp.status_code == 302
    assert req.session["user"]["sub"] == "from-id-token"


def test_ai_insights_endpoint_and_authorized_websocket(tmp_path):
    os.environ["DATABASE_URL"] = f"sqlite:///{tmp_path / 'api_insights.db'}"
    os.environ["INGEST_API_KEY"] = "test-key"
    os.environ["AUTH_MODE"] = "disabled"
    importlib.reload(main)

    from fastapi.testclient import TestClient

    client = TestClient(main.app)
    payload = [{"severity": "high", "title": "one"}]
    res = client.post(
        "/api/ingest/gitleaks?project_id=demo",
        files={"file": ("r.json", __import__("json").dumps(payload), "application/json")},
        headers={"x-api-key": "test-key"},
    )
    assert res.status_code == 200

    ai = client.get("/api/ai/insights?project_id=demo")
    assert ai.status_code == 200
    assert "provider" in ai.json()

    with client.websocket_connect("/ws") as ws:
        first = ws.receive_json()
        assert first["type"] == "refresh"
        ws.send_text("ping")


def test_oidc_register_called_on_reload(monkeypatch):
    from authlib.integrations.starlette_client import OAuth

    called = {"count": 0}
    orig = OAuth.register

    def wrapped(self, *args, **kwargs):
        called["count"] += 1
        return orig(self, *args, **kwargs)

    monkeypatch.setattr(OAuth, "register", wrapped)
    monkeypatch.setenv("AUTH_MODE", "oidc")
    monkeypatch.setenv("OIDC_DISCOVERY_URL", "https://issuer.example/.well-known/openid-configuration")
    monkeypatch.setenv("OIDC_CLIENT_ID", "cid")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "sec")
    importlib.reload(main)

    assert called["count"] >= 1


def test_require_ingestor_access_oidc_role_branch_when_api_key_present(monkeypatch):
    req = _request("/", session={"csrf_token": "token"})
    monkeypatch.setattr(main, "AUTH_MODE", "oidc")
    monkeypatch.setattr(main, "INGEST_API_KEY", "expected")

    called = {"csrf": False}

    def _mark_csrf(_request):
        called["csrf"] = True

    monkeypatch.setattr(main, "validate_csrf", _mark_csrf)
    auth = main.AuthContext(subject="u", roles={main.INGESTOR_ROLE})
    out = main.require_ingestor_access(req, x_api_key="wrong", auth=auth)
    assert out.subject == "u"
    assert called["csrf"] is True
