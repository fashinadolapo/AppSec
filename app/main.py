from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from authlib.integrations.starlette_client import OAuth
from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, Request, UploadFile, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import JSON, DateTime, Integer, String, create_engine, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware


DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./appsec.db")
INGEST_API_KEY = os.getenv("INGEST_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

AUTH_MODE = os.getenv("AUTH_MODE", "disabled").lower()
SESSION_SECRET_KEY = os.getenv("SESSION_SECRET_KEY", "change-me-in-production")
SESSION_HTTPS_ONLY = os.getenv("SESSION_HTTPS_ONLY", "true").lower() == "true"
OIDC_DISCOVERY_URL = os.getenv("OIDC_DISCOVERY_URL", "")
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET", "")
OIDC_SCOPES = os.getenv("OIDC_SCOPES", "openid profile email")
ROLE_CLAIM = os.getenv("ROLE_CLAIM", "roles")
VIEWER_ROLE = os.getenv("VIEWER_ROLE", "viewer")
INGESTOR_ROLE = os.getenv("INGESTOR_ROLE", "ingestor")
ADMIN_ROLE = os.getenv("ADMIN_ROLE", "admin")

INGEST_RATE_LIMIT_PER_MIN = int(os.getenv("INGEST_RATE_LIMIT_PER_MIN", "60"))
INGEST_MAX_BODY_BYTES = int(os.getenv("INGEST_MAX_BODY_BYTES", str(10 * 1024 * 1024)))

logger = logging.getLogger("appsec.audit")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))


def _sqlite_connect_args(url: str) -> dict[str, Any]:
    return {"check_same_thread": False} if url.startswith("sqlite") else {}


engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args=_sqlite_connect_args(DATABASE_URL))
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


class FindingRecord(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    fingerprint: Mapped[str] = mapped_column(String, unique=True, index=True)
    scanner: Mapped[str] = mapped_column(String, index=True)
    project_id: Mapped[str] = mapped_column(String, default="default", index=True)
    category: Mapped[str] = mapped_column(String, default="security")
    severity: Mapped[str] = mapped_column(String, default="medium", index=True)
    rule_id: Mapped[str] = mapped_column(String, default="unknown")
    title: Mapped[str] = mapped_column(String, default="Unnamed finding")
    description: Mapped[str] = mapped_column(String, default="")
    recommendation: Mapped[str] = mapped_column(String, default="")
    file_path: Mapped[str] = mapped_column(String, default="")
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String, default="open")
    source: Mapped[str] = mapped_column(String, default="ci")
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


Base.metadata.create_all(bind=engine)


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scanner: str
    project_id: str = "default"
    category: str = "security"
    severity: str = "medium"
    rule_id: str = "unknown"
    title: str = "Unnamed finding"
    description: str = ""
    recommendation: str = ""
    file_path: str = ""
    line: int | None = None
    status: str = "open"
    source: str = "ci"
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw: dict[str, Any] = Field(default_factory=dict)


class MCPIngestRequest(BaseModel):
    source: str = "mcp"
    scanner: str = "mcp-adapter"
    findings: list[dict[str, Any]]


class AuthContext(BaseModel):
    subject: str
    email: str | None = None
    roles: set[str] = Field(default_factory=set)


class ChaosConfig(BaseModel):
    enabled: bool = False
    latency_ms: int = 0
    error_percent: int = 0


class ChaosUpdate(BaseModel):
    enabled: bool = False
    latency_ms: int = Field(default=0, ge=0, le=10000)
    error_percent: int = Field(default=0, ge=0, le=100)


class ConnectionManager:
    def __init__(self) -> None:
        self.active: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active:
            self.active.remove(websocket)

    async def broadcast(self, payload: dict[str, Any]) -> None:
        stale: list[WebSocket] = []
        for ws in self.active:
            try:
                await ws.send_json(payload)
            except Exception:
                stale.append(ws)
        for ws in stale:
            self.disconnect(ws)


class RateLimiter:
    def __init__(self, limit_per_min: int) -> None:
        self.limit = limit_per_min
        self.buckets: dict[str, list[float]] = {}

    def allow(self, key: str) -> bool:
        now = time.time()
        window_start = now - 60
        entries = [t for t in self.buckets.get(key, []) if t >= window_start]
        if len(entries) >= self.limit:
            self.buckets[key] = entries
            return False
        entries.append(now)
        self.buckets[key] = entries
        return True


ws_manager = ConnectionManager()
chaos = ChaosConfig()
rate_limiter = RateLimiter(INGEST_RATE_LIMIT_PER_MIN)
app = FastAPI(title="AppSec Fusion Dashboard", version="1.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in os.getenv("CORS_ALLOW_ORIGINS", "*").split(",")],
    allow_methods=["*"],
    allow_headers=["*"],
)
if AUTH_MODE == "oidc":
    app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET_KEY, same_site="lax", https_only=SESSION_HTTPS_ONLY)
app.mount("/static", StaticFiles(directory="static"), name="static")


oauth = OAuth()
if AUTH_MODE == "oidc" and OIDC_DISCOVERY_URL and OIDC_CLIENT_ID and OIDC_CLIENT_SECRET:
    oauth.register(
        name="oidc",
        server_metadata_url=OIDC_DISCOVERY_URL,
        client_id=OIDC_CLIENT_ID,
        client_secret=OIDC_CLIENT_SECRET,
        client_kwargs={"scope": OIDC_SCOPES},
    )


SEVERITY_RANK = {"critical": 4, "error": 4, "high": 3, "warning": 2, "medium": 2, "note": 1, "low": 1, "info": 1}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


class IngestProtectionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/api/ingest") or request.url.path.startswith("/api/mcp/ingest"):
            ip = request.client.host if request.client else "unknown"
            if not rate_limiter.allow(f"{ip}:{request.url.path}"):
                return HTMLResponse(status_code=429, content="Too many requests")

            cl = request.headers.get("content-length")
            if cl and int(cl) > INGEST_MAX_BODY_BYTES:
                return HTMLResponse(status_code=413, content="Payload too large")

        if chaos.enabled and request.url.path.startswith("/api/") and not request.url.path.startswith("/api/admin/chaos"):
            if chaos.latency_ms > 0:
                await __import__("asyncio").sleep(chaos.latency_ms / 1000)
            if chaos.error_percent > 0:
                if secrets.randbelow(100) < chaos.error_percent:
                    return HTMLResponse(status_code=503, content="Chaos mode injected error")

        return await call_next(request)


app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(IngestProtectionMiddleware)


def audit(event: str, request: Request | None = None, **fields: Any) -> None:
    payload = {
        "event": event,
        "path": request.url.path if request else None,
        "method": request.method if request else None,
        "client": request.client.host if request and request.client else None,
        **fields,
    }
    logger.info("audit %s", json.dumps(payload, default=str))


def extract_roles(claims: dict[str, Any]) -> set[str]:
    roles: set[str] = set()
    raw = claims.get(ROLE_CLAIM)
    if isinstance(raw, str):
        roles.update(part.strip() for part in raw.split() if part.strip())
    elif isinstance(raw, list):
        roles.update(str(part).strip() for part in raw if str(part).strip())

    for fallback in ["groups", "scp", "scope"]:
        value = claims.get(fallback)
        if isinstance(value, str):
            roles.update(part.strip() for part in value.split() if part.strip())
        elif isinstance(value, list):
            roles.update(str(part).strip() for part in value if str(part).strip())

    return roles


def get_db() -> Any:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _claims_from_session(request: Request) -> dict[str, Any] | None:
    user = request.session.get("user") if hasattr(request, "session") else None
    return user if isinstance(user, dict) else None


def optional_auth(request: Request) -> AuthContext | None:
    if AUTH_MODE != "oidc":
        return AuthContext(subject="system", email="system@appsec.local", roles={VIEWER_ROLE, INGESTOR_ROLE, ADMIN_ROLE})

    claims = _claims_from_session(request)
    if not claims:
        return None
    return AuthContext(subject=str(claims.get("sub", "unknown")), email=claims.get("email"), roles=extract_roles(claims))


def require_role(role: str):
    def checker(auth: AuthContext | None = Depends(optional_auth)) -> AuthContext:
        if not auth or role not in auth.roles:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Role '{role}' required")
        return auth

    return checker


def _csrf_token(request: Request) -> str:
    if AUTH_MODE != "oidc":
        return "disabled"
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


def validate_csrf(request: Request, x_csrf_token: str | None = Header(default=None)) -> None:
    if AUTH_MODE != "oidc":
        return
    expected = request.session.get("csrf_token") if hasattr(request, "session") else None
    if not expected or x_csrf_token != expected:
        raise HTTPException(status_code=403, detail="CSRF token missing or invalid")


def require_ingestor_access(request: Request, x_api_key: str | None = Header(default=None), auth: AuthContext | None = Depends(optional_auth)) -> AuthContext:
    if INGEST_API_KEY:
        if x_api_key == INGEST_API_KEY:
            return auth or AuthContext(subject="api-key", roles={INGESTOR_ROLE})
        if AUTH_MODE == "oidc" and auth and INGESTOR_ROLE in auth.roles:
            validate_csrf(request)
            return auth
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Ingestor role or valid API key required")

    if auth and INGESTOR_ROLE in auth.roles:
        validate_csrf(request)
        return auth
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Ingestor role or valid API key required")


def fingerprint_finding(finding: Finding) -> str:
    payload = f"{finding.project_id}|{finding.scanner}|{finding.rule_id}|{finding.file_path}|{finding.line}|{finding.title}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def record_to_schema(record: FindingRecord) -> Finding:
    return Finding(
        id=record.id,
        scanner=record.scanner,
        project_id=record.project_id,
        category=record.category,
        severity=record.severity,
        rule_id=record.rule_id,
        title=record.title,
        description=record.description,
        recommendation=record.recommendation,
        file_path=record.file_path,
        line=record.line,
        status=record.status,
        source=record.source,
        detected_at=record.detected_at,
        raw=record.raw or {},
    )


def parse_sarif_report(report: dict[str, Any], scanner: str, project_id: str = "default") -> list[Finding]:
    findings: list[Finding] = []
    for run in report.get("runs", []):
        rules = {rule.get("id"): rule for rule in run.get("tool", {}).get("driver", {}).get("rules", []) if rule.get("id")}
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            rule = rules.get(rule_id, {})
            location = ((result.get("locations") or [{}])[0]).get("physicalLocation", {})
            region = location.get("region", {})
            findings.append(
                Finding(
                    scanner=scanner,
                    project_id=project_id,
                    severity=(result.get("level") or "warning").lower(),
                    rule_id=rule_id,
                    title=(rule.get("name") or rule_id),
                    description=result.get("message", {}).get("text", ""),
                    recommendation=(
                        rule.get("help", {}).get("text")
                        or rule.get("shortDescription", {}).get("text")
                        or "Review scanner guidance and remediate affected resource."
                    ),
                    file_path=location.get("artifactLocation", {}).get("uri", ""),
                    line=region.get("startLine"),
                    raw=result,
                )
            )
    return findings


def parse_generic_findings(report: list[dict[str, Any]], scanner: str, source: str = "ci", project_id: str = "default") -> list[Finding]:
    return [
        Finding(
            scanner=scanner,
            project_id=item.get("project_id", project_id),
            category=item.get("category", "security"),
            severity=str(item.get("severity", "medium")).lower(),
            rule_id=item.get("rule_id", item.get("id", "unknown")),
            title=item.get("title", item.get("name", "Unnamed finding")),
            description=item.get("description", ""),
            recommendation=item.get("recommendation", ""),
            file_path=item.get("file", item.get("file_path", "")),
            line=item.get("line"),
            status=item.get("status", "open"),
            source=item.get("source", source),
            raw=item,
        )
        for item in report
    ]




def parse_semgrep_json(report: dict[str, Any], scanner: str = "semgrep", project_id: str = "default") -> list[Finding]:
    findings: list[Finding] = []
    for result in report.get("results", []):
        extra = result.get("extra", {})
        findings.append(
            Finding(
                scanner=scanner,
                severity=str(extra.get("severity", "medium")).lower(),
                rule_id=result.get("check_id", "unknown"),
                title=result.get("check_id", "Semgrep finding"),
                description=extra.get("message", ""),
                recommendation=extra.get("metadata", {}).get("fix", ""),
                file_path=result.get("path", ""),
                line=(result.get("start") or {}).get("line"),
                raw=result,
            )
        )
    return findings


def parse_trivy_json(report: dict[str, Any], scanner: str = "trivy", project_id: str = "default") -> list[Finding]:
    findings: list[Finding] = []
    for result in report.get("Results", []):
        target = result.get("Target", "")
        vulns = result.get("Vulnerabilities", []) or result.get("Misconfigurations", [])
        for vuln in vulns:
            findings.append(
                Finding(
                    scanner=scanner,
                    project_id=project_id,
                    severity=str(vuln.get("Severity", vuln.get("severity", "medium"))).lower(),
                    rule_id=vuln.get("VulnerabilityID", vuln.get("ID", "unknown")),
                    title=vuln.get("Title", vuln.get("Message", "Trivy finding")),
                    description=vuln.get("Description", ""),
                    recommendation=vuln.get("PrimaryURL", vuln.get("Resolution", "")),
                    file_path=target,
                    raw=vuln,
                )
            )
    return findings


def parse_checkov_json(report: dict[str, Any], scanner: str = "checkov", project_id: str = "default") -> list[Finding]:
    failed = ((report.get("results") or {}).get("failed_checks")) or report.get("failed_checks") or []
    findings: list[Finding] = []
    for check in failed:
        findings.append(
            Finding(
                scanner=scanner,
                project_id=project_id,
                severity=str(check.get("severity", "medium")).lower(),
                rule_id=check.get("check_id", "unknown"),
                title=check.get("check_name", "Checkov finding"),
                description=check.get("guideline", ""),
                recommendation=check.get("guideline", ""),
                file_path=check.get("file_path", ""),
                line=check.get("file_line_range", [None])[0] if isinstance(check.get("file_line_range"), list) else None,
                raw=check,
            )
        )
    return findings


def parse_zap_json(report: dict[str, Any], scanner: str = "zap", project_id: str = "default") -> list[Finding]:
    findings: list[Finding] = []
    for site in (report.get("site") or []):
        for alert in site.get("alerts", []):
            findings.append(
                Finding(
                    scanner=scanner,
                    project_id=project_id,
                    severity=str(alert.get("riskdesc", "medium")).split(" ")[0].lower(),
                    rule_id=alert.get("pluginid", "unknown"),
                    title=alert.get("name", "ZAP alert"),
                    description=alert.get("desc", ""),
                    recommendation=alert.get("solution", ""),
                    file_path=site.get("@name", ""),
                    raw=alert,
                )
            )
    return findings


def parse_nuclei_json(report: list[dict[str, Any]], scanner: str = "nuclei", project_id: str = "default") -> list[Finding]:
    findings: list[Finding] = []
    for item in report:
        info = item.get("info", {})
        findings.append(
            Finding(
                scanner=scanner,
                project_id=project_id,
                severity=str(info.get("severity", "medium")).lower(),
                rule_id=item.get("template-id", "unknown"),
                title=info.get("name", "Nuclei finding"),
                description=item.get("matched-at", ""),
                recommendation=info.get("reference", [""])[0] if isinstance(info.get("reference"), list) and info.get("reference") else "",
                file_path=item.get("host", ""),
                raw=item,
            )
        )
    return findings


def detect_and_parse_report(report: Any, scanner: str, project_id: str = "default") -> list[Finding]:
    normalized = scanner.lower()
    if isinstance(report, dict) and "runs" in report:
        return parse_sarif_report(report, normalized, project_id=project_id)
    if normalized == "semgrep" and isinstance(report, dict) and isinstance(report.get("results"), list):
        return parse_semgrep_json(report, normalized, project_id=project_id)
    if normalized == "trivy" and isinstance(report, dict) and isinstance(report.get("Results"), list):
        return parse_trivy_json(report, normalized, project_id=project_id)
    if normalized == "checkov" and isinstance(report, dict) and ((report.get("results") or {}).get("failed_checks") or report.get("failed_checks")):
        return parse_checkov_json(report, normalized, project_id=project_id)
    if normalized == "zap" and isinstance(report, dict) and isinstance(report.get("site"), list):
        return parse_zap_json(report, normalized, project_id=project_id)
    if normalized == "nuclei" and isinstance(report, list) and report and isinstance(report[0], dict) and "template-id" in report[0]:
        return parse_nuclei_json(report, normalized, project_id=project_id)
    if isinstance(report, list):
        return parse_generic_findings(report, normalized, project_id=project_id)
    if isinstance(report, dict) and isinstance(report.get("findings"), list):
        return parse_generic_findings(report["findings"], normalized, project_id=project_id)
    if isinstance(report, dict) and isinstance(report.get("results"), list):
        return parse_generic_findings(report["results"], normalized, project_id=project_id)
    raise HTTPException(status_code=400, detail="Unsupported report format")

def summary_from_db(db: Session, project_id: str | None = None) -> dict[str, Any]:
    query = select(FindingRecord.severity, FindingRecord.scanner)
    if project_id:
        query = query.where(FindingRecord.project_id == project_id)
    rows = db.execute(query).all()
    by_severity: dict[str, int] = {}
    by_scanner: dict[str, int] = {}
    for severity, scanner in rows:
        by_severity[severity] = by_severity.get(severity, 0) + 1
        by_scanner[scanner] = by_scanner.get(scanner, 0) + 1
    return {"total": len(rows), "by_severity": by_severity, "by_scanner": by_scanner}


async def ingest_findings(db: Session, findings: list[Finding]) -> int:
    created = 0
    for finding in findings:
        fp = fingerprint_finding(finding)
        existing = db.scalar(select(FindingRecord).where(FindingRecord.fingerprint == fp))
        if existing:
            existing.severity = finding.severity
            existing.description = finding.description
            existing.recommendation = finding.recommendation
            existing.status = finding.status
            existing.raw = finding.raw
        else:
            db.add(
                FindingRecord(
                    fingerprint=fp,
                    scanner=finding.scanner,
                    project_id=finding.project_id,
                    category=finding.category,
                    severity=finding.severity,
                    rule_id=finding.rule_id,
                    title=finding.title,
                    description=finding.description,
                    recommendation=finding.recommendation,
                    file_path=finding.file_path,
                    line=finding.line,
                    status=finding.status,
                    source=finding.source,
                    raw=finding.raw,
                )
            )
            created += 1
    db.commit()
    await ws_manager.broadcast({"type": "refresh", "summary": summary_from_db(db)})
    return created


def build_local_ai_insights(findings: list[Finding], summary: dict[str, Any]) -> dict[str, Any]:
    prioritized = sorted(findings, key=lambda f: (SEVERITY_RANK.get(f.severity, 0), f.detected_at.timestamp()), reverse=True)[:5]
    actions = [{"finding_id": f.id, "priority": f.severity, "title": f.title, "scanner": f.scanner, "recommendation": f.recommendation or "Triage, patch, and re-scan in CI.", "path": f.file_path} for f in prioritized]
    narrative = (
        f"Detected {summary['total']} findings. Focus on {summary['by_severity'].get('critical', 0) + summary['by_severity'].get('error', 0)} critical/error "
        f"and {summary['by_severity'].get('high', 0)} high findings first."
    )
    return {"provider": "local-heuristic", "narrative": narrative, "actions": actions}


async def build_openai_ai_insights(findings: list[Finding], summary: dict[str, Any]) -> dict[str, Any]:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return build_local_ai_insights(findings, summary)

    compact = [{"severity": f.severity, "title": f.title, "scanner": f.scanner, "file_path": f.file_path, "recommendation": f.recommendation} for f in findings[:100]]
    payload = {"task": "Generate concise AppSec remediation guidance as JSON", "requirements": ["Return JSON keys: narrative, actions", "Prioritize critical/high first"], "summary": summary, "findings": compact}
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "model": OPENAI_MODEL,
                "temperature": 0.2,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": "You are an AppSec remediation assistant."},
                    {"role": "user", "content": json.dumps(payload)},
                ],
            },
        )
    if resp.status_code >= 400:
        return build_local_ai_insights(findings, summary)
    parsed = json.loads(resp.json().get("choices", [{}])[0].get("message", {}).get("content", "{}"))
    return {"provider": "openai", "narrative": parsed.get("narrative", ""), "actions": parsed.get("actions", [])}


def _render_template(path: str, user: str) -> HTMLResponse:
    html = Path(path).read_text(encoding="utf-8").replace("__USER_EMAIL__", user)
    return HTMLResponse(html)


@app.get("/")
def dashboard(auth: AuthContext = Depends(require_role(VIEWER_ROLE))) -> HTMLResponse:
    return _render_template("templates/index.html", auth.email or auth.subject)


@app.get("/chaos")
def chaos_page(auth: AuthContext = Depends(require_role(ADMIN_ROLE))) -> HTMLResponse:
    return _render_template("templates/chaos.html", auth.email or auth.subject)


@app.get("/api/me")
def me(request: Request, auth: AuthContext = Depends(require_role(VIEWER_ROLE))) -> dict[str, Any]:
    return {"subject": auth.subject, "email": auth.email, "roles": sorted(auth.roles), "auth_mode": AUTH_MODE, "csrf_token": _csrf_token(request)}


@app.get("/auth/login")
async def auth_login(request: Request) -> RedirectResponse:
    if AUTH_MODE != "oidc":
        return RedirectResponse(url="/", status_code=302)
    client = oauth.create_client("oidc")
    if client is None:
        raise HTTPException(status_code=500, detail="OIDC client not configured")
    redirect_uri = request.url_for("auth_callback")
    audit("auth_login_start", request)
    return await client.authorize_redirect(request, redirect_uri)


@app.get("/auth/callback")
async def auth_callback(request: Request) -> RedirectResponse:
    if AUTH_MODE != "oidc":
        return RedirectResponse(url="/", status_code=302)
    client = oauth.create_client("oidc")
    if client is None:
        raise HTTPException(status_code=500, detail="OIDC client not configured")
    token = await client.authorize_access_token(request)
    userinfo = token.get("userinfo")
    if not userinfo:
        userinfo = await client.parse_id_token(request, token)
    request.session["user"] = dict(userinfo)
    _csrf_token(request)
    audit("auth_login_success", request, sub=userinfo.get("sub"), email=userinfo.get("email"))
    return RedirectResponse(url="/", status_code=302)


@app.get("/auth/logout")
def auth_logout(request: Request) -> RedirectResponse:
    if hasattr(request, "session"):
        audit("auth_logout", request, sub=request.session.get("user", {}).get("sub"))
        request.session.clear()
    return RedirectResponse(url="/auth/login" if AUTH_MODE == "oidc" else "/", status_code=302)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/readyz")
def readyz(db: Session = Depends(get_db)) -> dict[str, str]:
    db.scalar(select(func.count(FindingRecord.id)))
    return {"status": "ready"}


@app.get("/api/findings")
def list_findings(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    project_id: str = Query(default="default"),
    _: AuthContext = Depends(require_role(VIEWER_ROLE)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    records = db.scalars(
        select(FindingRecord)
        .where(FindingRecord.project_id == project_id)
        .order_by(FindingRecord.detected_at.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    summary = summary_from_db(db, project_id=project_id)
    return {"summary": summary, "findings": [record_to_schema(r).model_dump(mode="json") for r in records], "limit": limit, "offset": offset}


@app.post("/api/ingest/{scanner}")
async def ingest_report(
    request: Request,
    scanner: str,
    file: UploadFile = File(...),
    project_id: str = Query(default="default"),
    auth: AuthContext = Depends(require_ingestor_access),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    report = json.loads(await file.read())
    findings = detect_and_parse_report(report, scanner, project_id=project_id)
    ingested = await ingest_findings(db, findings)
    audit("ingest_report", request, scanner=scanner, ingested=ingested, actor=auth.subject)
    return {"scanner": scanner, "project_id": project_id, "ingested": ingested, "summary": summary_from_db(db, project_id=project_id)}


@app.post("/api/mcp/ingest")
async def ingest_from_mcp(
    request: Request,
    payload: MCPIngestRequest,
    auth: AuthContext = Depends(require_ingestor_access),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    findings = parse_generic_findings(payload.findings, scanner=payload.scanner, source=payload.source, project_id="default")
    ingested = await ingest_findings(db, findings)
    audit("ingest_mcp", request, scanner=payload.scanner, ingested=ingested, actor=auth.subject)
    return {"scanner": payload.scanner, "source": payload.source, "ingested": ingested, "summary": summary_from_db(db)}


@app.get("/api/ai/insights")
async def ai_insights(
    project_id: str = Query(default="default"),
    _: AuthContext = Depends(require_role(VIEWER_ROLE)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    records = db.scalars(
        select(FindingRecord)
        .where(FindingRecord.project_id == project_id)
        .order_by(FindingRecord.detected_at.desc())
        .limit(1000)
    ).all()
    findings = [record_to_schema(r) for r in records]
    summary = summary_from_db(db, project_id=project_id)
    return await build_openai_ai_insights(findings, summary)


@app.get("/api/projects")
def list_projects(
    _: AuthContext = Depends(require_role(VIEWER_ROLE)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    rows = db.execute(select(FindingRecord.project_id, func.count(FindingRecord.id)).group_by(FindingRecord.project_id)).all()
    return {"projects": [{"project_id": project_id, "findings": count} for project_id, count in rows]}


@app.get("/api/admin/chaos")
def get_chaos(_: AuthContext = Depends(require_role(ADMIN_ROLE))) -> dict[str, Any]:
    return chaos.model_dump()


@app.post("/api/admin/chaos")
def set_chaos(request: Request, payload: ChaosUpdate, _: AuthContext = Depends(require_role(ADMIN_ROLE))) -> dict[str, Any]:
    validate_csrf(request)
    chaos.enabled = payload.enabled
    chaos.latency_ms = payload.latency_ms
    chaos.error_percent = payload.error_percent
    audit("chaos_update", request, **payload.model_dump())
    return chaos.model_dump()


@app.delete("/api/admin/findings")
def reset(
    request: Request,
    auth: AuthContext = Depends(require_role(ADMIN_ROLE)),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    validate_csrf(request)
    count = db.query(FindingRecord).delete()
    db.commit()
    audit("admin_delete_findings", request, actor=auth.subject, deleted=count)
    return {"status": "ok"}


def _auth_from_ws(websocket: WebSocket) -> AuthContext | None:
    if AUTH_MODE != "oidc":
        return AuthContext(subject="system", roles={VIEWER_ROLE, INGESTOR_ROLE, ADMIN_ROLE})
    session_cookie = websocket.cookies.get("session")
    if not session_cookie:
        return None
    # Session parsing is handled by middleware in HTTP only; for WS we require enabled mode + cookie presence as minimum gate.
    # Production deployments should run behind authenticated frontend session and same-origin websocket.
    return AuthContext(subject="oidc-session", roles={VIEWER_ROLE})


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    auth = _auth_from_ws(websocket)
    if not auth or VIEWER_ROLE not in auth.roles:
        await websocket.close(code=1008)
        return
    await ws_manager.connect(websocket)
    try:
        await websocket.send_json({"type": "refresh"})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
