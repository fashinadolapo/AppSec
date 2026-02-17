from __future__ import annotations

import hashlib
import json
import os
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
from starlette.middleware.sessions import SessionMiddleware


DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./appsec.db")
INGEST_API_KEY = os.getenv("INGEST_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

AUTH_MODE = os.getenv("AUTH_MODE", "disabled").lower()
SESSION_SECRET_KEY = os.getenv("SESSION_SECRET_KEY", "change-me-in-production")
OIDC_DISCOVERY_URL = os.getenv("OIDC_DISCOVERY_URL", "")
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET", "")
OIDC_SCOPES = os.getenv("OIDC_SCOPES", "openid profile email")
ROLE_CLAIM = os.getenv("ROLE_CLAIM", "roles")
VIEWER_ROLE = os.getenv("VIEWER_ROLE", "viewer")
INGESTOR_ROLE = os.getenv("INGESTOR_ROLE", "ingestor")
ADMIN_ROLE = os.getenv("ADMIN_ROLE", "admin")


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


ws_manager = ConnectionManager()
app = FastAPI(title="AppSec Fusion Dashboard", version="1.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in os.getenv("CORS_ALLOW_ORIGINS", "*").split(",")],
    allow_methods=["*"],
    allow_headers=["*"],
)
if AUTH_MODE == "oidc":
    app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET_KEY, same_site="lax", https_only=False)
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


def require_ingestor_access(x_api_key: str | None = Header(default=None), auth: AuthContext | None = Depends(optional_auth)) -> AuthContext:
    if INGEST_API_KEY:
        if x_api_key == INGEST_API_KEY:
            return auth or AuthContext(subject="api-key", roles={INGESTOR_ROLE})
        if AUTH_MODE == "oidc" and auth and INGESTOR_ROLE in auth.roles:
            return auth
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Ingestor role or valid API key required")

    if auth and INGESTOR_ROLE in auth.roles:
        return auth
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Ingestor role or valid API key required")


def fingerprint_finding(finding: Finding) -> str:
    payload = f"{finding.scanner}|{finding.rule_id}|{finding.file_path}|{finding.line}|{finding.title}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def record_to_schema(record: FindingRecord) -> Finding:
    return Finding(
        id=record.id,
        scanner=record.scanner,
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


def parse_sarif_report(report: dict[str, Any], scanner: str) -> list[Finding]:
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


def parse_generic_findings(report: list[dict[str, Any]], scanner: str, source: str = "ci") -> list[Finding]:
    return [
        Finding(
            scanner=scanner,
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


def summary_from_db(db: Session) -> dict[str, Any]:
    rows = db.execute(select(FindingRecord.severity, FindingRecord.scanner)).all()
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
    actions = [
        {
            "finding_id": f.id,
            "priority": f.severity,
            "title": f.title,
            "scanner": f.scanner,
            "recommendation": f.recommendation or "Triage, patch, and re-scan in CI.",
            "path": f.file_path,
        }
        for f in prioritized
    ]
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
    payload = {
        "task": "Generate concise AppSec remediation guidance as JSON",
        "requirements": ["Return JSON keys: narrative, actions", "Prioritize critical/high first"],
        "summary": summary,
        "findings": compact,
    }
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


@app.get("/")
def dashboard(auth: AuthContext = Depends(require_role(VIEWER_ROLE))) -> HTMLResponse:
    html = Path("templates/index.html").read_text(encoding="utf-8").replace("__USER_EMAIL__", auth.email or auth.subject)
    return HTMLResponse(html)


@app.get("/api/me")
def me(auth: AuthContext = Depends(require_role(VIEWER_ROLE))) -> dict[str, Any]:
    return {"subject": auth.subject, "email": auth.email, "roles": sorted(auth.roles), "auth_mode": AUTH_MODE}


@app.get("/auth/login")
async def auth_login(request: Request) -> RedirectResponse:
    if AUTH_MODE != "oidc":
        return RedirectResponse(url="/", status_code=302)
    client = oauth.create_client("oidc")
    if client is None:
        raise HTTPException(status_code=500, detail="OIDC client not configured")
    redirect_uri = request.url_for("auth_callback")
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
    return RedirectResponse(url="/", status_code=302)


@app.get("/auth/logout")
def auth_logout(request: Request) -> RedirectResponse:
    if hasattr(request, "session"):
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
    _: AuthContext = Depends(require_role(VIEWER_ROLE)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    records = db.scalars(select(FindingRecord).order_by(FindingRecord.detected_at.desc()).offset(offset).limit(limit)).all()
    summary = summary_from_db(db)
    return {"summary": summary, "findings": [record_to_schema(r).model_dump(mode="json") for r in records], "limit": limit, "offset": offset}


@app.post("/api/ingest/{scanner}")
async def ingest_report(
    scanner: str,
    file: UploadFile = File(...),
    _: AuthContext = Depends(require_ingestor_access),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    report = json.loads(await file.read())
    if isinstance(report, dict) and "runs" in report:
        findings = parse_sarif_report(report, scanner)
    elif isinstance(report, list):
        findings = parse_generic_findings(report, scanner)
    elif isinstance(report, dict) and isinstance(report.get("findings"), list):
        findings = parse_generic_findings(report["findings"], scanner)
    else:
        raise HTTPException(status_code=400, detail="Unsupported report format")
    ingested = await ingest_findings(db, findings)
    return {"scanner": scanner, "ingested": ingested, "summary": summary_from_db(db)}


@app.post("/api/mcp/ingest")
async def ingest_from_mcp(
    payload: MCPIngestRequest,
    _: AuthContext = Depends(require_ingestor_access),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    findings = parse_generic_findings(payload.findings, scanner=payload.scanner, source=payload.source)
    ingested = await ingest_findings(db, findings)
    return {"scanner": payload.scanner, "source": payload.source, "ingested": ingested, "summary": summary_from_db(db)}


@app.get("/api/ai/insights")
async def ai_insights(
    _: AuthContext = Depends(require_role(VIEWER_ROLE)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    records = db.scalars(select(FindingRecord).order_by(FindingRecord.detected_at.desc()).limit(1000)).all()
    findings = [record_to_schema(r) for r in records]
    summary = summary_from_db(db)
    return await build_openai_ai_insights(findings, summary)


@app.delete("/api/admin/findings")
def reset(
    _: AuthContext = Depends(require_role(ADMIN_ROLE)),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    db.query(FindingRecord).delete()
    db.commit()
    return {"status": "ok"}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await ws_manager.connect(websocket)
    try:
        await websocket.send_json({"type": "refresh"})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
