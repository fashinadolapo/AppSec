from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field


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
        disconnected: list[WebSocket] = []
        for ws in self.active:
            try:
                await ws.send_json(payload)
            except Exception:
                disconnected.append(ws)
        for ws in disconnected:
            self.disconnect(ws)


class FindingStore:
    def __init__(self) -> None:
        self._findings: dict[str, Finding] = {}

    def reset(self) -> None:
        self._findings = {}

    def upsert(self, finding: Finding) -> None:
        self._findings[finding.id] = finding

    def list(self) -> list[Finding]:
        return sorted(self._findings.values(), key=lambda f: f.detected_at, reverse=True)

    def summary(self) -> dict[str, Any]:
        findings = self.list()
        by_severity: dict[str, int] = {}
        by_scanner: dict[str, int] = {}
        for finding in findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
            by_scanner[finding.scanner] = by_scanner.get(finding.scanner, 0) + 1
        return {
            "total": len(findings),
            "by_severity": by_severity,
            "by_scanner": by_scanner,
        }


store = FindingStore()
ws_manager = ConnectionManager()
app = FastAPI(title="AppSec Fusion Dashboard", version="0.2.0")
app.mount("/static", StaticFiles(directory="static"), name="static")


SEVERITY_RANK = {
    "critical": 4,
    "error": 4,
    "high": 3,
    "warning": 2,
    "medium": 2,
    "note": 1,
    "low": 1,
    "info": 1,
}


def parse_sarif_report(report: dict[str, Any], scanner: str) -> list[Finding]:
    findings: list[Finding] = []
    for run in report.get("runs", []):
        rules: dict[str, dict[str, Any]] = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            rule_id = rule.get("id")
            if rule_id:
                rules[rule_id] = rule

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            rule = rules.get(rule_id, {})
            location = ((result.get("locations") or [{}])[0]).get("physicalLocation", {})
            region = location.get("region", {})
            message = result.get("message", {}).get("text", "")
            recommendation = (
                rule.get("help", {}).get("text")
                or rule.get("shortDescription", {}).get("text")
                or "Review scanner guidance and remediate affected resource."
            )
            findings.append(
                Finding(
                    scanner=scanner,
                    severity=(result.get("level") or "warning").lower(),
                    rule_id=rule_id,
                    title=(rule.get("name") or rule_id),
                    description=message,
                    recommendation=recommendation,
                    file_path=location.get("artifactLocation", {}).get("uri", ""),
                    line=region.get("startLine"),
                    raw=result,
                )
            )
    return findings


def parse_generic_findings(report: list[dict[str, Any]], scanner: str, source: str = "ci") -> list[Finding]:
    findings: list[Finding] = []
    for item in report:
        findings.append(
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
        )
    return findings


async def ingest_findings(findings: list[Finding]) -> int:
    for finding in findings:
        store.upsert(finding)
    await ws_manager.broadcast({"type": "refresh", "summary": store.summary()})
    return len(findings)


def build_local_ai_insights(findings: list[Finding]) -> dict[str, Any]:
    prioritized = sorted(
        findings,
        key=lambda item: (SEVERITY_RANK.get(item.severity, 0), item.detected_at.timestamp()),
        reverse=True,
    )[:5]

    actions = []
    for finding in prioritized:
        action = {
            "finding_id": finding.id,
            "priority": finding.severity,
            "title": finding.title,
            "scanner": finding.scanner,
            "recommendation": finding.recommendation
            or "Triage and patch this issue, then re-scan in CI.",
            "path": finding.file_path,
        }
        actions.append(action)

    summary = store.summary()
    narrative = (
        f"Detected {summary['total']} findings. "
        f"Focus first on {summary['by_severity'].get('critical', 0) + summary['by_severity'].get('error', 0)} critical/error and "
        f"{summary['by_severity'].get('high', 0)} high severity issues."
    )
    return {"provider": "local-heuristic", "narrative": narrative, "actions": actions}


async def build_openai_ai_insights(findings: list[Finding]) -> dict[str, Any]:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return build_local_ai_insights(findings)

    compact_findings = [
        {
            "severity": finding.severity,
            "title": finding.title,
            "scanner": finding.scanner,
            "file_path": finding.file_path,
            "recommendation": finding.recommendation,
        }
        for finding in findings[:100]
    ]

    prompt = {
        "task": "Generate concise remediation guidance for AppSec findings.",
        "requirements": [
            "Return JSON with keys: narrative (string), actions (array of objects with title, priority, recommendation, scanner, path)",
            "Prioritize critical/high findings first",
            "Keep response short and actionable",
        ],
        "findings": compact_findings,
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                "temperature": 0.2,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": "You are an AppSec remediation assistant."},
                    {"role": "user", "content": json.dumps(prompt)},
                ],
            },
        )

    if response.status_code >= 400:
        return build_local_ai_insights(findings)

    body = response.json()
    content = body.get("choices", [{}])[0].get("message", {}).get("content", "{}")
    parsed = json.loads(content)
    return {
        "provider": "openai",
        "narrative": parsed.get("narrative", ""),
        "actions": parsed.get("actions", []),
    }


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return Path("templates/index.html").read_text(encoding="utf-8")


@app.get("/api/findings")
def list_findings() -> dict[str, Any]:
    return {"summary": store.summary(), "findings": [finding.model_dump(mode="json") for finding in store.list()]}


@app.post("/api/ingest/{scanner}")
async def ingest_report(scanner: str, file: UploadFile = File(...)) -> dict[str, Any]:
    payload = await file.read()
    report = json.loads(payload)

    if isinstance(report, dict) and "runs" in report:
        findings = parse_sarif_report(report, scanner)
    elif isinstance(report, list):
        findings = parse_generic_findings(report, scanner)
    elif isinstance(report, dict) and isinstance(report.get("findings"), list):
        findings = parse_generic_findings(report["findings"], scanner)
    else:
        raise HTTPException(status_code=400, detail="Unsupported report format")

    count = await ingest_findings(findings)
    return {"scanner": scanner, "ingested": count, "summary": store.summary()}


@app.post("/api/mcp/ingest")
async def ingest_from_mcp(payload: MCPIngestRequest) -> dict[str, Any]:
    findings = parse_generic_findings(payload.findings, scanner=payload.scanner, source=payload.source)
    count = await ingest_findings(findings)
    return {"scanner": payload.scanner, "source": payload.source, "ingested": count, "summary": store.summary()}


@app.get("/api/ai/insights")
async def ai_insights() -> dict[str, Any]:
    findings = store.list()
    return await build_openai_ai_insights(findings)


@app.post("/api/admin/reset")
def reset() -> dict[str, str]:
    store.reset()
    return {"status": "ok"}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await ws_manager.connect(websocket)
    try:
        await websocket.send_json({"type": "refresh", "summary": store.summary()})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
