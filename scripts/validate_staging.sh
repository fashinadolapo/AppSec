#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <base_url>" >&2
  echo "Example: $0 https://appsec-staging-abc-uc.a.run.app" >&2
  exit 1
fi

BASE_URL="${1%/}"
API_KEY="${INGEST_API_KEY:-}"
if [[ -z "$API_KEY" ]]; then
  echo "ERROR: INGEST_API_KEY env var is required for ingest checks." >&2
  exit 1
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

cat > "$tmpdir/semgrep.json" <<JSON
{"results":[{"check_id":"demo.semgrep","path":"src/a.py","start":{"line":10},"extra":{"severity":"ERROR","message":"Demo semgrep"}}]}
JSON

cat > "$tmpdir/trivy.json" <<JSON
{"Results":[{"Target":"alpine","Vulnerabilities":[{"VulnerabilityID":"CVE-2026-0001","Severity":"HIGH","Title":"Demo trivy"}]}]}
JSON

cat > "$tmpdir/checkov.json" <<JSON
{"results":{"failed_checks":[{"check_id":"CKV_AWS_20","check_name":"Demo checkov","severity":"MEDIUM","file_path":"main.tf","file_line_range":[1,2]}]}}
JSON

cat > "$tmpdir/zap.json" <<JSON
{"site":[{"@name":"https://example","alerts":[{"pluginid":"40012","name":"Demo zap","riskdesc":"High (High)","desc":"demo"}]}]}
JSON

cat > "$tmpdir/nuclei.json" <<JSON
[{"template-id":"demo-nuclei","matched-at":"https://example","info":{"name":"Demo nuclei","severity":"low"}}]
JSON

cat > "$tmpdir/sonarqube.json" <<JSON
{"issues":[{"rule":"python:S3649","severity":"CRITICAL","message":"Demo sonar","component":"src/db.py","line":2}]}
JSON

cat > "$tmpdir/snykcode.json" <<JSON
{"issues":[{"id":"js/sql-injection","severity":"high","title":"Demo snyk","description":"demo","filePath":"api.js","lineNumber":5}]}
JSON

cat > "$tmpdir/horusec.json" <<JSON
{"analysisVulnerabilities":[{"vulnerabilities":{"severity":"LOW","ruleID":"HS001","details":"Demo horusec","file":"crypto.go","line":1}}]}
JSON

cat > "$tmpdir/stackhawk.json" <<JSON
{"vulnerabilities":[{"pluginId":"10021","name":"Demo stackhawk","severity":"medium","path":"/","description":"demo"}]}
JSON

health_check() {
  local path="$1"
  echo "==> GET $BASE_URL$path"
  curl -fsS "$BASE_URL$path" >/dev/null
}

ingest_file() {
  local scanner="$1"
  local project="$2"
  local file="$3"
  echo "==> POST /api/ingest/$scanner?project_id=$project"
  curl -fsS -X POST \
    -H "x-api-key: $API_KEY" \
    -F "file=@$file" \
    "$BASE_URL/api/ingest/$scanner?project_id=$project" >/dev/null
}

echo "[1/5] health probes"
health_check "/healthz"
health_check "/readyz"

echo "[2/5] scoped ingest for scanner families (team-a + team-b)"
ingest_file semgrep team-a "$tmpdir/semgrep.json"
ingest_file trivy team-a "$tmpdir/trivy.json"
ingest_file checkov team-a "$tmpdir/checkov.json"
ingest_file zap team-a "$tmpdir/zap.json"
ingest_file nuclei team-a "$tmpdir/nuclei.json"
ingest_file sonarqube team-b "$tmpdir/sonarqube.json"
ingest_file snykcode team-b "$tmpdir/snykcode.json"
ingest_file horusec team-b "$tmpdir/horusec.json"
ingest_file stackhawk team-b "$tmpdir/stackhawk.json"

echo "[3/5] mcp scoped ingest"
curl -fsS -X POST \
  -H "x-api-key: $API_KEY" \
  -H "content-type: application/json" \
  -d '{"source":"mcp","scanner":"custom","project_id":"team-a","findings":[{"title":"demo mcp","severity":"high"}]}' \
  "$BASE_URL/api/mcp/ingest" >/dev/null

cat <<MSG
[4/5] OIDC / session / websocket parity checks (manual)
- Login in browser: $BASE_URL/auth/login
- Verify /api/me returns expected subject/roles after login.
- Open dashboard and confirm WebSocket updates are active for authenticated viewer.
- In a separate private window (not logged in), verify /ws fails (policy violation / close).
MSG

cat <<MSG
[5/5] project scope and admin delete checks
- If your staging uses AUTH_MODE=disabled, run:
    curl -sS "$BASE_URL/api/findings?project_id=team-a&limit=200" | jq '.summary.total'
    curl -sS "$BASE_URL/api/findings?project_id=team-b&limit=200" | jq '.summary.total'
    curl -sS -X DELETE "$BASE_URL/api/admin/findings?project_id=team-a" | jq '.'
- If staging uses OIDC, perform the same checks from an authenticated browser session.
MSG

echo "Validation script completed."
