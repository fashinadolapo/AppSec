const summaryEl = document.getElementById('summary');
const tableEl = document.getElementById('findings-body');
const aiInsightsEl = document.getElementById('ai-insights');
const meEl = document.getElementById('me');

function severityBadge(sev) {
  const normalized = (sev || 'unknown').toLowerCase();
  return `<span class="badge ${normalized}">${normalized}</span>`;
}

async function refreshMe() {
  const res = await fetch('/api/me');
  if (res.status !== 200) {
    meEl.innerHTML = '<a href="/auth/login">Login</a>';
    return;
  }
  const data = await res.json();
  meEl.innerHTML = `<strong>User:</strong> ${data.email || data.subject} <br/><strong>Roles:</strong> ${(data.roles || []).join(', ') || 'none'} <br/><a href="/auth/logout">Logout</a>`;
}

async function refreshInsights() {
  const res = await fetch('/api/ai/insights');
  const data = await res.json();
  const actions = (data.actions || []).slice(0, 5).map((a) => {
    return `<li><strong>${a.priority || 'unknown'}</strong> [${a.scanner || '-'}] ${a.title || '-'} → ${a.recommendation || '-'}</li>`;
  }).join('');

  aiInsightsEl.innerHTML = `
    <strong>AI Insights Provider:</strong> ${data.provider}
    <br/><strong>Summary:</strong> ${data.narrative || 'No insights yet'}
    <br/><strong>Priority Actions:</strong>
    <ul>${actions || '<li>No actions yet</li>'}</ul>
  `;
}

async function refresh() {
  const res = await fetch('/api/findings');
  const data = await res.json();

  const bySeverity = Object.entries(data.summary.by_severity || {})
    .map(([k, v]) => `${k}: ${v}`)
    .join(' • ');

  const byScanner = Object.entries(data.summary.by_scanner || {})
    .map(([k, v]) => `${k}: ${v}`)
    .join(' • ');

  summaryEl.innerHTML = `
    <strong>Total Findings:</strong> ${data.summary.total}
    <br/><strong>Severity:</strong> ${bySeverity || 'none'}
    <br/><strong>Scanners:</strong> ${byScanner || 'none'}
  `;

  tableEl.innerHTML = data.findings.map((f) => `
    <tr>
      <td>${f.scanner}</td>
      <td>${severityBadge(f.severity)}</td>
      <td>${f.title}</td>
      <td>${f.file_path || '-'}</td>
      <td>${f.line || '-'}</td>
      <td>${f.recommendation || '-'}</td>
      <td>${f.source || '-'}</td>
    </tr>
  `).join('');

  await refreshInsights();
}

const wsProto = window.location.protocol === 'https:' ? 'wss' : 'ws';
const ws = new WebSocket(`${wsProto}://${window.location.host}/ws`);
ws.onmessage = () => refresh();

refreshMe();
refresh();
