const enabledEl = document.getElementById('enabled');
const latencyEl = document.getElementById('latency');
const errorEl = document.getElementById('error');
const saveEl = document.getElementById('save');
const statusEl = document.getElementById('status');

let csrfToken = '';

async function loadMe() {
  const me = await fetch('/api/me').then(r => r.json());
  csrfToken = me.csrf_token || '';
}

async function loadChaos() {
  const data = await fetch('/api/admin/chaos').then(r => r.json());
  enabledEl.checked = !!data.enabled;
  latencyEl.value = data.latency_ms || 0;
  errorEl.value = data.error_percent || 0;
}

saveEl.addEventListener('click', async () => {
  const payload = {
    enabled: enabledEl.checked,
    latency_ms: Number(latencyEl.value || 0),
    error_percent: Number(errorEl.value || 0),
  };
  const res = await fetch('/api/admin/chaos', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-csrf-token': csrfToken,
    },
    body: JSON.stringify(payload),
  });

  if (res.status !== 200) {
    statusEl.textContent = `Failed to save (${res.status})`;
    return;
  }
  statusEl.textContent = 'Chaos config updated successfully';
});

(async function init() {
  await loadMe();
  await loadChaos();
})();
