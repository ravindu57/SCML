/* TrustMediator Frontend — API Client */
const API_BASE = 'http://localhost:8000';

const req = async (path, opts = {}) => {
  const r = await fetch(API_BASE + path, opts);
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.json();
};

const reqText = async (path) => {
  const r = await fetch(API_BASE + path);
  if (!r.ok) throw new Error(`${r.status}`);
  return r.text();
};

window.API = {
  health:            ()  => req('/health'),
  metrics:           ()  => reqText('/metrics'),
  quarantined:       ()  => req('/v1/mediate/memory/quarantined'),
  releaseMemory:     (id)=> req(`/v1/mediate/memory/quarantined/${id}/release`, { method: 'POST' }),
  purgeMemory:       (id)=> req(`/v1/mediate/memory/quarantined/${id}`, { method: 'DELETE' }),
  auditReplay:       (s) => req(`/v1/audit/replay/${s}`),
  getPolicy:         ()  => req('/v1/policy'),
  getPolicyVersions: ()  => req('/v1/policy/versions'),
  updatePolicy:      (d) => req('/v1/policy', { method: 'PUT', headers: {'Content-Type':'application/json'}, body: JSON.stringify(d) }),
  rollbackPolicy:    (id)=> req(`/v1/policy/rollback/${id}`, { method: 'POST' }),
  mediateContext:    (d) => req('/v1/mediate/context',   { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(d) }),
  mediateToolCall:   (d) => req('/v1/mediate/tool-call', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(d) }),
};

/* Parse Prometheus text → { metricName: [{labels,value}] } */
window.parseMetrics = (text) => {
  const out = {};
  for (const line of text.split('\n')) {
    if (!line || line.startsWith('#')) continue;
    const m = line.match(/^([^\{]+?)(?:\{([^\}]*)\})?\s+([\d.e+\-]+)$/);
    if (!m) continue;
    const [, name, labelsRaw, val] = m;
    const labels = {};
    (labelsRaw || '').split(',').forEach(p => {
      const [k, v] = p.split('=');
      if (k && v) labels[k.trim()] = v.replace(/"/g, '').trim();
    });
    (out[name.trim()] = out[name.trim()] || []).push({ labels, value: parseFloat(val) });
  }
  return out;
};

/* Avg latency in ms across all /v1/ endpoints */
window.calcAvgLatencyMs = (m) => {
  const sums   = m['trustmediator_request_duration_seconds_sum']   || [];
  const counts = m['trustmediator_request_duration_seconds_count'] || [];
  let s = 0, c = 0;
  sums.filter(x => (x.labels.endpoint||'').startsWith('/v1/')).forEach(x => s += x.value);
  counts.filter(x => (x.labels.endpoint||'').startsWith('/v1/')).forEach(x => c += x.value);
  return c ? (s / c * 1000).toFixed(1) : '—';
};

window.calcThroughput = (m) => {
  const counts = m['trustmediator_request_duration_seconds_count'] || [];
  return counts.filter(x => (x.labels.endpoint||'').startsWith('/v1/')).reduce((a,x) => a + x.value, 0);
};

window.fmtTime = (iso) => iso ? new Date(iso).toLocaleTimeString('en-GB', {hour12:false}) : '—';
window.fmtTs   = (iso) => iso ? new Date(iso).toISOString().replace('T',' ').slice(0,19)+' UTC' : '—';

window.decisionColor = (d) => ({
  block: 'text-error', escalate: 'text-alert-amber', quarantine: 'text-quarantine-purple',
  allow: 'text-security-teal', reject: 'text-error', transform: 'text-alert-amber'
}[d?.toLowerCase()] || 'text-on-surface-variant');

window.decisionBadge = (d) => ({
  block:      'border-error/40 text-error',
  escalate:   'border-alert-amber/40 text-alert-amber',
  quarantine: 'border-quarantine-purple/40 text-quarantine-purple',
  allow:      'border-security-teal/40 text-security-teal',
  reject:     'border-error/40 text-error',
  transform:  'border-alert-amber/40 text-alert-amber',
}[d?.toLowerCase()] || 'border-outline-variant/40 text-on-surface-variant');

window.showToast = (msg, type = 'info') => {
  const colors = { info: 'bg-mediation-blue', success: 'bg-security-teal text-black', error: 'bg-error text-black' };
  const t = document.createElement('div');
  t.className = `fixed bottom-6 right-6 z-[999] px-5 py-3 rounded-lg font-code-sm text-code-sm text-white shadow-xl transition-all ${colors[type] || colors.info}`;
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3000);
};
