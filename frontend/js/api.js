/* TrustMediator Frontend — API Client */

/* Which mediator these pages talk to.
   This was hardcoded to http://localhost:8000, which is right for the single
   laptop case and wrong for every other one: an agent running on a second
   machine reports to a mediator that is not on the viewer's localhost, so the
   dashboard showed an empty page with no clue why. Resolution order is the
   same as the session id — ?api= in the URL, then the last one used in this
   browser, then localhost. So

       audit.html?api=http://192.168.1.42:8000&session=truelane-live

   pins a remote mediator and remembers it. */
const DEFAULT_API_BASE = 'http://localhost:8000';

const resolveApiBase = () => {
  const q = new URLSearchParams(location.search).get('api');
  if (q && q.trim()) {
    const url = q.trim().replace(/\/+$/, '');
    localStorage.setItem('tm_api_base', url);
    return url;
  }
  return localStorage.getItem('tm_api_base') || DEFAULT_API_BASE;
};

const API_BASE = resolveApiBase();

/* API key for production mode (X-API-Key). Stored in localStorage; on the
   first 401/403 the user is prompted once and the key is remembered. */
let API_KEY = localStorage.getItem('tm_api_key') || '';

const authHeaders = () => (API_KEY ? { 'X-API-Key': API_KEY } : {});

const promptForKey = () => {
  let k = null;
  try {
    // Some embedded browsers don't implement prompt(); fall back to
    // window.API.setKey('<key>') from the console in that case.
    k = window.prompt('TrustMediator API key (X-API-Key header):', API_KEY);
  } catch {
    return false;
  }
  if (k && k.trim() && k.trim() !== API_KEY) {
    API_KEY = k.trim();
    localStorage.setItem('tm_api_key', API_KEY);
    return true;
  }
  return false;
};

const req = async (path, opts = {}) => {
  const r = await fetch(API_BASE + path, {
    ...opts,
    headers: { ...authHeaders(), ...(opts.headers || {}) },
  });
  if ((r.status === 401 || r.status === 403) && promptForKey()) {
    return req(path, opts);
  }
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.json();
};

const reqText = async (path) => {
  const r = await fetch(API_BASE + path, { headers: authHeaders() });
  if ((r.status === 401 || r.status === 403) && promptForKey()) {
    return reqText(path);
  }
  if (!r.ok) throw new Error(`${r.status}`);
  return r.text();
};

window.API = {
  setKey:            (k) => { API_KEY = k; localStorage.setItem('tm_api_key', k); },
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

/* ── Active audit session ───────────────────────────────────────────────────
   The audit, traffic and overview pages are filtered by session id, and each
   hardcoded "demo-traffic" — the session exhibition.sh seeds. That is right
   for the seeded demo and wrong for everything else: a real integration (an
   agent on another machine, say) uses its own session id, so its traffic
   arrives in the database and the dashboard shows an empty table.

   Resolution order: ?session= in the URL, then the last session used in this
   browser, then the seeded default. So

       audit.html?session=shipping-live

   pins a live integration's session and remembers it across pages and
   reloads, while opening the pages bare still shows the seeded demo. */
const DEFAULT_SESSION = 'demo-traffic';

window.SESSION = {
  DEFAULT: DEFAULT_SESSION,
  get() {
    const q = new URLSearchParams(location.search).get('session');
    if (q && q.trim()) {
      localStorage.setItem('tm_session', q.trim());
      return q.trim();
    }
    return localStorage.getItem('tm_session') || DEFAULT_SESSION;
  },
  set(s) {
    if (s && s.trim()) localStorage.setItem('tm_session', s.trim());
  },
};

/* Seed every page's session input from the resolved session and remember
   edits. Runs before the pages' own DOMContentLoaded handlers because this
   script is loaded first, so their initial load already uses the right id. */
document.addEventListener('DOMContentLoaded', () => {
  for (const id of ['session-filter', 'session-id', 'session-input']) {
    const el = document.getElementById(id);
    if (!el) continue;
    el.value = window.SESSION.get();
    el.addEventListener('change', () => window.SESSION.set(el.value));
  }
});

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
