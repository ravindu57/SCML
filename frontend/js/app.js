/* Shared nav renderer + Tailwind config injector */

const PAGES = [
  { id: 'dashboard', label: 'Dashboard',         icon: 'dashboard',       href: 'index.html' },
  { id: 'demo',      label: 'Live Agent Demo',   icon: 'play_circle',     href: 'demo.html' },
  { id: 'traffic',   label: 'Traffic',            icon: 'security',        href: 'traffic.html' },
  { id: 'policy',    label: 'Tool Policies',      icon: 'shield_lock',     href: 'policy.html' },
  { id: 'memory',    label: 'Memory Integrity',   icon: 'memory',          href: 'memory.html' },
  { id: 'redaction', label: 'Output Redaction',   icon: 'visibility_off',  href: 'policy.html#redaction' },
  { id: 'audit',     label: 'Audit Logs',         icon: 'receipt_long',    href: 'audit.html' },
];

window.renderNav = (activePage) => {
  const navLinks = PAGES.map(p => {
    const active = p.id === activePage;
    return `<a href="${p.href}" class="${active
      ? 'bg-primary-container/20 text-primary border-l-4 border-primary translate-x-1 shadow-[inset_0_0_15px_rgba(7,152,255,0.1)]'
      : 'text-on-surface-variant hover:bg-surface-variant/50'
    } px-4 py-3 flex items-center gap-3 transition-all rounded-r font-label-caps text-label-caps">
      <span class="material-symbols-outlined text-[20px]" style="${active ? "font-variation-settings:'FILL' 1" : ''}">${p.icon}</span>
      ${p.label}
    </a>`;
  }).join('');

  document.getElementById('side-nav').innerHTML = `
    <div class="px-6 mb-8 flex items-center gap-3">
      <div class="w-9 h-9 rounded-full bg-surface-variant flex items-center justify-center border border-outline-variant/30">
        <span class="material-symbols-outlined text-primary text-[18px]">admin_panel_settings</span>
      </div>
      <div>
        <div class="font-headline-md text-[16px] text-primary font-bold leading-tight">TrustMediator</div>
        <div class="font-label-caps text-label-caps text-on-surface-variant mt-0.5">High-Stakes Mediation</div>
      </div>
    </div>
    <div class="flex-1 flex flex-col gap-1 overflow-y-auto px-2">${navLinks}</div>
    ${renderTemplatePicker()}
    <div class="px-4 mt-6">
      <button id="emergency-lock" onclick="emergencyLock()" class="w-full bg-quarantine-purple/10 text-quarantine-purple border border-quarantine-purple/40 py-2.5 rounded font-label-caps text-label-caps hover:bg-quarantine-purple hover:text-white transition-all flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(124,77,255,0.15)]">
        <span class="material-symbols-outlined text-[18px]">lock</span> Emergency Lock
      </button>
    </div>
    <div class="flex flex-col gap-1 border-t border-outline-variant/20 pt-4 mt-4 px-4">
      <a href="${API_BASE}/docs" target="_blank" class="text-on-surface-variant hover:text-primary px-2 py-2 flex items-center gap-3 transition-all font-label-caps text-label-caps rounded hover:bg-surface-variant/30">
        <span class="material-symbols-outlined text-[18px]">code</span> API Docs
      </a>
    </div>`;

  document.getElementById('top-bar-title').textContent = 'scml - middleware layer secure';
};

/* Emergency lock — revoke every agent's tool authority.

   This used to show a toast saying "all agents in shadow mode" and do nothing
   at all. A security control that reports success without acting is worse than
   no control: it is the one button someone reaches for when they believe
   something is wrong.

   It now writes a real policy version in which every agent's allowed_tools is
   empty, so every tool call is denied by the same deny-by-default path an
   unknown agent hits. It is reversible — the previous version stays in the
   history and can be rolled back from this page.

   Note it is NOT shadow mode. Shadow means observe-and-log without enforcing,
   which is the opposite of what an emergency stop should do. */
window.emergencyLock = async () => {
  if (!confirm(
    'EMERGENCY LOCK\n\n' +
    'Publishes a new policy version with every agent stripped of all tools. ' +
    'All tool calls will be denied until you roll back.\n\nContinue?'
  )) return;

  try {
    const current = await API.getPolicy();
    const policy = JSON.parse(JSON.stringify(current.policy || current));
    const agents = policy.agents || {};
    for (const name of Object.keys(agents)) {
      agents[name].allowed_tools = [];
    }

    const res = await API.updatePolicy({
      policy_data: policy,
      description: 'EMERGENCY LOCK — all tool authority revoked',
      created_by: 'dashboard',
      activate: true,
      shadow: false,
    });

    showToast(
      `Emergency lock active — policy v${res.version_number}. ` +
      `Roll back from Version History to restore.`, 'error');
    if (typeof loadPolicy === 'function') loadPolicy();
  } catch (err) {
    showToast(`Emergency lock FAILED: ${err.message}. Policy unchanged.`, 'error');
  }
};

/* ── Theme templates ───────────────────────────────────────────────────────
   The active template is one stylesheet swapped at <link id="tm-theme">.

   Every page carries that link plus a tiny inline script that sets its href
   from localStorage before first paint, so switching survives navigation and
   no page flashes the wrong theme on the way in.

   Templates 2 and 3 are reserved and currently @import Template 1, so
   selecting one is safe: the pages are Tailwind utilities plus a few inline
   rules, and with no theme layer they render as a broken-looking console. A
   reserved slot that looks familiar beats one that looks broken, particularly
   on a machine someone is demonstrating from. */
window.TEMPLATES = [
  { id: 'template1', label: 'Template 1', note: 'Glass' },
  { id: 'template2', label: 'Template 2', note: 'reserved' },
  { id: 'template3', label: 'Template 3', note: 'reserved' },
];

window.getTemplate = () => localStorage.getItem('tm_template') || 'template1';

window.setTemplate = (id) => {
  if (!window.TEMPLATES.some(t => t.id === id)) return;
  localStorage.setItem('tm_template', id);
  const link = document.getElementById('tm-theme');
  if (link) link.href = `css/${id}.css`;
  document.querySelectorAll('[data-template-option]').forEach(el => {
    const active = el.dataset.templateOption === id;
    el.setAttribute('aria-current', active ? 'true' : 'false');
  });
  const t = window.TEMPLATES.find(x => x.id === id);
  if (typeof showToast === 'function') showToast(`${t.label} applied`, 'info');
};

/* Rendered into the nav rail by renderNav(). A <select> rather than three
   buttons: the rail is narrow, the set will grow, and a native control gets
   keyboard and screen-reader behaviour without any work. */
window.renderTemplatePicker = () => {
  const current = window.getTemplate();
  const options = window.TEMPLATES.map(t =>
    `<option value="${t.id}" ${t.id === current ? 'selected' : ''}>${t.label}${t.note ? ` — ${t.note}` : ''}</option>`
  ).join('');
  return `
    <div class="px-4 mt-4">
      <label for="tm-template-select" class="block text-label-caps text-on-surface-variant mb-1.5">Theme</label>
      <select id="tm-template-select" onchange="setTemplate(this.value)"
        class="w-full bg-surface-container-high border border-outline-variant/40 text-on-surface text-body-sm rounded px-2 py-2">
        ${options}
      </select>
    </div>`;
};

/* Shared Tailwind config — call injectTailwindConfig() in <head> script */
window.TW_COLORS = {
  "surface-container-low": "#121826",
  "primary": "#60a5fa",
  "surface-bright": "#232c3f",
  "success-emerald": "#34d399",
  "surface-dim": "#0b0f17",
  "outline-variant": "#263043",
  "error": "#f87171",
  "surface-container-high": "#1b2333",
  "on-surface": "#e8ecf5",
  "background": "#0b0f17",
  "mediation-blue": "#60a5fa",
  "security-teal": "#34d399",
  "on-surface-variant": "#95a3bd",
  "surface-container": "#151c2c",
  "surface-variant": "#1b2333",
  "surface-charcoal": "#141b28",
  "alert-amber": "#fbbf24",
  "surface": "#0b0f17",
  "primary-container": "#3b82f6",
  "outline": "#5d6b85",
  "quarantine-purple": "#a78bfa",
  "inverse-surface": "#e8ecf5"
};
