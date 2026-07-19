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
    <div class="px-4 mt-6">
      <button id="emergency-lock" onclick="emergencyLock()" class="w-full bg-quarantine-purple/10 text-quarantine-purple border border-quarantine-purple/40 py-2.5 rounded font-label-caps text-label-caps hover:bg-quarantine-purple hover:text-white transition-all flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(124,77,255,0.15)]">
        <span class="material-symbols-outlined text-[18px]">lock</span> Emergency Lock
      </button>
    </div>
    <div class="flex flex-col gap-1 border-t border-outline-variant/20 pt-4 mt-4 px-4">
      <a href="http://localhost:8000/docs" target="_blank" class="text-on-surface-variant hover:text-primary px-2 py-2 flex items-center gap-3 transition-all font-label-caps text-label-caps rounded hover:bg-surface-variant/30">
        <span class="material-symbols-outlined text-[18px]">code</span> API Docs
      </a>
    </div>`;

  document.getElementById('top-bar-title').textContent = 'scml - middleware layer secure';
};

window.emergencyLock = async () => {
  if (!confirm('⚠️ EMERGENCY LOCK: This will set all agents to SHADOW mode. Continue?')) return;
  showToast('Emergency lock engaged — all agents in shadow mode', 'error');
};

/* Shared Tailwind config — call injectTailwindConfig() in <head> script */
window.TW_COLORS = {
  "surface-container-low":"#131b2e","on-primary":"#003259","primary":"#a0c9ff",
  "surface-bright":"#31394d","success-emerald":"#10B981","surface-dim":"#0b1326",
  "outline-variant":"#3f4753","error":"#ffb4ab","surface-container-high":"#222a3d",
  "on-surface":"#dae2fd","background":"#0b1326","mediation-blue":"#0798FF",
  "security-teal":"#00FFC2","on-background":"#dae2fd","on-surface-variant":"#bfc7d5",
  "surface-container":"#171f33","secondary":"#cdbdff","surface-variant":"#2d3449",
  "surface-charcoal":"#1E293B","alert-amber":"#FFB800","error-container":"#93000a",
  "surface":"#0b1326","primary-container":"#0798ff","outline":"#89919e","on-error":"#690005",
  "quarantine-purple":"#7C4DFF","surface-container-highest":"#2d3449",
  "inverse-surface":"#dae2fd"
};
