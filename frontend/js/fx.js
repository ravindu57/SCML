/* ============================================================================
   Background field for Template 2 "HUD".

   A slow neural lattice with occasional drifting figures, painted to a fixed
   canvas behind the interface.

   Three rules it holds to, because this runs on a machine that is also serving
   a live mediator during a demonstration:

   1. **Subordinate to the content.** Low opacity, slow velocities, no motion
      that crosses the eye quickly. Anything eye-catching enough to notice while
      reading a verdict is too much — the dashboard's job is to be read.
   2. **Cheap.** Node count scales with viewport area and is capped. Edges are
      found on a spatial grid rather than by testing all pairs, so cost grows
      linearly rather than quadratically. Paused entirely when the tab is
      hidden, so a backgrounded dashboard costs nothing.
   3. **Optional.** Declines to mount under prefers-reduced-motion, and only
      mounts when Template 2 is the active theme. It is removed on switching
      away, rather than left running invisibly.
   ========================================================================= */

(function () {
  'use strict';

  const TEMPLATE = 'template2';
  const CANVAS_ID = 'tm-fx';

  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)');

  const activeTemplate = () => {
    try { return localStorage.getItem('tm_template') || 'template1'; }
    catch (e) { return 'template1'; }
  };

  let raf = null;
  let canvas = null;
  let ctx = null;
  let nodes = [];
  let glyphs = [];
  let w = 0, h = 0, dpr = 1;
  let cell = 130;              // spatial-hash cell; also the link radius
  let lastGlyph = 0;

  const CY = '34,211,238';     // accent cyan, matching the theme's --accent
  const IN = '99,102,241';     // indigo, the theme's --accent-2

  function size() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);   // 2 is plenty; 3 costs 2.25x for no visible gain
    w = window.innerWidth;
    h = window.innerHeight;
    canvas.width = Math.floor(w * dpr);
    canvas.height = Math.floor(h * dpr);
    canvas.style.width = w + 'px';
    canvas.style.height = h + 'px';
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    seed();
  }

  function seed() {
    // ~1 node per 26k px², capped. A 1920x1080 screen lands near 78.
    const target = Math.min(95, Math.max(26, Math.round((w * h) / 26000)));
    nodes = new Array(target).fill(0).map(() => ({
      x: Math.random() * w,
      y: Math.random() * h,
      vx: (Math.random() - 0.5) * 0.13,
      vy: (Math.random() - 0.5) * 0.13,
      r: 0.7 + Math.random() * 1.5,
      p: Math.random() * Math.PI * 2,        // phase, for a slow brightness breathe
    }));
  }

  function spawnGlyph(now) {
    // Drifting figures — decimals and hex, the texture of instrument readouts.
    const pool = '0123456789ABCDEF';
    const len = 3 + Math.floor(Math.random() * 4);
    let s = '';
    if (Math.random() < 0.55) {
      s = (Math.random()).toFixed(3);                       // 0.412
    } else {
      for (let i = 0; i < len; i++) s += pool[Math.floor(Math.random() * pool.length)];
    }
    glyphs.push({
      x: Math.random() * w,
      y: h + 16,
      vy: -(0.16 + Math.random() * 0.22),
      text: s,
      born: now,
      life: 9000 + Math.random() * 6000,
      size: 9 + Math.random() * 3,
    });
    // Hard ceiling: a leak here would quietly eat the frame budget.
    if (glyphs.length > 22) glyphs.shift();
  }

  function frame(now) {
    ctx.clearRect(0, 0, w, h);

    // ── advance ──────────────────────────────────────────────────────────
    for (const n of nodes) {
      n.x += n.vx; n.y += n.vy;
      if (n.x < -20) n.x = w + 20; else if (n.x > w + 20) n.x = -20;
      if (n.y < -20) n.y = h + 20; else if (n.y > h + 20) n.y = -20;
    }

    // ── edges, via a spatial hash ────────────────────────────────────────
    // Only neighbouring cells are tested, so this stays linear in node count
    // instead of the n² a naive all-pairs sweep would cost.
    const cols = Math.max(1, Math.ceil(w / cell));
    const rows = Math.max(1, Math.ceil(h / cell));
    const grid = new Map();
    for (const n of nodes) {
      const cx = Math.min(cols - 1, Math.max(0, Math.floor(n.x / cell)));
      const cy = Math.min(rows - 1, Math.max(0, Math.floor(n.y / cell)));
      const key = cy * cols + cx;
      let bucket = grid.get(key);
      if (!bucket) grid.set(key, (bucket = []));
      bucket.push(n);
    }

    ctx.lineWidth = 1;
    for (let cy = 0; cy < rows; cy++) {
      for (let cx = 0; cx < cols; cx++) {
        const here = grid.get(cy * cols + cx);
        if (!here) continue;
        for (let dy = 0; dy <= 1; dy++) {
          for (let dx = -1; dx <= 1; dx++) {
            if (dy === 0 && dx < 0) continue;             // each pair once
            const nx = cx + dx, ny = cy + dy;
            if (nx < 0 || ny < 0 || nx >= cols || ny >= rows) continue;
            const there = grid.get(ny * cols + nx);
            if (!there) continue;
            for (const a of here) {
              for (const b of there) {
                if (a === b) continue;
                const ddx = a.x - b.x, ddy = a.y - b.y;
                const d2 = ddx * ddx + ddy * ddy;
                if (d2 > cell * cell) continue;
                const t = 1 - Math.sqrt(d2) / cell;        // fade with distance
                ctx.strokeStyle = `rgba(${CY},${(t * 0.16).toFixed(3)})`;
                ctx.beginPath();
                ctx.moveTo(a.x, a.y);
                ctx.lineTo(b.x, b.y);
                ctx.stroke();
              }
            }
          }
        }
      }
    }

    // ── nodes ────────────────────────────────────────────────────────────
    for (const n of nodes) {
      const breathe = 0.5 + 0.5 * Math.sin(now / 2600 + n.p);
      ctx.fillStyle = `rgba(${CY},${(0.14 + breathe * 0.26).toFixed(3)})`;
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      ctx.fill();
    }

    // ── drifting figures ─────────────────────────────────────────────────
    if (now - lastGlyph > 1400) { spawnGlyph(now); lastGlyph = now; }
    ctx.font = '500 11px "JetBrains Mono", ui-monospace, monospace';
    for (let i = glyphs.length - 1; i >= 0; i--) {
      const g = glyphs[i];
      const age = now - g.born;
      if (age > g.life || g.y < -20) { glyphs.splice(i, 1); continue; }
      g.y += g.vy;
      // Fade in over the first fifth, out over the last third.
      const inT = Math.min(1, age / (g.life * 0.2));
      const outT = Math.min(1, Math.max(0, (g.life - age) / (g.life * 0.34)));
      const alpha = 0.20 * inT * outT;
      ctx.font = `500 ${g.size}px "JetBrains Mono", ui-monospace, monospace`;
      ctx.fillStyle = `rgba(${i % 4 === 0 ? IN : CY},${alpha.toFixed(3)})`;
      ctx.fillText(g.text, g.x, g.y);
    }

    raf = requestAnimationFrame(frame);
  }

  function start() {
    if (canvas || reduced.matches) return;
    canvas = document.createElement('canvas');
    canvas.id = CANVAS_ID;
    canvas.setAttribute('aria-hidden', 'true');   // decoration: keep it out of the a11y tree
    document.body.insertBefore(canvas, document.body.firstChild);
    ctx = canvas.getContext('2d', { alpha: true });
    size();
    window.addEventListener('resize', size, { passive: true });
    lastGlyph = performance.now();
    raf = requestAnimationFrame(frame);
  }

  function stop() {
    if (raf) cancelAnimationFrame(raf);
    raf = null;
    window.removeEventListener('resize', size);
    if (canvas && canvas.parentNode) canvas.parentNode.removeChild(canvas);
    canvas = null; ctx = null; nodes = []; glyphs = [];
  }

  function sync() {
    if (activeTemplate() === TEMPLATE && !reduced.matches) start();
    else stop();
  }

  // A hidden tab should cost nothing; requestAnimationFrame already throttles,
  // but releasing the loop entirely is cheaper and predictable.
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) { if (raf) { cancelAnimationFrame(raf); raf = null; } }
    else if (canvas && !raf) raf = requestAnimationFrame(frame);
  });

  if (reduced.addEventListener) reduced.addEventListener('change', sync);

  // setTemplate() dispatches this so the field appears and disappears with the
  // theme rather than needing a reload.
  window.addEventListener('tm:template', sync);

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', sync);
  } else {
    sync();
  }
})();
