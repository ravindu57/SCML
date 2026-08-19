# SCML — Demo Video Production Workflow

Target: a **6-minute** submission video in four chapters. Three chapters are
sourced from the existing cinematic animation; one chapter (the live demo) is a
**real screen recording** that replaces the animation's simulated demo scene.

| # | Chapter | Length | Source |
|---|---------|-------:|--------|
| 1 | Solution overview | 1:00 | Animation scenes 1–6 (condensed) |
| 2 | **Live demo** | 3:00 | **Real screen recording** (replaces animation scene 7) |
| 3 | Key features & tech stack | 1:00 | Animation scene 8 (as-is) |
| 4 | Closing — impact + future scope | 1:00 | **Recreated** (animation scenes 9–10 rebuilt) |

The animation's own runtime is 6:30. Its non-live content (scenes 1–6, 8–10)
is what we compress/re-cut down to ~3 minutes; the freed 3 minutes become the
real live demo.

---

## Resource 1 — the cinematic animation (what exists)

File: `.claude/worktrees/scml-cinematic-demo-f31050/scml_cinematic_demo.html`
(2,509 lines, single self-contained HTML — no build step, no external assets).

**Theme / style / hook (do NOT change):** dark cinematic stage, a rotating 3D
"machine" of stacked layers, glass panels, mono/serif type pairing, synthesised
audio cues (no copyrighted audio), and a self-narrating script spoken live by
the browser's speech engine. Keyboard transport is the hook: `SPACE` play/pause,
`R` restart, `←/→` jump scene, `V` voice, `M` sound, `N` script panel, `C`
captions.

**Scene map (timings are seconds from start):**

| Scene | Name | Window | Use in video |
|-------|------|--------|--------------|
| 1 | Introduction | 0:00–0:28 | Overview |
| 2 | The problem | 0:28–1:02 | Overview |
| 3 | Start from code | 1:02–1:32 | Overview |
| 4 | Architecture | 1:32–2:32 | Overview |
| 5 | Trust labels | 2:32–3:12 | Overview |
| 6 | Mediation | 3:12–3:57 | Overview |
| 7 | **Live demo (simulated)** | 3:57–5:12 | **CUT — replace with real recording** |
| 8 | Features & stack | 5:12–5:57 | Key features chapter |
| 9 | Complete system | 5:57–6:15 | Closing (rebuilt) |
| 10 | Closing | 6:15–6:30 | Closing (rebuilt) |

Scene 7 self-labels as simulated ("Latencies are illustrative"), which is
exactly why it must be swapped for real footage — otherwise the submission's
"real live demo" requirement isn't met.

---

## Resource 2 — the live demo surfaces (what to record)

All served locally right now:

- **Live Agent Demo** — `http://localhost:3002/demo.html`
  The hero. SSE-driven real-time mission: AI agent → security gateway →
  environment, with live BLOCKED/ALLOWED counters, per-event decision +
  latency, threat analytics, and a "tamper-evident audit chain" badge. Needs
  no API key.
- **Security Command Center** — `http://localhost:3002/index.html`
  Gateway ACTIVE / Fail-Closed READY, avg latency, total requests, live audit
  trail, active interventions. Needs the API key set once (`window.API.setKey`).
- **Policy Control** — `http://localhost:3002/policy.html` — per-agent tool
  allow-lists (the least-agency story).
- **Memory Integrity** — `http://localhost:3002/memory.html` — quarantine list.
- **Audit Logs** — `http://localhost:3002/audit.html` — hash-chain replay.
- **Traffic Analysis** — `http://localhost:3002/traffic.html`.
- **API docs (Swagger)** — `http://localhost:8000/docs` — proves it's a real
  service, not a mockup.

Backing evidence you can show as real: the API returns genuine decisions
(injection → `block`, memory poison → `reject`, unlisted tool →
`deny.not_allowlisted`, safe tool → `allow`), and `GET /v1/audit/replay/{session}`
returns a SHA-256 chain with `chain_valid: true`.

---

## Chapter 1 — Solution overview (1:00)

**Goal:** the problem, the approach, the architecture — fast.

**Visual:** screen-record animation scenes 1–6, then cut to ~60s. Play with
voice on (`V`), then either (a) let the animation's own narration carry it, or
(b) mute it and record your own VO using the script below.

**Narration (condense to ~60s):**
> "An AI agent reads everything you give it — your question, a retrieved
> document, a tool's output, its own memory. To the model it's all just text, so
> a poisoned document can issue orders and the model can't tell the difference.
> That's indirect prompt injection, and nothing in a normal stack keeps
> instructions and data apart. SCML is a secure middleware layer that sits
> *between* the agent and its tools. Every value is labelled by where it came
> from, scanned for manipulation, and checked against policy before any action.
> If anything is wrong, the answer is no — it fails closed. SCML authorises a
> tool call; it never executes one."

**Editing tip:** scenes 4 (architecture) and 6 (mediation) are the most
important visuals — give them the most screen time; trim 3 and 5.

---

## Chapter 2 — LIVE DEMO (3:00) — real recording

This is the chapter that must be real footage. Record it as a clean screen
capture with the pre-flight below done first.

### Pre-flight (once, before recording)
1. Confirm stack is up: `curl -s localhost:8000/health` → `{"status":"ok"...}`.
2. Open `http://localhost:3002/index.html`, set the API key when prompted (or
   `window.API.setKey('<key>')` in the console), so the dashboard panels fill.
3. Open `http://localhost:3002/demo.html` and let one mission cycle play so the
   counters aren't zero when you start.
4. Hide bookmarks bar; full-screen the browser; 1080p or higher.

### Shot list (≈3:00)

| Time | Screen | What to show / say |
|-----:|--------|--------------------|
| 0:00–0:35 | `demo.html` | "This is a real autonomous agent running against the live gateway." Point at the agent → gateway → environment flow and the CONNECTED status. |
| 0:35–1:15 | `demo.html` | Walk the event history: Prompt Injection → **BLOCK**, Memory Poisoning → **REJECT**, Unauthorised Tool → **DENY**, Destructive Tool → **DENY**, with real latencies (6–23 ms). Contrast with the ALLOWED safe steps. |
| 1:15–1:35 | `demo.html` | Threat Analytics panel: "4 threats intercepted out of 10 events," and the **Tamper-evident** audit-chain badge. |
| 1:35–2:05 | `index.html` | Command Center: Gateway ACTIVE, Fail-Closed READY, live latency/requests, Live Audit Trail populating. |
| 2:05–2:25 | `policy.html` | Show the per-agent allow-list — "the agent may only call these four tools; everything else is denied by default." |
| 2:25–2:45 | Swagger `/docs` | Prove it's a real API: expand `POST /v1/mediate/tool-call`, show the `deny.not_allowlisted` response. (Optional: `audit.html` hash-chain replay instead.) |
| 2:45–3:00 | `demo.html` | Return to the live view for a strong close on the running system. |

**Say, honestly:** "detection here is a heuristic + policy engine — the
enforcement, audit chain, and fail-closed behaviour are real and verifiable."
Do NOT claim AI/ML detection accuracy or a trained model; that's future scope.

---

## Chapter 3 — Key features & tech stack (1:00)

**Visual:** animation scene 8, as-is (it's already complete and on-theme).

**Features shown (all real):** provenance trust labelling · taint propagation ·
control-path isolation · prompt-injection scanning (heuristic → pluggable
classifier) · least-agency tool policy · human-in-the-loop escalation · memory
integrity · output redaction · SHA-256 tamper-evident audit · fail-closed by
default.

**Stack shown:** Python 3.11 / Pydantic v2 · FastAPI / Uvicorn · PostgreSQL +
Redis · scikit-learn TF-IDF + regex + Shannon-entropy detection · REST + gRPC ·
Docker Compose / Kubernetes / GitHub Actions CI.

---

## Chapter 4 — Closing (1:00) — recreated

The current animation closing (scenes 9–10) is only 30s and is a stylistic
sign-off with no impact/future-scope substance. It is rebuilt to two 30s beats.
On-screen text keeps the existing theme (glass panels, mono labels, big serif).

### 4a. Expected impact (0:30)
> "Agentic AI is being wired into real systems faster than it's being secured,
> and the core weakness — instructions and data sharing one channel — has no
> fix inside the model. SCML gives teams a single, auditable control point
> between the agent and the real world: every action is labelled, mediated, and
> logged to a tamper-evident chain. It turns 'trust the model' into 'verify
> every side effect' — the difference between an agent that *might* be safe and
> one you can prove was."

### 4b. Future scope & next steps (0:30)
> "Next: replace the heuristic scanner with the trained ML classifier to drive
> injection attack-success-rate down toward the sub-10% target, and validate it
> on external benchmarks — AgentDojo and InjecAgent — rather than our own
> corpus. Then a sandboxed tool executor so risky calls run in isolation, and
> production hardening with TLS/mTLS and a secrets manager. The layer is built;
> the roadmap is making its detection provably strong."

**Accuracy guardrails (important for a submission):**
- Frame the ML classifier, external benchmarks, sandboxed executor, and
  TLS/secrets manager as *future scope* — they are not shipped.
- If you cite a number, the honest one is "~33% ASR measured today, target
  <10%." Don't imply the target is already met.

---

## The animation cut is built — `scml_cinematic_demo_3min.html`

A dedicated **3:58** cut exists alongside the full 6:30 film (original kept 100%
intact). Five scenes, back to back, including the signature layer animation:

| Segment | Window | Scene |
|---------|--------|-------|
| Introduction | 0:00–0:28 | Intro |
| Architecture (layer animation) | 0:28–1:28 | the six layers assemble/separate |
| Mediation | 1:28–2:13 | the five modules + decision space |
| Features & stack | 2:13–2:58 | Features |
| Closing (impact + future) | 2:58–3:58 | rebuilt closing |

The film's simulated demo scene is dropped (real footage replaces it). The 3D
machine is shown **only** in the Architecture scene — its camera clock is
remapped so the layers assemble exactly as authored — and hidden elsewhere so it
can't bleed into the closing title. Verified in-browser: no JS errors, each
scene isolated, layers animate (separation 0→1), narration/captions/audio all
remapped. Preview: `http://localhost:3003/scml_cinematic_demo_3min.html` (SPACE).

## Final assembly

1. **Record the animation** in one pass: open `scml_cinematic_demo_3min.html`
   full-screen, press `SPACE`, record to the end (3:58). `C` toggles captions.
2. **Record the 3-min live demo** separately, per the shot list above.
3. **Splice — one cut.** Cut the animation recording at **2:13** (end of
   Mediation, where the film originally showed its demo) and insert the 3-min
   live demo there. Order: intro + architecture + mediation (0:00–2:13) →
   live demo (3:00) → features + closing (1:45).
4. **Export** 1080p, H.264.

**Total runtime ≈ 6:58.** Including the architecture scene pushed the animation
to ~4 min, so with the 3-min live demo the whole video is ~7 min — over the
original 6-min target. If a hard 6-min cap matters, trim the live demo to ~2 min
or drop the Mediation scene (saves 45s); otherwise this is the fullest version.

## Closing — implemented in the HTML ✅
The rebuilt closing is now live in `scml_cinematic_demo.html`. Scene 10 was
extended from 0:15 to 1:00 (film total 6:30 → 7:15), keeping theme/style/hook:
- **0–7s** "Labelled. Mediated. Auditable." (unchanged)
- **8–21s** Expected impact beat (new)
- **23–42s** Future scope — four roadmap rows (new)
- **45–60s** SCML title reveal + "Built for a safer digital future." (finale)

Narration (`VO[]`), the caption panel (`NARRATION[]`), audio cues, and the
timeline duration labels were all updated to match, so the film still narrates
itself. Verified in-browser: no JS errors, beats sequence correctly, title
reveals last.

Preview it: `python3 -m http.server 3003 --directory "<worktree>"` then open
`http://localhost:3003/scml_cinematic_demo.html` and press SPACE. The file lives
in the worktree: `.claude/worktrees/scml-cinematic-demo-f31050/`.
