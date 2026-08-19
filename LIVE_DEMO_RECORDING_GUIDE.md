# SCML — Live Demo Recording Guide (≈3 minutes)

Seven sectors, one continuous screen recording, with narration. Order is chosen
to tell a story: **prove it's real → show it running → inspect each defence.**

Target: **3:00–3:15**. Each sector below has: **DO** (what to click) and
**SAY** (narration, ~natural speaking pace).

---

## PRE-FLIGHT (do this BEFORE hitting record)

1. **Stack up?** In a terminal: `curl -s localhost:8000/health` → should return
   `{"status":"ok"...}`. If refused, see the recovery block at the bottom.
2. **Open 3 browser tabs**, in this order (left to right):
   - Tab 1 — `http://localhost:8000/docs` (Swagger)
   - Tab 2 — `http://localhost:3002/index.html` (Dashboard; nav bar reaches the
     other pages)
   - Tab 3 — `http://localhost:3002/demo.html` (Live Agent Demo)
3. **Authorize Swagger (Tab 1):** click **Authorize**, paste the API key, Authorize, Close.
4. **Key the dashboard (Tab 2):** if prompted, paste the same key; else run in the
   console `window.API.setKey('<key>')` and reload. Confirm Gateway: ACTIVE.
5. **Prime the live demo (Tab 3):** let one mission cycle finish so counters
   aren't zero, then leave it — you'll re-enter it on camera at a fresh mission.
6. **Traffic & Audit auto-load** session **`demo-traffic`** now (box pre-filled,
   data shows on open — no typing). **One-time:** hard-refresh each page once
   (`Ctrl+Shift+R`) to clear any cached older copy, or they'll look empty.
7. Full-screen the browser, hide the bookmarks bar, 1080p+.

Keep this narration honest: the scanner is a **heuristic + policy engine**; the
enforcement, audit chain, and fail-closed behaviour are the real, provable parts.
Do **not** claim ML/AI detection accuracy — that's future scope.

---

## 1 · Swagger API — "it's a real service" (0:00–0:25)

**DO:** Start on Tab 1 (`/docs`). Scroll the endpoint list. Expand
`POST /v1/mediate/tool-call`, click **Try it out**, and send a body with
`tool_name: "delete_all_files"`, `agent_id: "default"`. Show the response.

**SAY:**
> "SCML isn't a mockup — it's a running FastAPI service. Every mediation
> decision is a real HTTP endpoint. Here I ask it to authorise a destructive
> tool call on the default agent… and it returns `deny.not_allowlisted`. The
> gateway refuses anything that isn't explicitly permitted."

---

## 2 · Dashboard — the command center (0:25–0:50)

**DO:** Switch to Tab 2 (`index.html`). Point at the top row.

**SAY:**
> "This is the security command center. Gateway active, fail-closed ready — if
> the mediator ever errors, side effects are denied by default. Live latency,
> total requests, and a running audit trail. Everything you see is pulled from
> the live API."

---

## 3 · Live Agent Demo — the hero (0:50–1:45)

**DO:** Switch to Tab 3 (`demo.html`). Wait for a **fresh** mission to start
(counters reset, "Mission Initialisation"). Let it play; point at the event
history as decisions land.

**SAY:**
> "Now a real autonomous agent runs a research mission through the gateway.
> Watch the pipeline mediate every step in real time. A safe web search —
> allowed. Then the attacks: a prompt-injection in retrieved content — blocked.
> A memory-poisoning write — rejected. An unauthorised tool, and a destructive
> tool — both denied. Four threats intercepted, the legitimate work allowed —
> and every decision is written to a tamper-evident chain, shown bottom-right."

*(Tip: if it says "Waiting for orchestrator", wait ~30s for the next mission —
that's the SSE loop starting a fresh session, and it's the clean way in.)*

---

## 4 · Traffic — ingress interception (1:45–2:10)

**DO:** Dashboard nav → **Traffic**. It auto-loads `demo-traffic` (Clean 1 ·
Escalated 1 · Blocked 3). Click one BLOCKED row to open Scanner Details.

**SAY:**
> "Every value entering the agent is intercepted and labelled. Here's one
> session's ingress feed, bucketed by trust zone — clean, escalated, blocked.
> Click any envelope and the scanner shows the score and the exact patterns it
> matched. This is the provenance and injection-scanning layer in action."

---

## 5 · Tool Policies — least agency (2:10–2:35)

**DO:** Nav → **Tool Policies**. Show the per-agent allow-lists; point at
`research-agent`'s four allowed tools and the deny-all `default` agent.

**SAY:**
> "Agents get least agency by default. Each agent has a declarative allow-list —
> the research agent may only call these four tools; everything else is denied.
> The default policy allows no tools at all. Policies are versioned, so every
> change is tracked and reversible."

---

## 6 · Memory Integrity — quarantine (2:35–3:00)

**DO:** Nav → **Memory Integrity**. Show the quarantined entries (score ~0.53).
Hover the Release / Purge actions (don't necessarily click).

**SAY:**
> "Long-term memory is where poisoning persists, so every candidate write is
> scored before it's stored. High-risk writes are rejected outright; borderline
> ones are quarantined for human review — here are two, held pending approval. A
> reviewer can release or purge each. Nothing suspicious reaches memory silently."

---

## 7 · Audit Logs — tamper-evident proof (3:00–3:15)

**DO:** Nav → **Audit Logs**. It auto-loads `demo-traffic` (or click Replay).
Point at the chained events and the "chain valid" indicator.

**SAY:**
> "Finally, the evidence. Every decision across a session is SHA-256 hash-chained
> — each entry linked to the one before it. The whole session can be replayed and
> verified: chain valid. If anyone tampered with a record, verification would
> fail. That's the auditable core of SCML."

**End** on the audit view, or cut back to the Live Agent Demo for a strong final
frame.

---

## RECOVERY — if the stack is down before recording
Docker Desktop stops on sleep/restart. Run in order:
```bash
systemctl --user start docker-desktop        # wait ~10s
cd "/home/ravindu/Desktop/project/scml - middleware layer secure" && docker compose up -d
( set -a; . ./.env; set +a; nohup python3 -u orchestrator.py --loop --delay 4 > .logs/orchestrator.log 2>&1 & )
```
Then re-seed demo data (Traffic + Memory) by re-running the seed commands, or ask
me to re-seed.

## Notes on honesty (for Q&A)
- Detection = heuristic patterns + policy, not a trained model (that's roadmap).
- Output Redaction dashboard tile is a static mockup; the redaction **engine** is
  real — demo it via `POST /v1/mediate/output` in Swagger if asked, not the tile.
- `http://localhost:8000/` (bare root) 404s by design — always use `/docs`.
