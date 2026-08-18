/**
 * The orchestration: researcher → planner → executor/finance → reporter.
 *
 * Each hop emits an event so the UI can show the run unfolding rather than
 * printing a verdict at the end. The interesting thing to watch is the label
 * column: it starts `trusted` on the operator's own task, and the moment the
 * researcher reads a document it drops to `untrusted_data` and never recovers.
 * That is the never-promote rule — taint only ever flows downhill.
 *
 * Planning is deterministic by default. What is being demonstrated is the
 * mediation boundary, not a model's reasoning, and a demo that needs a working
 * API key is a demo that can fail on the day for reasons unrelated to the
 * thing it is showing. With ANTHROPIC_API_KEY set, a real model plans instead.
 */

import { AGENT_ID, TOOLS, toolByName, type Role } from './agents.js';
import { docById, searchCorpus, type Doc } from './corpus.js';
import * as scml from './scml.js';

export interface Event {
  seq: number;
  role: Role | 'system';
  agentId?: string;
  stage: 'task' | 'retrieve' | 'ingress' | 'memory' | 'plan' | 'authorise' | 'execute' | 'egress' | 'done';
  title: string;
  detail: string;
  label?: string;
  verdict?: string;
  blocked?: boolean;
  auditRef?: string;
}

export interface RunResult {
  events: Event[];
  reply: string;
  mode: 'llm' | 'deterministic';
  stopped: string[];
}

type Emit = (e: Event) => void;

interface Step {
  tool: string;
  args: Record<string, any>;
  why: string;
}

// ── Planning ─────────────────────────────────────────────────────────────────

/**
 * Derive steps from the task plus whatever the researcher found.
 *
 * This reads the retrieved documents as instructions, which is exactly the
 * vulnerability being demonstrated. A planner that ignored retrieved content
 * would be safe and useless — the whole value of a RAG agent is that what it
 * reads changes what it does.
 */
function deterministicPlan(task: string, docs: Doc[]): Step[] {
  const corpus = docs.map(d => d.body).join('\n').toLowerCase();
  const all = `${task}\n${corpus}`.toLowerCase();
  const steps: Step[] = [];

  const container = /\b([a-z]{4}\d{7})\b/i.exec(`${task} ${corpus}`)?.[1]?.toUpperCase();

  if (/\bpurge|wipe|delete permanently|retention schedule\b/.test(all))
    steps.push({ tool: 'wipe_shipment_records', args: {}, why: 'retrieved memo instructs a purge' });

  if (/\b(compile|send|export).{0,40}(customer|account).{0,30}(list|listing|table)|portal access key\b/.test(all))
    steps.push({ tool: 'export_customer_data', args: {}, why: 'retrieved packet requests the customer listing' });

  if (/\bproceed to dispatch|dispatch container|release .{0,20}carrier\b/.test(all))
    steps.push({
      tool: 'dispatch_container',
      args: { containerId: container ?? 'MSKU7834561' },
      why: 'retrieved email instructs dispatch',
    });

  // `\binvoice|bill\b` would parse as `(\binvoice)|(bill\b)`, and "BILL OF
  // LADING" then matches — every run that retrieved a BOL spuriously planned
  // an invoice. Group the alternation and exclude the shipping document.
  if (/\b(invoice|billing)\b|\bbill\b(?!\s+of\s+lading)/.test(all))
    steps.push({
      tool: 'issue_invoice',
      args: { customer: 'Acme Freight', amountUsd: 2450 },
      why: 'task mentions billing',
    });

  if (/\bquote|rate|price|how much\b/.test(all))
    steps.push({
      tool: 'quote_shipment',
      args: { origin: 'Chicago', dest: 'Dallas', weightLbs: 42000 },
      why: 'task asks for a rate',
    });

  if (/\btrack|status|update\b/.test(all) && container)
    steps.push({
      tool: 'update_tracking',
      args: { containerId: container, status: 'ready for pickup' },
      why: 'task asks for a status update',
    });

  return steps;
}

async function llmPlan(task: string, docs: Doc[], apiKey: string): Promise<Step[]> {
  const catalogue = TOOLS.map(t => `- ${t.name}: ${t.description}`).join('\n');
  const context = docs.map(d => `### ${d.id} — ${d.title}\n${d.body}`).join('\n\n');
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      model: process.env.ORCH_MODEL || 'claude-sonnet-4-6',
      max_tokens: 700,
      system:
        `You are the planner in a freight operations system. Tools:\n${catalogue}\n\n` +
        `Given the operator's task and the retrieved documents, output ONLY JSON: ` +
        `{"steps":[{"tool":"<name>","args":{...},"why":"<short>"}]}. No fences.`,
      messages: [{ role: 'user', content: `TASK:\n${task}\n\nRETRIEVED:\n${context}` }],
    }),
  });
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  const data = await res.json();
  const raw = String(data?.content?.[0]?.text ?? '');
  const parsed = JSON.parse(raw.replace(/^```(?:json)?/gm, '').replace(/```$/gm, '').trim());
  return Array.isArray(parsed?.steps) ? parsed.steps.filter((s: Step) => toolByName(s.tool)) : [];
}

// ── The run ──────────────────────────────────────────────────────────────────

export async function run(task: string, sessionId: string, emit: Emit): Promise<RunResult> {
  const events: Event[] = [];
  const stopped: string[] = [];
  let seq = 0;
  const apiKey = process.env.ANTHROPIC_API_KEY || '';
  const mode: 'llm' | 'deterministic' = apiKey ? 'llm' : 'deterministic';

  const push = (e: Omit<Event, 'seq'>) => {
    const ev = { ...e, seq: ++seq };
    events.push(ev);
    emit(ev);
    return ev;
  };

  // The operator's own instruction starts trusted. Everything the system reads
  // from here can only make the label worse.
  let label = 'trusted';

  push({ role: 'system', stage: 'task', title: 'Operator task', detail: task, label });

  // ── researcher ─────────────────────────────────────────────────────────────
  const hits = searchCorpus(task);
  push({
    role: 'researcher',
    agentId: AGENT_ID.researcher,
    stage: 'retrieve',
    title: `Retrieved ${hits.length} document(s)`,
    detail: hits.map(d => `${d.id} — ${d.title}`).join('\n'),
    label,
  });

  const docs: Doc[] = [];
  for (const hit of hits) {
    const doc = docById(hit.id)!;
    docs.push(doc);
    const ctx = await scml.mediateInbound({
      content: doc.body,
      sessionId,
      agentId: AGENT_ID.researcher,
      sourceUri: `corpus://${doc.id}`,
    });
    // Never-promote: the running label only ever gets more restrictive.
    label = scml.mostRestrictive([label, ctx.trustLabel]);
    push({
      role: 'researcher',
      agentId: AGENT_ID.researcher,
      stage: 'ingress',
      title: `Read ${doc.id}`,
      detail: ctx.flagged
        ? `Scanner flagged it: ${ctx.reason}`
        : `Scanner saw nothing. The document is still labelled ${ctx.trustLabel} because of where it came from, not what it said.`,
      label,
      verdict: ctx.verdict,
      auditRef: ctx.auditRef,
    });
  }

  // ── researcher writes down what it read ────────────────────────────────────
  // An agent that retrieves and then forgets is not much of an agent. This is
  // the memory-poisoning surface: whatever survives here is read back on later
  // runs as established fact, by which point nobody remembers it came from a
  // supplier email.
  for (const doc of docs) {
    const mem = await scml.mediateMemoryWrite({
      sessionId,
      agentId: AGENT_ID.researcher,
      content: doc.body,
      sourceUri: `corpus://${doc.id}`,
      trustLabel: label,
    });

    push({
      role: 'researcher',
      agentId: AGENT_ID.researcher,
      stage: 'memory',
      title: `Remember ${doc.id} — ${mem.verdict || 'error'}`,
      detail: mem.quarantined
        ? `Held for review, not given to the agent. ${mem.reason}`
        : mem.stored
          ? `Stored${mem.score !== null ? ` (integrity ${mem.score})` : ''}. Note this is only storage — the mediator never reads memory to authorise an action.`
          : `Rejected outright. ${mem.reason}`,
      label,
      verdict: mem.quarantined ? 'quarantine' : mem.stored ? 'allow' : 'block',
      blocked: !mem.stored,
      auditRef: mem.auditRef,
    });
  }

  // ── planner ────────────────────────────────────────────────────────────────
  let steps: Step[] = [];
  try {
    steps = apiKey ? await llmPlan(task, docs, apiKey) : deterministicPlan(task, docs);
  } catch (err) {
    steps = deterministicPlan(task, docs);
    push({
      role: 'planner', agentId: AGENT_ID.planner, stage: 'plan',
      title: 'Model unavailable — planned deterministically',
      detail: err instanceof Error ? err.message.slice(0, 140) : String(err),
      label,
    });
  }

  push({
    role: 'planner',
    agentId: AGENT_ID.planner,
    stage: 'plan',
    title: steps.length ? `Planned ${steps.length} step(s)` : 'No actions planned',
    detail: steps.length
      ? steps.map(s => `${s.tool} — ${s.why}`).join('\n')
      : 'Nothing in the task or the retrieved documents implies an action.',
    label,
  });

  // ── executor / finance ─────────────────────────────────────────────────────
  const outputs: string[] = [];

  for (const step of steps) {
    const tool = toolByName(step.tool);
    if (!tool) continue;
    const role: Role = tool.role;
    const agentId = AGENT_ID[role];

    const decision = await scml.authorise({
      sessionId,
      agentId,
      tool: tool.name,
      args: step.args,
      trustLabel: label,
      irreversible: tool.irreversible,
      highImpact: tool.highImpact,
    });

    push({
      role,
      agentId,
      stage: 'authorise',
      title: `${tool.name} — policy check as ${agentId}`,
      detail: decision.reason || (decision.allowed ? 'Authorised.' : 'Not permitted.'),
      label,
      verdict: decision.verdict,
      blocked: !decision.allowed,
      auditRef: decision.auditRef,
    });

    if (!decision.allowed) {
      stopped.push(tool.name);
      continue;
    }

    const result = tool.run(step.args);
    outputs.push(result);
    push({
      role, agentId, stage: 'execute',
      title: `${tool.name} ran`,
      detail: result,
      label,
    });
  }

  // ── reporter ───────────────────────────────────────────────────────────────
  const summary =
    (outputs.length ? outputs.join('\n') : 'No actions were carried out.') +
    (stopped.length ? `\n\nStopped by policy: ${stopped.join(', ')}.` : '');

  const out = await scml.mediateOutbound({ content: summary, sessionId });
  push({
    role: 'reporter',
    agentId: AGENT_ID.reporter,
    stage: 'egress',
    title: 'Report checked',
    detail: out.blocked
      ? `Blocked: ${out.reason}`
      : out.redacted
        ? 'Sensitive values redacted before leaving the system.'
        : 'Clean.',
    label,
    verdict: out.verdict,
    blocked: out.blocked,
    auditRef: out.auditRef,
  });

  push({
    role: 'system', stage: 'done',
    title: 'Run complete',
    detail: `${stopped.length} action(s) stopped by policy. Final label: ${label}.`,
    label,
  });

  return {
    events,
    reply: out.blocked ? `Report withheld: ${out.reason}` : out.text,
    mode,
    stopped,
  };
}
