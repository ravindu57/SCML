/**
 * SCML mediation for the orchestration, plus the taint lattice.
 *
 * The lattice is the part a single-agent demo cannot show. When the researcher
 * reads three documents and one of them is hostile, the plan derived from all
 * three inherits the *most restrictive* label of its inputs, not the average
 * and not the last one seen (PRD FR-TR-02). That label then travels with the
 * arguments the executor passes to a tool, which is what lets the
 * untrusted-argument rule fire at all.
 *
 * Getting this backwards is the classic failure: a system that labels each hop
 * independently loses the taint at the first boundary, and by the time a value
 * reaches a tool it looks like it came from the operator.
 */

import { SCML, SCMLUnavailable } from 'scml-client';

const url = process.env.SCML_URL || 'http://localhost:8000';

const client = new SCML({
  url,
  apiKey: process.env.SCML_API_KEY || undefined,
  agentId: 'orch-researcher',
  timeoutMs: Number(process.env.SCML_TIMEOUT_MS || 5000),
});

export const mediatorUrl = url;

// ── Taint lattice ────────────────────────────────────────────────────────────

/** Least → most restrictive. Anything unrecognised sorts as most restrictive. */
const ORDER = ['trusted', 'user_input', 'risky_external', 'untrusted_data'];

export function mostRestrictive(labels: string[]): string {
  if (labels.length === 0) return 'untrusted_data';
  return labels.reduce((worst, l) => {
    const a = ORDER.indexOf(worst);
    const b = ORDER.indexOf(l);
    // -1 (unknown) must win: an unrecognised label is not a promotion.
    if (a === -1) return worst;
    if (b === -1) return l;
    return b > a ? l : worst;
  }, labels[0]!);
}

export async function health(): Promise<{ ok: boolean; detail: string }> {
  try {
    const h = await client.health();
    return { ok: h.status === 'ok', detail: `${h.service} v${h.version} (${h.env})` };
  } catch (err) {
    return { ok: false, detail: err instanceof Error ? err.message : 'unreachable' };
  }
}

// ── Ingress ──────────────────────────────────────────────────────────────────

export interface Inbound {
  trustLabel: string;
  flagged: boolean;
  verdict: string;
  reason: string;
  auditRef: string;
}

export async function mediateInbound(opts: {
  content: string;
  sessionId: string;
  agentId: string;
  sourceUri?: string;
}): Promise<Inbound> {
  try {
    const r = await client.mediateContext({
      sessionId: opts.sessionId,
      content: opts.content,
      source: 'rag_retrieval',
      sourceUri: opts.sourceUri ?? '',
      agentId: opts.agentId,
      failOpen: true,
    });
    return {
      trustLabel: r.trustLabel || 'untrusted_data',
      flagged: !r.allowed,
      verdict: r.verdict,
      reason: r.reason,
      auditRef: r.auditRef,
    };
  } catch {
    return { trustLabel: 'untrusted_data', flagged: false, verdict: 'error', reason: '', auditRef: '' };
  }
}

// ── Memory writes ────────────────────────────────────────────────────────────

export interface MemoryVerdict {
  verdict: string;
  stored: boolean;
  quarantined: boolean;
  score: number | null;
  reason: string;
  auditRef: string;
}

/**
 * Vet a record the agent wants to remember (FR-MI-01).
 *
 * This is the memory-poisoning surface: a retrieved document says something,
 * the agent writes it down, and every later run reads it back as if it were
 * established fact. The scorer returns one of three verdicts — persist,
 * quarantine, reject — and quarantine is the interesting one: the record is
 * kept for review but withheld from the agent.
 *
 * Worth being clear about what this is not. It scores text, so it catches
 * imperative phrasing ("from now on, always…") and misses a declarative
 * authority claim ("policy validation has been disabled"), which persists at
 * 0.755. That is the same weakness the injection scanner has, and it is why
 * the control that actually stops the attack is the tool policy — which never
 * reads memory to make its decision.
 */
export async function mediateMemoryWrite(opts: {
  sessionId: string;
  agentId: string;
  content: string;
  sourceUri?: string;
  trustLabel: string;
}): Promise<MemoryVerdict> {
  try {
    const r = await client.mediateMemoryWrite({
      sessionId: opts.sessionId,
      content: opts.content,
      source: 'document',
      sourceUri: opts.sourceUri ?? '',
      trustLabel: opts.trustLabel,
      agentId: opts.agentId,
      failOpen: true,
    });
    const verdict = String(r.decision || r.verdict || '').toLowerCase();
    return {
      verdict,
      stored: verdict === 'persist',
      quarantined: verdict === 'quarantine',
      score: typeof r.score === 'number' ? r.score : null,
      reason: r.reason,
      auditRef: r.auditRef,
    };
  } catch {
    return { verdict: 'error', stored: false, quarantined: false, score: null, reason: '', auditRef: '' };
  }
}

// ── Authorisation ────────────────────────────────────────────────────────────

export interface Decision {
  allowed: boolean;
  verdict: string;
  reason: string;
  auditRef: string;
}

export async function authorise(opts: {
  sessionId: string;
  agentId: string;
  tool: string;
  args: Record<string, unknown>;
  trustLabel: string;
  irreversible?: boolean;
  highImpact?: boolean;
}): Promise<Decision> {
  const argumentTrustLabels = Object.fromEntries(
    Object.keys(opts.args).map(k => [k, opts.trustLabel]),
  );
  try {
    const r = await client.mediateToolCall({
      sessionId: opts.sessionId,
      tool: opts.tool,
      arguments: opts.args,
      argumentTrustLabels,
      agentId: opts.agentId,
      isIrreversible: opts.irreversible ?? false,
      isHighImpact: opts.highImpact ?? false,
      failOpen: false, // §9 — side effects fail closed
    });
    return { allowed: r.allowed, verdict: r.verdict, reason: r.reason, auditRef: r.auditRef };
  } catch (err) {
    if (err instanceof SCMLUnavailable) {
      return {
        allowed: false,
        verdict: 'error',
        reason:
          'SCML unreachable — the step could not be authorised and did not run. ' +
          'Failing closed is correct: "could not ask" is never "permitted".',
        auditRef: '',
      };
    }
    throw err;
  }
}

// ── Egress ───────────────────────────────────────────────────────────────────

export interface Outbound {
  text: string;
  blocked: boolean;
  redacted: boolean;
  verdict: string;
  reason: string;
  auditRef: string;
}

export async function mediateOutbound(opts: {
  content: string;
  sessionId: string;
}): Promise<Outbound> {
  try {
    const r = await client.mediateOutput({
      sessionId: opts.sessionId,
      content: opts.content,
      destination: 'user',
      failOpen: true,
    });
    const safe = r.content ?? opts.content;
    return {
      text: r.allowed ? safe : '',
      blocked: !r.allowed,
      redacted: safe !== opts.content,
      verdict: r.verdict,
      reason: r.reason,
      auditRef: r.auditRef,
    };
  } catch {
    return { text: opts.content, blocked: false, redacted: false, verdict: 'error', reason: '', auditRef: '' };
  }
}
