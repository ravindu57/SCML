/**
 * SCML mediation for the demo agent.
 *
 * A thin wrapper over `scml-client` that keeps the agent code readable and
 * makes one policy decision in one place: what happens when the mediator is
 * unreachable.
 *
 * This demo runs ENFORCING by default, unlike a production rollout which
 * should start in observe mode. The point of the demo is to show actions being
 * stopped, so an install that silently observed would show nothing.
 *
 * Fail policy: authorisation fails CLOSED. If the mediator cannot be reached,
 * the action does not run — "could not ask" is never "permitted" (PRD §9).
 * Ingress and egress fail open with a loud banner, because refusing to answer
 * at all makes for a confusing exhibit and neither is an authorisation step.
 */

import { SCML, SCMLUnavailable } from 'scml-client';

const url = process.env.SCML_URL || 'http://localhost:8000';

const client = new SCML({
  url,
  apiKey: process.env.SCML_API_KEY || undefined,
  agentId: 'demo-agent-quoting',
  timeoutMs: Number(process.env.SCML_TIMEOUT_MS || 5000),
});

export const mediatorUrl = url;

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

export async function mediateInbound(content: string, sessionId: string): Promise<Inbound> {
  try {
    const r = await client.mediateContext({
      sessionId,
      content,
      source: 'user_input',
      metadata: { surface: 'demo-agent-chat' },
      failOpen: true,
    });
    return {
      // Default to the restrictive label rather than the convenient one.
      trustLabel: r.trustLabel || 'untrusted_data',
      flagged: !r.allowed,
      verdict: r.verdict,
      reason: r.reason,
      auditRef: r.auditRef,
    };
  } catch {
    return {
      trustLabel: 'untrusted_data', flagged: false,
      verdict: 'error', reason: 'mediator unreachable', auditRef: '',
    };
  }
}

// ── Authorisation ────────────────────────────────────────────────────────────

export interface Decision {
  allowed: boolean;
  verdict: string;
  reason: string;
  auditRef: string;
}

export async function authoriseAction(opts: {
  sessionId: string;
  agentId: string;
  tool: string;
  args: Record<string, unknown>;
  trustLabel: string;
  irreversible?: boolean;
  highImpact?: boolean;
}): Promise<Decision> {
  // Every argument carries the label of the message it came from. Without
  // these the untrusted-argument rule cannot fire and a value composed from a
  // hostile message is indistinguishable from one a human typed.
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
          'SCML is unreachable, so this action could not be authorised and did not run. ' +
          'Failing closed is the correct behaviour — an unreachable mediator must ' +
          'never be mistaken for permission.',
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

export async function mediateOutbound(content: string, sessionId: string): Promise<Outbound> {
  try {
    const r = await client.mediateOutput({ sessionId, content, destination: 'user', failOpen: true });
    const safe = r.content ?? content;
    return {
      // Substituting r.content is the enforcement step. Reading the verdict
      // and sending the original would enforce nothing.
      text: r.allowed ? safe : '',
      blocked: !r.allowed,
      redacted: safe !== content,
      verdict: r.verdict,
      reason: r.reason,
      auditRef: r.auditRef,
    };
  } catch {
    return { text: content, blocked: false, redacted: false, verdict: 'error', reason: '', auditRef: '' };
  }
}
