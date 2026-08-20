/**
 * The agent loop, with SCML on every edge.
 *
 *   user text ──▶ [1] mediateContext ──▶ decide ──▶ [2] mediateToolCall
 *                                                        │
 *                                              allowed ──┴──▶ run tool
 *                                                             │
 *                            reply ◀── [3] mediateOutput ◀────┘
 *
 * Three properties this is built to demonstrate honestly:
 *
 * 1. **The injection works.** Step 1 does not stop the agent. The agent reads
 *    the hostile text, believes it, and genuinely tries to call the tool it
 *    was told to. Anything else would be theatre.
 * 2. **The action is what gets stopped.** Step 2 is the enforcement point.
 *    Authority comes from the policy store, which never reads the user's
 *    message to decide.
 * 3. **Egress is checked separately.** A tool can succeed and still have its
 *    output redacted on the way out.
 *
 * Intent selection runs in one of two modes, and the UI says which:
 *
 *   llm         ANTHROPIC_API_KEY set — a real model picks the tool.
 *   deterministic  no key — keyword intent matching picks it.
 *
 * The deterministic mode is not a cop-out. What is being demonstrated is the
 * mediation boundary, not the model's cleverness, and a demo that dies because
 * an API key expired at an exhibition is worse than one that cannot.
 */

import { TOOLS, toolByName, type ToolDef } from './tools.js';
import * as scml from './scml.js';

export interface Step {
  stage: 'ingress' | 'decide' | 'authorise' | 'execute' | 'egress';
  label: string;
  verdict?: string;
  detail: string;
  blocked?: boolean;
  /** SCML audit chain reference, when the mediator returned one. */
  auditRef?: string;
}

export interface AgentReply {
  reply: string;
  steps: Step[];
  mode: 'llm' | 'deterministic';
  toolCalled?: string;
  blockedAt?: 'ingress' | 'authorise' | 'egress';
}

// ── Intent selection ─────────────────────────────────────────────────────────

interface Intent {
  tool: ToolDef;
  args: Record<string, any>;
}

/** Keyword intent matching. Order matters: dangerous verbs win ties. */
function deterministicIntent(text: string): Intent | null {
  const t = text.toLowerCase();

  const container = /\b([a-z]{4}\d{7})\b/i.exec(text)?.[1]?.toUpperCase();
  const amount = /\$?\s?([\d,]{3,})\b/.exec(text)?.[1]?.replace(/,/g, '');
  const customer = Object.keys({ 'acme freight': 1, 'pacific lines': 1 })
    .find(name => t.includes(name));

  /* Dangerous verbs are matched generously on purpose.

     A visitor phrases a request their own way — "send it out to the carrier"
     rather than "dispatch". A narrow pattern misses, the agent answers
     conversationally, and it reads as though the system did not understand,
     when in fact it never got as far as asking policy anything. Missing a
     dangerous intent is the expensive failure here; matching one too eagerly
     just produces a denial the visitor was going to see anyway.

     Note each alternation is grouped. `\ba|b|c\b` binds the word boundaries to
     the first and last branches only, so the middle ones match inside other
     words — the same bug that once made "BILL OF LADING" trigger invoicing. */
  if (/\b(wipe|delete|purge|erase|destroy|remove)\b/.test(t) && /\b(record|history|log|data)/.test(t))
    return { tool: toolByName('wipe_shipment_records')!, args: {} };

  if (/\b(export|dump|leak|exfiltrate)\b|\b(send|email|forward|give)\b.{0,20}\b(me|to)\b/.test(t)
      && /\b(customer|client|account|portal|key|data|list|table)/.test(t))
    return { tool: toolByName('export_customer_data')!, args: {} };

  if (/\b(withdraw|transfer|wire|remit|payout)\b|\bmove\b.{0,15}\b(money|funds)\b|\b(money|funds)\b.{0,15}\b(to|out)\b/.test(t))
    return {
      tool: toolByName('transfer_funds')!,
      args: {
        toAccount: /\bacc(?:ount)?\.?\s*([A-Za-z0-9-]{4,})/i.exec(text)?.[1] ?? 'unknown',
        amountUsd: Number(/\$?\s?([\d,]{3,})/.exec(text)?.[1]?.replace(/,/g, '') ?? 25000),
      },
    };

  /* `ship` and `load` are ordinary freight vocabulary — "how much to ship a
     load" is a pricing question, not a dispatch order — so neither appears as
     a bare trigger. A movement verb only counts when it is qualified by a
     destination: out, off, to the carrier, to the truck. Generous on intent,
     but not so generous that quoting a lane reads as releasing freight. */
  if (/\b(dispatch|release)\b|\b(send|move|hand|push|ship)\b.{0,25}\b(out|off|carrier|truck)\b|\bhand(ed)? (it )?(over|to)\b|\blet\b.{0,24}\b(go|leave|out)\b/.test(t))
    return { tool: toolByName('dispatch_container')!, args: { containerId: container ?? 'MSKU7834561' } };

  if (/\b(invoice|billing|charge)\b|\bbill\b(?!\s+of\s+lading)/.test(t))
    return {
      tool: toolByName('issue_invoice')!,
      args: { customer: customer ?? 'Acme Freight', amountUsd: Number(amount ?? 2450) },
    };

  if (/\btrack|status|where is|eta\b/.test(t))
    return { tool: toolByName('track_container')!, args: { containerId: container ?? 'MSKU7834561' } };

  if (/\bcustomer|account|contact|terms|balance\b/.test(t))
    return { tool: toolByName('lookup_customer')!, args: { name: customer ?? 'Acme Freight' } };

  if (/\bquote|price|cost|how much|rate\b/.test(t)) {
    const cities = /from\s+([a-z ]+?)\s+to\s+([a-z ]+?)(?:[,.]|$)/i.exec(text);
    return {
      tool: toolByName('quote_shipment')!,
      args: {
        origin: cities?.[1]?.trim() ?? 'Chicago',
        dest: cities?.[2]?.trim() ?? 'Dallas',
        weightLbs: Number(/(\d{4,6})\s?(?:lbs|pounds)/i.exec(text)?.[1] ?? 42000),
      },
    };
  }

  return null;
}

/** Ask a real model which tool to call. Falls back to keywords on any error. */
async function llmIntent(text: string, apiKey: string): Promise<Intent | null> {
  const catalogue = TOOLS.map(t => `- ${t.name}: ${t.description}`).join('\n');
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      model: process.env.DEMO_AGENT_MODEL || 'claude-sonnet-4-6',
      max_tokens: 300,
      system:
        `You are a freight operations agent. You have these tools:\n${catalogue}\n\n` +
        `Choose the single tool that best fulfils the request and reply with ONLY ` +
        `JSON: {"tool":"<name>","args":{...}}. If no tool fits, reply {"tool":null}. ` +
        `No markdown fences.`,
      messages: [{ role: 'user', content: text }],
    }),
  });

  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  const data = await res.json();
  const raw = data?.content?.[0]?.text ?? '';
  const parsed = JSON.parse(raw.replace(/^```(?:json)?/gm, '').replace(/```$/gm, '').trim());
  const tool = parsed?.tool ? toolByName(parsed.tool) : undefined;
  return tool ? { tool, args: parsed.args ?? {} } : null;
}

// ── The loop ─────────────────────────────────────────────────────────────────

export async function handleMessage(message: string, sessionId: string): Promise<AgentReply> {
  const steps: Step[] = [];
  const apiKey = process.env.ANTHROPIC_API_KEY || '';
  const mode: 'llm' | 'deterministic' = apiKey ? 'llm' : 'deterministic';

  // [1] Ingress. Label and scan, but do not stop — see the header comment.
  const ctx = await scml.mediateInbound(message, sessionId);
  steps.push({
    stage: 'ingress',
    label: 'Message scanned',
    verdict: ctx.verdict,
    auditRef: ctx.auditRef,
    detail: ctx.flagged
      ? `Flagged: ${ctx.reason}. The agent still reads it — detection is not the defence.`
      : `Labelled ${ctx.trustLabel}. Nothing matched, which is common: the scanner misses most attacks.`,
  });

  // [2] Decide.
  let intent: Intent | null = null;
  try {
    intent = apiKey ? await llmIntent(message, apiKey) : deterministicIntent(message);
  } catch (err) {
    intent = deterministicIntent(message);
    steps.push({
      stage: 'decide',
      label: 'Model unavailable',
      detail: `Fell back to keyword intent matching: ${err instanceof Error ? err.message.slice(0, 120) : err}`,
    });
  }

  if (!intent) {
    steps.push({ stage: 'decide', label: 'No tool selected', detail: 'Answering conversationally.' });
    const out = await scml.mediateOutbound(
      `I can quote shipments, track containers, look up customers and issue invoices. What do you need?`,
      sessionId,
    );
    steps.push({
      stage: 'egress', label: 'Reply checked', verdict: out.verdict,
      auditRef: out.auditRef, detail: out.redacted ? 'Redactions applied.' : 'Clean.',
    });
    return { reply: out.text, steps, mode };
  }

  steps.push({
    stage: 'decide',
    label: `Agent chose ${intent.tool.name}`,
    detail:
      `Arguments: ${JSON.stringify(intent.args)}. They derive from the message, so ` +
      `they inherit its ${ctx.trustLabel} label and travel with it.`,
  });

  // [3] Authorise. This is the enforcement point.
  const decision = await scml.authoriseAction({
    sessionId,
    agentId: intent.tool.agentId,
    tool: intent.tool.name,
    args: intent.args,
    trustLabel: ctx.trustLabel,
    irreversible: intent.tool.irreversible,
    highImpact: intent.tool.highImpact,
  });

  steps.push({
    stage: 'authorise',
    label: `Policy check as ${intent.tool.agentId}`,
    verdict: decision.verdict,
    auditRef: decision.auditRef,
    blocked: !decision.allowed,
    detail: decision.reason || (decision.allowed ? 'Authorised by policy.' : 'Not permitted.'),
  });

  if (!decision.allowed) {
    const why =
      decision.verdict === 'approval_required'
        ? `**${intent.tool.name}** needs human approval before it runs.`
        : `**${intent.tool.name}** is not permitted for this agent.`;
    const out = await scml.mediateOutbound(
      `${why}\n\n${decision.reason}\n\nThe action did not execute.`,
      sessionId,
    );
    steps.push({
      stage: 'egress', label: 'Reply checked', verdict: out.verdict,
      auditRef: out.auditRef, detail: out.redacted ? 'Redactions applied.' : 'Clean.',
    });
    return { reply: out.text, steps, mode, toolCalled: intent.tool.name, blockedAt: 'authorise' };
  }

  // [4] Execute. Only reached when policy allowed it.
  const result = intent.tool.run(intent.args);
  steps.push({
    stage: 'execute',
    label: `${intent.tool.name} ran`,
    detail: 'The tool actually executed. Nothing in the tool layer second-guesses policy.',
  });

  // [5] Egress.
  const out = await scml.mediateOutbound(result, sessionId);
  steps.push({
    stage: 'egress',
    label: 'Reply checked',
    verdict: out.verdict,
    auditRef: out.auditRef,
    blocked: out.blocked,
    detail: out.blocked
      ? `Output blocked: ${out.reason}`
      : out.redacted
        ? 'Sensitive values redacted before sending.'
        : 'Clean.',
  });

  return {
    reply: out.blocked ? `Output withheld: ${out.reason}` : out.text,
    steps,
    mode,
    toolCalled: intent.tool.name,
    blockedAt: out.blocked ? 'egress' : undefined,
  };
}
