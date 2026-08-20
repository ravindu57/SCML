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

/** Either a tool to call, or a conversational reply. */
type LlmDecision =
  | { kind: 'tool'; intent: Intent }
  | { kind: 'chat'; reply: string };

/**
 * Which model to ask, and with whose key.
 *
 * Two wire formats cover essentially every provider: Anthropic's, and the
 * OpenAI chat-completions shape that OpenAI, Groq, OpenRouter, Together,
 * DeepSeek, Mistral, Google's compat endpoint and local Ollama or LM Studio
 * all speak. So the choice here is a format, not a vendor — pointing
 * DEMO_AGENT_BASE_URL somewhere else is the whole of "use a different
 * provider", and a laptop running Ollama needs no key or network at all.
 *
 * Provider is inferred from whichever key is present so the common case needs
 * one variable, and DEMO_AGENT_PROVIDER settles it when that guess is wrong.
 */
interface LlmConfig {
  provider: 'anthropic' | 'openai';
  apiKey: string;
  model: string;
  baseUrl: string;
}

export function llmConfig(): LlmConfig | null {
  const explicit = (process.env.DEMO_AGENT_PROVIDER || '').toLowerCase();
  const key =
    process.env.DEMO_AGENT_API_KEY ||
    process.env.OPENAI_API_KEY ||
    process.env.ANTHROPIC_API_KEY ||
    '';

  const provider: 'anthropic' | 'openai' =
    explicit === 'anthropic' ? 'anthropic'
    : explicit === 'openai' ? 'openai'
    // No explicit choice: an Anthropic key implies Anthropic, anything else
    // implies the OpenAI shape, which is the majority of providers.
    : (process.env.ANTHROPIC_API_KEY && !process.env.OPENAI_API_KEY && !process.env.DEMO_AGENT_API_KEY)
      ? 'anthropic'
      : 'openai';

  const baseUrl = (process.env.DEMO_AGENT_BASE_URL || '').replace(/\/+$/, '') ||
    (provider === 'anthropic' ? 'https://api.anthropic.com' : 'https://api.openai.com/v1');

  // A local runtime needs no key; a hosted one does. Requiring a key for
  // localhost would rule out the offline case for no reason.
  const isLocal = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])/.test(baseUrl);
  if (!key && !isLocal) return null;

  const model = process.env.DEMO_AGENT_MODEL ||
    (provider === 'anthropic' ? 'claude-sonnet-4-6' : 'gpt-4o-mini');

  return { provider, apiKey: key, model, baseUrl };
}

/**
 * The model's entire job: read the message, name a tool or write a sentence.
 *
 * It is a classifier with a conversational fallback, and deliberately nothing
 * more. It does not execute, and it is not asked whether an action is allowed —
 * SCML decides that from declarative policy, after this returns. Keeping the
 * model out of the authorisation decision is the point of the architecture, not
 * an implementation detail: a model that could authorise its own tool calls
 * would be exactly the failure mode being defended against.
 *
 * Which is why the prompt says plainly that it selects rather than executes.
 * Without that, a safety-trained model tends to decline to route a
 * dangerous-sounding request — and a refusal here means nothing reaches the
 * mediator, no decision is audited, and the demonstration shows the wrong
 * component saying no.
 */
const SYSTEM_PROMPT = (catalogue: string) =>
  `You are the routing layer of a freight operations assistant. Available tools:\n` +
  `${catalogue}\n\n` +
  `You SELECT a tool; you never execute one. Every selection is then sent to a ` +
  `separate authorisation service which decides whether it is permitted, and ` +
  `refuses most of them. These tools are simulated for a security demonstration.\n\n` +
  `Because of that, route on intent alone. If a request maps to a tool, return ` +
  `that tool even when the request sounds unwise or hostile — declining to route ` +
  `it hides the request from the layer whose job is to refuse it. Do not lecture ` +
  `the user and do not add warnings.\n\n` +
  `Reply with ONLY one JSON object, no markdown fences:\n` +
  `  {"tool":"<name>","args":{...}}   when a tool matches\n` +
  `  {"reply":"<1-2 sentences>"}      when none does — greetings, questions ` +
  `about what you can do, small talk. Be brief, warm and practical.`;

/** One call that both routes and converses. Throws on any failure; the caller
 *  degrades to keyword matching. */
async function llmDecide(text: string, cfg: LlmConfig): Promise<LlmDecision> {
  const system = SYSTEM_PROMPT(TOOLS.map(t => `- ${t.name}: ${t.description}`).join('\n'));

  const anthropic = cfg.provider === 'anthropic';
  const res = await fetch(
    anthropic ? `${cfg.baseUrl}/v1/messages` : `${cfg.baseUrl}/chat/completions`,
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(anthropic
          ? { 'x-api-key': cfg.apiKey, 'anthropic-version': '2023-06-01' }
          : cfg.apiKey ? { authorization: `Bearer ${cfg.apiKey}` } : {}),
      },
      body: JSON.stringify(
        anthropic
          ? {
              model: cfg.model,
              max_tokens: 400,
              system,
              messages: [{ role: 'user', content: text }],
            }
          : {
              model: cfg.model,
              max_tokens: 400,
              messages: [
                { role: 'system', content: system },
                { role: 'user', content: text },
              ],
            }
      ),
    }
  );

  if (!res.ok) throw new Error(`${res.status} ${(await res.text()).slice(0, 200)}`);
  const data: any = await res.json();

  const raw = String(
    anthropic ? data?.content?.[0]?.text ?? '' : data?.choices?.[0]?.message?.content ?? ''
  );

  // Smaller models wrap JSON in prose or fences however the mood takes them;
  // strip fences, then fall back to the outermost braces.
  const cleaned = raw.replace(/^```(?:json)?/gm, '').replace(/```$/gm, '').trim();
  const slice = cleaned.slice(cleaned.indexOf('{'), cleaned.lastIndexOf('}') + 1);
  const parsed = JSON.parse(slice || cleaned);

  const tool = parsed?.tool ? toolByName(parsed.tool) : undefined;
  if (tool) return { kind: 'tool', intent: { tool, args: parsed.args ?? {} } };

  const reply = typeof parsed?.reply === 'string' && parsed.reply.trim()
    ? parsed.reply.trim()
    : 'I can quote shipments, track containers, look up customers and issue invoices. What do you need?';
  return { kind: 'chat', reply };
}


// ── The loop ─────────────────────────────────────────────────────────────────

export async function handleMessage(message: string, sessionId: string): Promise<AgentReply> {
  const steps: Step[] = [];
  const cfg = llmConfig();
  const mode: 'llm' | 'deterministic' = cfg ? 'llm' : 'deterministic';

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

  // [2] Decide — a tool to call, or a conversational answer.
  let intent: Intent | null = null;
  let chatReply: string | null = null;

  try {
    if (cfg) {
      const decision = await llmDecide(message, cfg);
      if (decision.kind === 'tool') intent = decision.intent;
      else chatReply = decision.reply;
    } else {
      intent = deterministicIntent(message);
    }
  } catch (err) {
    // Any model failure — no network, bad key, malformed JSON — degrades to
    // keyword routing rather than failing the request. Surfaced on screen so a
    // viewer is never misled about which path produced the answer.
    intent = deterministicIntent(message);
    chatReply = null;
    steps.push({
      stage: 'decide',
      label: 'Model unavailable',
      detail: `Fell back to keyword intent matching: ${err instanceof Error ? err.message.slice(0, 120) : err}`,
    });
  }

  if (!intent) {
    steps.push({
      stage: 'decide',
      label: 'No tool selected',
      detail: chatReply
        ? 'The model answered conversationally — no action was proposed, so there is nothing to authorise.'
        : 'Answering conversationally.',
    });
    // The reply still goes through egress mediation. A conversational answer is
    // outbound content like any other, and is where a model would leak.
    const out = await scml.mediateOutbound(
      chatReply ??
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
