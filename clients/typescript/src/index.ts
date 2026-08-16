/**
 * SCML client for Node.js and TypeScript.
 *
 * SCML (Secure Context Mediation Layer) is the product; TrustMediator is the
 * engine. This package talks to a running mediator over HTTP and has **zero
 * runtime dependencies** — it uses the platform `fetch`, so it needs Node 18+
 * and adds nothing to your dependency tree.
 *
 * The API mirrors the Python SDK method-for-method, so an integration written
 * against one reads the same as the other.
 *
 * ## Why not just call fetch yourself
 *
 * The mediation endpoints do not share a response shape:
 *
 * | Endpoint                | Carries          |
 * |-------------------------|------------------|
 * | `/v1/mediate/context`   | `decision`       |
 * | `/v1/mediate/tool-call` | `decision`       |
 * | `/v1/mediate/output`    | `blocked` — no `decision` at all |
 * | `/v1/mediate/memory/write` | `verdict` ("persist"/"quarantine"/"reject") |
 * | `/v1/mediate/memory/read`  | `verified` / `withheld` |
 *
 * Code branching on `result.decision` is therefore correct for two endpoints
 * and silently wrong for three: a blocked output or a quarantined memory write
 * reads as "no decision field, carry on". This client normalises all five onto
 * one `verdict` so `if (!result.allowed)` means the same thing everywhere.
 *
 * ## Fail policy (PRD §9)
 *
 * Side-effect operations fail **closed**: if the mediator cannot be reached,
 * the call throws `SCMLUnavailable` rather than returning something that looks
 * like an allow. An agent that treats a network error as permission is exactly
 * the failure mode §9 exists to prevent. Pass `{ failOpen: true }` per call to
 * opt out on a genuinely low-risk read; every fail-open is logged, because by
 * definition the audit log is unreachable at that moment.
 */

// ── Verdicts ────────────────────────────────────────────────────────────────

export type Verdict =
  | 'allow'
  | 'block'
  | 'approval_required'
  | 'escalate'
  | 'quarantine'
  | 'error'
  | 'unknown';

/**
 * Map a raw server decision string onto a normalised {@link Verdict}.
 *
 * The branch order is load-bearing and matches the Python SDK exactly. Each
 * case was added in response to a real escape:
 *
 * - `require_approval` arrives suffixed (`.irreversible`, `.high_impact`,
 *   `.untrusted_arg`). Matching it exactly rather than by prefix once meant a
 *   gated call matched no branch at all, so an irreversible action sailed
 *   through a gate the policy had closed (FR-PE-03).
 * - `deny` likewise arrives suffixed (`deny.schema_violation`).
 * - Anything unrecognised maps to `unknown`, never to `allow`. Treating "I do
 *   not understand this answer" as permission is how the gap above went
 *   unnoticed in the first place.
 */
export function classifyDecision(decision?: string | null): Verdict {
  const d = (decision ?? '').toLowerCase();

  if (['allow', 'persist', 'transform', 'verified'].includes(d)) return 'allow';
  if (['block', 'reject', 'deny'].includes(d) || d.startsWith('deny')) return 'block';
  if (d.startsWith('require_approval')) return 'approval_required';
  if (d === 'escalate') return 'escalate';
  if (d === 'quarantine' || d === 'quarantined') return 'quarantine';
  if (d === '' || d === 'error') return 'error';
  return 'unknown';
}

// ── Errors ──────────────────────────────────────────────────────────────────

/** Base class for every error thrown by this client. */
export class SCMLError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SCMLError';
  }
}

/**
 * The mediator could not be reached, or returned a transport-level error.
 *
 * Thrown rather than returned, because a caller that cannot tell "allowed"
 * from "could not ask" will eventually treat the second as the first.
 */
export class SCMLUnavailable extends SCMLError {
  constructor(message: string) {
    super(message);
    this.name = 'SCMLUnavailable';
  }
}

/** The mediator returned a verdict that is not an allow. */
export class SCMLBlocked extends SCMLError {
  readonly result?: MediationResult;

  constructor(message: string, result?: MediationResult) {
    super(message);
    this.name = 'SCMLBlocked';
    this.result = result;
  }
}

// ── Result ──────────────────────────────────────────────────────────────────

/** One mediation decision, normalised across endpoint response shapes. */
export class MediationResult {
  readonly verdict: Verdict;
  readonly decision: string;
  readonly reason: string;
  readonly content?: string;
  readonly trustLabel?: string;
  readonly score?: number;
  readonly auditRef: string;
  readonly patternsMatched: string[];
  /** The unmodified server payload, for anything this class does not surface. */
  readonly raw: Record<string, unknown>;

  constructor(init: {
    verdict: Verdict;
    decision: string;
    reason?: string;
    content?: string;
    trustLabel?: string;
    score?: number;
    auditRef?: string;
    patternsMatched?: string[];
    raw?: Record<string, unknown>;
  }) {
    this.verdict = init.verdict;
    this.decision = init.decision;
    this.reason = init.reason ?? '';
    this.content = init.content;
    this.trustLabel = init.trustLabel;
    this.score = init.score;
    this.auditRef = init.auditRef ?? '';
    this.patternsMatched = init.patternsMatched ?? [];
    this.raw = init.raw ?? {};
  }

  /**
   * True only for an explicit allow.
   *
   * Quarantine, escalate, approval-required, error and unknown are all *not*
   * allowed. Gate side effects on this rather than on `verdict !== 'block'`.
   */
  get allowed(): boolean {
    return this.verdict === 'allow';
  }

  /** Throw {@link SCMLBlocked} unless the verdict is an allow. */
  assertAllowed(): this {
    if (!this.allowed) {
      throw new SCMLBlocked(
        `SCML ${this.verdict}: ${this.reason || this.decision}`,
        this,
      );
    }
    return this;
  }

  // -- constructors per response shape --------------------------------------

  /** For `/context` and `/tool-call`, which carry a `decision` field. */
  static fromDecision(p: Record<string, any>): MediationResult {
    const decision = String(p.decision ?? '');
    return new MediationResult({
      verdict: classifyDecision(decision),
      decision,
      // /context calls it `rationale`; /tool-call calls it `reason`.
      reason: String(p.reason ?? p.rationale ?? ''),
      content: p.content,
      trustLabel: p.trust_label,
      score: p.score,
      auditRef: String(p.audit_ref ?? ''),
      patternsMatched: Array.isArray(p.patterns_matched) ? p.patterns_matched : [],
      raw: p,
    });
  }

  /** For `/output`, which reports `blocked`/`action_allowed` and no `decision`. */
  static fromOutput(p: Record<string, any>): MediationResult {
    if (p.decision === 'error') {
      return new MediationResult({
        verdict: 'error', decision: 'error', reason: String(p.reason ?? ''), raw: p,
      });
    }
    const blocked = Boolean(p.blocked);
    // action_allowed is absent on older responses; only an explicit false blocks.
    const allowed = p.action_allowed !== false;
    const verdict: Verdict = blocked || !allowed ? 'block' : 'allow';
    return new MediationResult({
      verdict,
      decision: verdict,
      reason: String(p.block_reason ?? ''),
      content: p.content,
      auditRef: String(p.audit_ref ?? ''),
      raw: p,
    });
  }

  /** For `/memory/write`, which reports `verdict`, not `decision`. */
  static fromMemoryWrite(p: Record<string, any>): MediationResult {
    if (p.decision === 'error') {
      return new MediationResult({
        verdict: 'error', decision: 'error', reason: String(p.reason ?? ''), raw: p,
      });
    }
    const v = String(p.verdict ?? '');
    return new MediationResult({
      verdict: classifyDecision(v),
      decision: v,
      reason: String(p.quarantine_reason ?? ''),
      score: p.integrity_score,
      auditRef: String(p.audit_ref ?? ''),
      raw: p,
    });
  }

  /** For `/memory/read`, which reports `verified`/`withheld`. */
  static fromMemoryRead(p: Record<string, any>): MediationResult {
    if (p.decision === 'error') {
      return new MediationResult({
        verdict: 'error', decision: 'error', reason: String(p.reason ?? ''), raw: p,
      });
    }
    const withheld = Boolean(p.withheld);
    const verified = Boolean(p.verified);
    return new MediationResult({
      verdict: verified && !withheld ? 'allow' : 'block',
      decision: withheld ? 'withheld' : verified ? 'verified' : 'unverified',
      reason: String(p.reason ?? ''),
      content: p.content,
      score: p.integrity_score,
      raw: p,
    });
  }
}

// ── Client ──────────────────────────────────────────────────────────────────

export interface SCMLOptions {
  /** Base URL of the mediator, e.g. `http://192.168.1.42:8000`. */
  url?: string;
  /** Sent as `X-API-Key`. Omit in development mode, where auth is off. */
  apiKey?: string;
  /** Identifies this agent in audit logs and policy lookups. */
  agentId?: string;
  /** Per-request timeout in milliseconds (default 5000). */
  timeoutMs?: number;
  /** Optional logger; defaults to `console`. */
  logger?: Pick<Console, 'warn' | 'error'>;
}

/** Options accepted by every mediation call. */
export interface CallOptions {
  /**
   * Proceed when the mediator is unreachable instead of throwing.
   * Off by default — see the fail policy note at the top of this file.
   */
  failOpen?: boolean;
}

export const DEFAULT_URL = 'http://localhost:8000';
export const DEFAULT_TIMEOUT_MS = 5000;

/**
 * SCML client.
 *
 * ```ts
 * const scml = new SCML({ url: process.env.SCML_URL });
 * const ctx = await scml.mediateContext({ sessionId, content: supplierDoc });
 * const d = await scml.mediateToolCall({
 *   sessionId,
 *   tool: 'release_container',
 *   arguments: { containerId },
 *   argumentTrustLabels: { containerId: ctx.trustLabel ?? 'untrusted_data' },
 * });
 * if (!d.allowed) throw new Error(d.reason);
 * ```
 */
export class SCML {
  readonly url: string;
  readonly agentId: string;
  readonly timeoutMs: number;
  private readonly headers: Record<string, string>;
  private readonly logger: Pick<Console, 'warn' | 'error'>;

  constructor(options: SCMLOptions = {}) {
    this.url = (options.url ?? DEFAULT_URL).replace(/\/+$/, '');
    this.agentId = options.agentId ?? 'default';
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.logger = options.logger ?? console;
    this.headers = { 'Content-Type': 'application/json' };
    if (options.apiKey) this.headers['X-API-Key'] = options.apiKey;
  }

  /** Low-level escape hatch: returns the raw JSON body. */
  async request(
    method: string,
    path: string,
    body?: unknown,
    opts: CallOptions = {},
  ): Promise<Record<string, any>> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await fetch(`${this.url}${path}`, {
        method,
        headers: this.headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
      });
      if (!res.ok) {
        const text = await res.text().catch(() => '');
        throw new Error(`${res.status} ${res.statusText} ${text}`.trim());
      }
      return (await res.json()) as Record<string, any>;
    } catch (err) {
      return this.onTransportError(err, path, opts.failOpen === true);
    } finally {
      clearTimeout(timer);
    }
  }

  private onTransportError(
    err: unknown,
    path: string,
    failOpen: boolean,
  ): Record<string, any> {
    const detail = err instanceof Error ? err.message : String(err);
    if (!failOpen) {
      this.logger.error(`SCML mediator unreachable for ${path}: ${detail}`);
      throw new SCMLUnavailable(`SCML mediator unreachable for ${path}: ${detail}`);
    }
    this.logger.warn(
      `SCML FAIL-OPEN — ${path} could not be mediated (${detail}). ` +
        `Proceeding unmediated; this decision is NOT in the audit chain.`,
    );
    return { decision: 'error', reason: detail };
  }

  // -- mediation ------------------------------------------------------------

  /** Label and scan inbound content before an agent reads it (FR-IG-01). */
  async mediateContext(
    args: {
      sessionId: string;
      content: string;
      source?: string;
      sourceUri?: string;
      agentId?: string;
      metadata?: Record<string, unknown>;
    } & CallOptions,
  ): Promise<MediationResult> {
    const body = await this.request('POST', '/v1/mediate/context', {
      session_id: args.sessionId,
      content: args.content,
      source: args.source ?? 'tool_result',
      source_uri: args.sourceUri ?? '',
      agent_id: args.agentId ?? this.agentId,
      metadata: args.metadata ?? {},
    }, args);
    return MediationResult.fromDecision(body);
  }

  /**
   * Authorise a proposed tool call (FR-PE-01..04).
   *
   * `argumentTrustLabels` is not optional in practice: without it the engine
   * sees no untrusted arguments, so the untrusted-argument rule (FR-PE-04)
   * can never fire and a model-composed argument is indistinguishable from a
   * user-supplied one.
   */
  async mediateToolCall(
    args: {
      sessionId: string;
      tool: string;
      arguments?: Record<string, unknown>;
      argumentTrustLabels?: Record<string, string>;
      agentId?: string;
      isIrreversible?: boolean;
      isHighImpact?: boolean;
    } & CallOptions,
  ): Promise<MediationResult> {
    const body = await this.request('POST', '/v1/mediate/tool-call', {
      session_id: args.sessionId,
      tool_name: args.tool,
      arguments: args.arguments ?? {},
      argument_trust_labels: args.argumentTrustLabels ?? {},
      agent_id: args.agentId ?? this.agentId,
      is_irreversible: args.isIrreversible ?? false,
      is_high_impact: args.isHighImpact ?? false,
    }, args);
    return MediationResult.fromDecision(body);
  }

  /**
   * Redact and authorise an outbound response (FR-OR-01/02).
   *
   * `result.content` is the safe text to send. Substituting it is the
   * enforcement step — reading the verdict and sending the original anyway
   * enforces nothing.
   */
  async mediateOutput(
    args: {
      sessionId: string;
      content: string;
      destination?: string;
      dataClassLabels?: string[];
    } & CallOptions,
  ): Promise<MediationResult> {
    const body = await this.request('POST', '/v1/mediate/output', {
      session_id: args.sessionId,
      content: args.content,
      destination: args.destination ?? 'user',
      data_class_labels: args.dataClassLabels ?? [],
    }, args);
    return MediationResult.fromOutput(body);
  }

  /** Vet a candidate memory write (FR-MI-01). */
  async mediateMemoryWrite(
    args: {
      sessionId: string;
      content: string;
      source?: string;
      sourceUri?: string;
      trustLabel?: string;
      agentId?: string;
      metadata?: Record<string, unknown>;
    } & CallOptions,
  ): Promise<MediationResult> {
    const body = await this.request('POST', '/v1/mediate/memory/write', {
      session_id: args.sessionId,
      content: args.content,
      source: args.source ?? 'agent',
      source_uri: args.sourceUri ?? '',
      trust_label: args.trustLabel ?? 'untrusted_data',
      agent_id: args.agentId ?? this.agentId,
      metadata: args.metadata ?? {},
    }, args);
    return MediationResult.fromMemoryWrite(body);
  }

  /** Verify a memory record before the agent acts on it (FR-MI-02). */
  async mediateMemoryRead(
    args: {
      sessionId: string;
      memoryId: string;
      agentId?: string;
      rescan?: boolean;
    } & CallOptions,
  ): Promise<MediationResult> {
    const body = await this.request('POST', '/v1/mediate/memory/read', {
      session_id: args.sessionId,
      memory_id: args.memoryId,
      agent_id: args.agentId ?? this.agentId,
      rescan: args.rescan ?? false,
    }, args);
    return MediationResult.fromMemoryRead(body);
  }

  // -- audit ----------------------------------------------------------------

  /** Return the full decision trail for a session (FR-AL-01). */
  async replaySession(sessionId: string, opts: CallOptions = {}): Promise<Record<string, any>> {
    return this.request('GET', `/v1/audit/replay/${sessionId}`, undefined, opts);
  }

  /** Liveness probe. Fails open by default — it is not a decision point. */
  async health(opts: CallOptions = { failOpen: true }): Promise<Record<string, any>> {
    return this.request('GET', '/health', undefined, opts);
  }
}

/** Alias — the engine's name, for symmetry with the Python SDK. */
export const TrustMediatorClient = SCML;
export const SCMLClient = SCML;

export default SCML;
