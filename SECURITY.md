# Security Policy

TrustMediator is security infrastructure: it decides whether an agent may take
an action, and it produces the audit record of that decision. A flaw here does
not just affect this project — it affects whatever was trusting it. Please
report problems rather than filing them publicly.

## Reporting a vulnerability

**Do not open a public issue for a security bug.**

- Preferred: [GitHub private vulnerability reporting](https://github.com/ravindu57/SCML/security/advisories/new)
  (Security → Report a vulnerability).
- Alternative: email the maintainer at the address on the latest commits
  (`git log -1 --format='%ae'`).

Useful in a report: the version or commit, how the mediator was configured
(`TRUST_MEDIATOR_ENV`, whether API keys or TLS were set), what you sent, what
happened, and what you expected. A failing test or `curl` is worth more than a
description.

This is a single-maintainer project with no paid support and no bug bounty.
Expect an acknowledgement within **7 days** and an assessment within **30**. If
you hear nothing, assume the message was missed and follow up — that is not
rudeness, it is how a small project stays honest.

Please give a reasonable window to ship a fix before publishing. If a flaw is
already being exploited, say so and disclose on whatever timeline protects
users.

## What counts as a vulnerability

The trust invariants are the product. Anything that breaks one is in scope,
even if no memory is corrupted and nothing crashes:

- **Control-path contamination (PRD §5.2)** — data labelled `untrusted_data` or
  `risky_external` influencing a policy decision or authorising a tool call.
- **Taint laundering** — a derived value carrying a weaker label than its
  inputs.
- **Fail-open on a side-effect path (PRD §9)** — a tool call, memory write or
  outbound response proceeding after a mediator error.
- **Audit integrity (FR-AL-01)** — forging, reordering or silently dropping a
  chained event, or attributing an action to a principal that did not take it.
- **Authentication and authorisation** — reaching a `/v1` endpoint without a
  valid key, or acting beyond the policy for an `agent_id`.
- **Secret disclosure** — an API key reaching a log line, span attribute, error
  body, metrics label or rate-limit bucket name.

### Known-weak areas, already documented

These are published limitations, not vulnerabilities. Reports are still
welcome, but they will not be treated as new findings — see the "Known gaps"
and "Measured state" sections of [CLAUDE.md](CLAUDE.md):

- **The injection scanner detects 0 of 1054 InjecAgent attacks.** Enforcement,
  not detection, is what holds. Demonstrating that a payload evades the scanner
  is expected; demonstrating that it evades *tool policy* is a vulnerability.
- **Memory-poisoning ASR is 33.3% storage / 18.8% harm** against a <10% target.
  §14.2 acceptance is not met and this is stated openly.
- **The policy document is single-tenant.** `PUT /v1/policy` replaces it whole,
  so two administrators clobber each other. Known; the fix is a per-agent
  endpoint that is not built.
- **Audit overflow drops events**, records that it did, and does not spill to
  disk.
- **No sandboxed tool executor** (PRD §11) — execution stays in the host app.
- **TLS is supported but off in every shipped deployment**, which terminates at
  nginx/Ingress. Connections to Postgres, Redis and Kafka are plaintext.

## Supported versions

Pre-1.0 in practice, despite the version string. Only `main` is supported;
there are no backports. Fixes land on `main` and are described in the commit.

## Deploying this safely

Defaults that matter, and the ways they are commonly got wrong:

- **Set `TRUST_MEDIATOR_API_KEYS` or `TRUST_MEDIATOR_API_KEYS_FILE`.** With
  neither, development mode serves unauthenticated callers. Production rejects
  everything instead — that is deliberate.
- **Give each workflow or sub-agent its own `agent_id`.** One shared id makes
  the allow-list the union of everything any part of the system needs, which is
  the opposite of least agency. An unknown id falls back to `default`, which is
  deny-all by design.
- **Send `argument_trust_labels`.** Without them the untrusted-argument rule
  (FR-PE-04) never fires and a model-composed argument is indistinguishable
  from a user-supplied one.
- **Terminate TLS somewhere.** Production refuses to start in plaintext unless
  `TRUST_MEDIATOR_ALLOW_INSECURE_HTTP=true` says an ingress is doing it.
- **Rotate keys through the key file, not the env var.** Revoke by *emptying*
  the file; deleting it is indistinguishable from a broken mount, so the last
  good key set is retained.

## Credit

Reporters are credited in the fix commit unless they ask not to be.
