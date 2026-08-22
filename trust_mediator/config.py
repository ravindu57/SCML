"""
Global settings — loaded from environment variables / .env file.
All module configuration is consolidated here so the whole system
can be tuned through a single .env without touching source code.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# A principal name in TRUST_MEDIATOR_API_KEYS ("alice:sk-abc123"). Deliberately
# narrow so an unnamed key that happens to contain a colon is not misread as one.
_PRINCIPAL_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def parse_key_entries(raw: str) -> list[tuple[str | None, str]]:
    """Parse API key entries into (principal, key) pairs.

    Accepts the env-var form (comma-separated) and the file form (one per
    line, ``#`` comments allowed), because the same text is read from both
    ``TRUST_MEDIATOR_API_KEYS`` and ``TRUST_MEDIATOR_API_KEYS_FILE``.

    Each entry is a bare key (``sk-abc123``) or a named one
    (``alice:sk-abc123``). The name is what lands in audit records for admin
    actions, so an operator can tell *which* keyholder released a quarantined
    record. Unnamed keys get ``None`` here and are identified downstream by
    fingerprint, never by the key itself.

    A name is only recognised when it looks like an identifier and leaves a
    non-empty remainder, so an unnamed key containing a colon is still treated
    as one key. The residual ambiguity — an unnamed key whose text before the
    first colon happens to be identifier-shaped — fails closed and loudly: the
    key simply stops authenticating.
    """
    pairs: list[tuple[str | None, str]] = []
    for line in raw.splitlines():
        # A trailing "#" comment cannot be stripped from the middle of a line:
        # "#" is a legal character in a key. Only whole-line comments count.
        if line.lstrip().startswith("#"):
            continue
        for chunk in line.split(","):
            entry = chunk.strip()
            if not entry:
                continue
            name, sep, key = entry.partition(":")
            if sep and key and _PRINCIPAL_NAME_RE.match(name):
                pairs.append((name, key))
            else:
                pairs.append((None, entry))
    return pairs


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="TRUST_MEDIATOR_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Service ───────────────────────────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 8000
    env: Literal["development", "production", "test"] = "development"
    log_level: str = "INFO"
    secret_key: str = "change-me-to-a-random-256-bit-secret"
    workers: int = 1
    # Comma-separated API keys, e.g. "sk-abc123,sk-def456"
    # Leave empty in development for open access.
    api_keys_raw: str = Field(default="", alias="TRUST_MEDIATOR_API_KEYS")

    # Read API keys from a file instead of the env var. This is how a secrets
    # manager delivers them (Kubernetes Secret, Vault Agent, External Secrets
    # Operator all render a file), and it is what makes rotation possible
    # without a restart — see trust_mediator/api/key_store.py.
    api_keys_file: str = Field(default="", alias="TRUST_MEDIATOR_API_KEYS_FILE")
    # How long a loaded key set is trusted before the file is re-stat'ed.
    api_keys_reload_seconds: float = Field(
        default=5.0, alias="TRUST_MEDIATOR_API_KEYS_RELOAD_SECONDS"
    )

    @property
    def api_key_principals(self) -> list[tuple[str | None, str]]:
        """(principal, key) pairs from TRUST_MEDIATOR_API_KEYS.

        The env source only. Callers that must honour a rotating key file want
        ``trust_mediator.api.key_store.principals()`` instead.
        """
        return parse_key_entries(self.api_keys_raw)

    @property
    def api_keys(self) -> list[str]:
        """The valid API keys from the env var, stripped of any prefix."""
        return [key for _, key in self.api_key_principals]

    # ── gRPC (FR-IG-02) ───────────────────────────────────────────────────────
    grpc_enabled: bool = Field(default=False, alias="TRUST_MEDIATOR_GRPC_ENABLED")
    grpc_port: int = Field(default=50051, alias="TRUST_MEDIATOR_GRPC_PORT")

    # ── HTTP hardening ────────────────────────────────────────────────────────
    # Comma-separated allowed CORS origins for production, e.g.
    # "https://console.example.com,https://ops.example.com". Ignored in dev
    # (dev allows all origins for the local frontend).
    cors_origins_raw: str = Field(default="", alias="TRUST_MEDIATOR_CORS_ORIGINS")
    # Comma-separated allowed Host header values, e.g. "mediator.example.com".
    # Empty = no host filtering (rely on the ingress / nginx layer).
    trusted_hosts_raw: str = Field(default="", alias="TRUST_MEDIATOR_TRUSTED_HOSTS")
    # Emit Strict-Transport-Security (enable once TLS terminates in front).
    hsts_enabled: bool = Field(default=False, alias="TRUST_MEDIATOR_HSTS_ENABLED")

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.cors_origins_raw.split(",") if o.strip()]

    @property
    def trusted_hosts(self) -> list[str]:
        return [h.strip() for h in self.trusted_hosts_raw.split(",") if h.strip()]

    # ── TLS / mTLS (NFR-SEC-03) ───────────────────────────────────────────────
    # Server certificate. Setting both enables TLS on the HTTP and gRPC ports.
    tls_cert_file: str = Field(default="", alias="TRUST_MEDIATOR_TLS_CERT_FILE")
    tls_key_file: str = Field(default="", alias="TRUST_MEDIATOR_TLS_KEY_FILE")
    # CA bundle used to verify *client* certificates (mTLS).
    tls_ca_file: str = Field(default="", alias="TRUST_MEDIATOR_TLS_CA_FILE")
    # Require and verify a client certificate. Needs tls_ca_file.
    tls_require_client_cert: bool = Field(
        default=False, alias="TRUST_MEDIATOR_TLS_REQUIRE_CLIENT_CERT"
    )
    # Explicit opt-out for plaintext in production — the supported way to say
    # "TLS terminates at the ingress or service mesh". Without it, a production
    # process refuses to start over plaintext rather than serving mediation
    # decisions and API keys in the clear because nobody set a certificate.
    allow_insecure_http: bool = Field(
        default=False, alias="TRUST_MEDIATOR_ALLOW_INSECURE_HTTP"
    )

    @property
    def tls_enabled(self) -> bool:
        """TLS is on only when both halves of the keypair are configured."""
        return bool(self.tls_cert_file and self.tls_key_file)

    @property
    def mtls_enabled(self) -> bool:
        return self.tls_enabled and self.tls_require_client_cert and bool(self.tls_ca_file)

    # ── Database ──────────────────────────────────────────────────────────────
    database_url: str = Field(
        default="sqlite+aiosqlite:///./trust_mediator.db",
        alias="DATABASE_URL",
    )

    # ── Redis ─────────────────────────────────────────────────────────────────
    redis_url: str = Field(default="", alias="REDIS_URL")

    @property
    def redis_enabled(self) -> bool:
        return bool(self.redis_url)

    # ── Injection Scanner ─────────────────────────────────────────────────────
    scanner_backend: Literal["heuristic", "onnx", "llm"] = Field(
        default="heuristic", alias="SCANNER_BACKEND"
    )
    scanner_shadow_mode: bool = Field(default=False, alias="SCANNER_SHADOW_MODE")
    scanner_block_threshold: float = Field(default=0.85, alias="SCANNER_BLOCK_THRESHOLD")
    scanner_escalate_threshold: float = Field(
        default=0.70, alias="SCANNER_ESCALATE_THRESHOLD"
    )
    scanner_transform_threshold: float = Field(
        default=0.50, alias="SCANNER_TRANSFORM_THRESHOLD"
    )
    #: Heuristic score at or above which stage 2 (the ML classifier) is consulted.
    #:
    #: This is a cost control, not a detection threshold: it exists so an
    #: expensive backend is not invoked on every scan. But it gates recall on
    #: the *cheap* stage, so stage 2 can only ever see what stage 1 already
    #: suspects — and measured against InjecAgent the pre-filter scores exactly
    #: 0.0 on 992 of 1054 attacks, so a classifier of any quality is consulted
    #: on none of them (`tests/unit/test_scanner_ml_gate.py`).
    #:
    #: Set to 0.0 to scan everything. Required for `SCANNER_BACKEND=llm` to be
    #: worth paying for; the default preserves the historic behaviour.
    scanner_ml_gate_threshold: float = Field(
        default=0.20, alias="SCANNER_ML_GATE_THRESHOLD"
    )

    # ── LLM Scanner / Alignment Auditor ──────────────────────────────────────
    llm_scanner_api_key: str = Field(default="", alias="LLM_SCANNER_API_KEY")
    llm_scanner_base_url: str = Field(
        default="https://api.openai.com/v1", alias="LLM_SCANNER_BASE_URL"
    )
    llm_scanner_model: str = Field(default="gpt-4o-mini", alias="LLM_SCANNER_MODEL")
    llm_scanner_no_retention: bool = Field(
        default=True, alias="LLM_SCANNER_NO_RETENTION"
    )

    # ── Memory Integrity ──────────────────────────────────────────────────────
    memory_integrity_threshold: float = Field(
        default=0.65, alias="MEMORY_INTEGRITY_THRESHOLD"
    )
    # FR-MI-04 is a Must requirement: memory must be re-verified on read so
    # entries written before a policy update are still checked. Defaulting this
    # off left that requirement opt-in. Measured cost is ~4 ms against the
    # §8.1 400 ms fast-path budget.
    memory_rescan_on_read: bool = Field(default=True, alias="MEMORY_RESCAN_ON_READ")

    # ── Consistency checker (FR-MI-02) ───────────────────────────────────────
    # These four gate the contradiction/instruction detector, which the §14.3
    # ablation shows is the largest single contributor to the memory-poisoning
    # defence (disabling it takes ASR 33.3% -> 64.6%). They were literals in
    # consistency_checker.py, so the layer doing most of the work was the one
    # that could not be adjusted without a code change.
    #
    # Defaults reproduce the previous constants exactly. Do not tune them
    # against the in-house corpus — see the note in CLAUDE.md; that is
    # overfitting, not a result.
    #: combined_risk above which a candidate write is flagged suspicious.
    memory_consistency_suspicion_threshold: float = Field(
        default=0.40, alias="MEMORY_CONSISTENCY_SUSPICION_THRESHOLD"
    )
    #: Minimum Jaccard token overlap for two entries to be considered as
    #: possibly contradicting. Below this they are about different things, so
    #: a negation between them is not a contradiction.
    memory_contradiction_overlap_min: float = Field(
        default=0.25, alias="MEMORY_CONTRADICTION_OVERLAP_MIN"
    )
    #: Minimum negation divergence before an overlapping pair counts as
    #: contradictory rather than merely similar.
    memory_negation_divergence_min: float = Field(
        default=0.30, alias="MEMORY_NEGATION_DIVERGENCE_MIN"
    )
    #: Minimum combined score for a specific existing record to be *named* as
    #: contradicted. Distinct from the two above: those decide whether a
    #: contradiction exists at all, this decides which records are cited for
    #: review, so raising it hides evidence rather than changing the verdict.
    memory_contradiction_report_min: float = Field(
        default=0.30, alias="MEMORY_CONTRADICTION_REPORT_MIN"
    )

    # ── Rate Limiting ─────────────────────────────────────────────────────────
    # slowapi limit string, e.g. "200/minute", "500/minute", "10/second"
    rate_limit: str = Field(default="200/minute", alias="TRUST_MEDIATOR_RATE_LIMIT")

    # ── Human-in-the-Loop Escalation Webhook ─────────────────────────────────
    # POST target when a mediation decision = 'escalate'
    # Compatible with Slack Incoming Webhooks, MS Teams, PagerDuty, or any HTTP endpoint.
    # Leave empty to disable (safe default for development).
    escalation_webhook_url: str = Field(default="", alias="TRUST_MEDIATOR_ESCALATION_WEBHOOK_URL")
    escalation_timeout_s: int = Field(default=5, alias="TRUST_MEDIATOR_ESCALATION_TIMEOUT_S")

    # ── Audit / SIEM ──────────────────────────────────────────────────────────
    audit_siem_webhook_url: str = Field(default="", alias="AUDIT_SIEM_WEBHOOK_URL")
    audit_kafka_bootstrap: str = Field(default="", alias="AUDIT_KAFKA_BOOTSTRAP")
    # Max events the background writer coalesces into one transaction. Batches
    # are opportunistic — under light load they are size 1 and behaviour is
    # unchanged. Larger values raise sustained audit throughput but hold the
    # per-session row lock for longer; 1 restores per-event writes.
    audit_batch_max: int = Field(default=128, alias="AUDIT_BATCH_MAX")
    # Bound on the in-memory audit queue. Unbounded, offered load above writer
    # throughput grew the queue until the process died and took every queued
    # decision with it. 0 restores the unbounded behaviour. At the measured
    # ~2,800 events/s drain rate the default is roughly 3.5s of burst headroom.
    audit_queue_maxsize: int = Field(default=10_000, alias="AUDIT_QUEUE_MAXSIZE")
    # What to do when the queue is full. Neither option is good — that is the
    # point of bounding it — but the choice must be explicit and recorded.
    #   drop_newest: refuse the incoming event, keep the backlog intact
    #   drop_oldest: evict the head to make room, preferring recent events
    audit_overflow_policy: Literal["drop_newest", "drop_oldest"] = Field(
        default="drop_newest", alias="AUDIT_OVERFLOW_POLICY"
    )

    # ── Policy ────────────────────────────────────────────────────────────────
    policy_default_file: str = Field(
        default="policies/default_policy.yaml", alias="POLICY_DEFAULT_FILE"
    )

    # ── Observability ─────────────────────────────────────────────────────────
    otel_exporter_otlp_endpoint: str = Field(
        default="", alias="OTEL_EXPORTER_OTLP_ENDPOINT"
    )
    otel_service_name: str = Field(default="trust-mediator", alias="OTEL_SERVICE_NAME")

    @field_validator("database_url", mode="before")
    @classmethod
    def default_sqlite_if_empty(cls, v: str) -> str:
        if not v:
            return "sqlite+aiosqlite:///./trust_mediator.db"
        return v

    @property
    def is_development(self) -> bool:
        return self.env == "development"

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @property
    def policy_default_path(self) -> Path:
        return Path(self.policy_default_file)


# Singleton settings instance used throughout the application
settings = Settings()


class InsecureTransportError(RuntimeError):
    """A production listener was asked to start without TLS (NFR-SEC-03)."""


def require_secure_transport(component: str) -> None:
    """Fail closed rather than serve a production listener in the clear.

    Every credential and every mediation decision crosses this socket, so
    plaintext in production defeats the API key work entirely — it is a header
    anyone on the path can read and replay.

    Terminating TLS at an ingress or service mesh is a legitimate deployment,
    so this is an opt-out rather than a hard requirement. What it is not is a
    *silent* default: ``TRUST_MEDIATOR_ALLOW_INSECURE_HTTP=true`` makes the
    choice explicit and greppable, which is the difference between a decision
    and an oversight.
    """
    if not settings.is_production:
        return
    if settings.tls_enabled or settings.allow_insecure_http:
        return
    raise InsecureTransportError(
        f"{component} refused to start: TRUST_MEDIATOR_ENV=production with no TLS. "
        "Set TRUST_MEDIATOR_TLS_CERT_FILE and TRUST_MEDIATOR_TLS_KEY_FILE, or set "
        "TRUST_MEDIATOR_ALLOW_INSECURE_HTTP=true if TLS terminates in front of "
        "this process (ingress, service mesh, or nginx)."
    )
