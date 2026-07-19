"""
Global settings — loaded from environment variables / .env file.
All module configuration is consolidated here so the whole system
can be tuned through a single .env without touching source code.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    @property
    def api_keys(self) -> list[str]:
        """Return a list of valid API keys (strips whitespace, drops empties)."""
        return [k.strip() for k in self.api_keys_raw.split(",") if k.strip()]

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
    memory_rescan_on_read: bool = Field(default=False, alias="MEMORY_RESCAN_ON_READ")

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
