"""FastAPI dependency injection — pipeline, audit logger, policy store."""
from __future__ import annotations

from typing import Annotated

from fastapi import Depends

from trust_mediator.core.pipeline import MediationPipeline
from trust_mediator.modules.audit_log.logger import AuditLogger
from trust_mediator.modules.policy_store.store import PolicyStore

# Singletons shared across the lifetime of the process
_pipeline: MediationPipeline | None = None
_audit: AuditLogger | None = None
_policy_store: PolicyStore | None = None


def get_pipeline() -> MediationPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = MediationPipeline()
    return _pipeline


def get_audit_logger() -> AuditLogger:
    global _audit
    if _audit is None:
        _audit = get_pipeline()._audit
    return _audit


def get_policy_store() -> PolicyStore:
    global _policy_store
    if _policy_store is None:
        _policy_store = PolicyStore()
    return _policy_store


PipelineDep = Annotated[MediationPipeline, Depends(get_pipeline)]
AuditDep = Annotated[AuditLogger, Depends(get_audit_logger)]
PolicyStoreDep = Annotated[PolicyStore, Depends(get_policy_store)]
