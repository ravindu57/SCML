"""
TrustMediator — Trust-Aware Context Mediation Middleware
=========================================================
A lightweight, framework-agnostic security layer that sits between an LLM agent
and everything it reads or acts on. Provides:

  • Trust classification and taint propagation
  • Injection scanning (heuristic + pluggable classifier)
  • Least-agency tool-call policy enforcement
  • Memory write integrity vetting (primary contribution)
  • Output redaction and exfiltration prevention
  • Append-only tamper-evident audit logging

PRD Reference: TrustMediator PRD v1.0 (16 July 2026)
"""

__version__ = "1.0.0"
__author__ = "TrustMediator Project"

from trust_mediator.config import settings  # noqa: F401
