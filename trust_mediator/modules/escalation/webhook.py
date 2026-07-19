"""
Human-in-the-Loop Escalation Webhook Dispatcher.

When a mediation decision is `escalate`, this module fires an async HTTP POST
to the configured webhook URL (Slack, Teams, PagerDuty, or any HTTP endpoint).

Configuration:
    TRUST_MEDIATOR_ESCALATION_WEBHOOK_URL  — webhook endpoint to POST to
                                             If empty, escalations are only logged.
    TRUST_MEDIATOR_ESCALATION_TIMEOUT_S   — HTTP timeout in seconds (default: 5)

Webhook payload (all fields):
    {
        "source":          "scml-middleware-layer-secure",
        "event":           "escalation",
        "timestamp":       "2026-07-19T11:30:00Z",
        "session_id":      "...",
        "agent_id":        "...",
        "decision":        "escalate",
        "score":           0.73,
        "patterns_matched": ["role_override_ignore"],
        "content_preview": "First 200 chars of the flagged content...",
        "action_required": "Review and approve or block this agent action."
    }

Slack compatibility:
    Set TRUST_MEDIATOR_ESCALATION_WEBHOOK_URL to a Slack Incoming Webhook URL.
    The dispatcher sends a primary JSON payload AND attaches a Slack-formatted
    `text` field so it renders nicely in Slack channels out of the box.

Teams compatibility:
    Compatible with Microsoft Teams Incoming Webhook (card format included).
"""
from __future__ import annotations

import asyncio
import datetime
import logging
from typing import Any

import httpx
import structlog

from trust_mediator.config import settings

logger = structlog.get_logger(__name__)
_stdlib_logger = logging.getLogger(__name__)


async def fire_escalation_webhook(
    *,
    session_id: str,
    agent_id: str,
    score: float,
    patterns_matched: list[str],
    content_preview: str,
    decision: str = "escalate",
) -> None:
    """
    Fire an escalation webhook notification asynchronously.

    This is a fire-and-forget call — it does not block the API response.
    A single retry is attempted on failure.

    Args:
        session_id:       Agent session that triggered the escalation.
        agent_id:         Identifier of the agent.
        score:            Trust/threat score that caused the escalation.
        patterns_matched: List of patterns / rule IDs that matched.
        content_preview:  First 200 chars of the flagged content.
        decision:         Decision value (always "escalate" in practice).
    """
    webhook_url = settings.escalation_webhook_url
    if not webhook_url:
        logger.debug(
            "escalation.webhook.skipped",
            reason="TRUST_MEDIATOR_ESCALATION_WEBHOOK_URL not configured",
            session_id=session_id,
        )
        return

    timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    preview = (content_preview[:200] + "…") if len(content_preview) > 200 else content_preview

    payload: dict[str, Any] = {
        "source": "scml-middleware-layer-secure",
        "event": "escalation",
        "timestamp": timestamp,
        "session_id": session_id,
        "agent_id": agent_id,
        "decision": decision,
        "score": round(score, 4),
        "patterns_matched": patterns_matched,
        "content_preview": preview,
        "action_required": "Review and approve or block this agent action at your dashboard.",
        # ── Slack-compatible field ──────────────────────────────────────────
        "text": (
            f":rotating_light: *ESCALATION — Human Review Required*\n"
            f">*Agent:* `{agent_id}`  |  *Session:* `{session_id}`\n"
            f">*Score:* `{score:.3f}`  |  *Patterns:* `{', '.join(patterns_matched) or 'none'}`\n"
            f">*Preview:* _{preview}_\n"
            f">*Time:* {timestamp}"
        ),
    }

    timeout = getattr(settings, "escalation_timeout_s", 5)

    async def _send(attempt: int) -> bool:
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(webhook_url, json=payload)
                resp.raise_for_status()
                logger.info(
                    "escalation.webhook.sent",
                    session_id=session_id,
                    agent_id=agent_id,
                    score=score,
                    status_code=resp.status_code,
                    attempt=attempt,
                )
                return True
        except Exception as exc:
            logger.warning(
                "escalation.webhook.failed",
                session_id=session_id,
                error=str(exc),
                attempt=attempt,
            )
            return False

    # Attempt 1
    success = await _send(attempt=1)
    if not success:
        # One retry after a short back-off
        await asyncio.sleep(2)
        await _send(attempt=2)


def schedule_escalation_webhook(**kwargs: Any) -> None:
    """
    Schedule the webhook in the running event loop without blocking.

    Call this from a synchronous or async context — it will safely create
    a background task that outlives the current request.

    Usage:
        from trust_mediator.modules.escalation.webhook import schedule_escalation_webhook

        schedule_escalation_webhook(
            session_id=...,
            agent_id=...,
            score=0.73,
            patterns_matched=["role_override_ignore"],
            content_preview="Ignore all previous instructions...",
        )
    """
    try:
        loop = asyncio.get_event_loop()
        loop.create_task(fire_escalation_webhook(**kwargs))
    except RuntimeError:
        # No running event loop — fall back to asyncio.run (test contexts)
        asyncio.run(fire_escalation_webhook(**kwargs))
