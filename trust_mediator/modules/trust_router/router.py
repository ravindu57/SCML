"""
§6.2 — Trust Router: taint and provenance labelling.

Assigns each value a trust label based on its source and configured rules,
propagates taint, and keeps trusted instructions and untrusted data in
separate channels (FR-TR-01, FR-TR-02, FR-TR-03).
"""

from __future__ import annotations


import structlog

from trust_mediator.models.context_envelope import (
    ContextEnvelope,
    TrustLabel,
)

logger = structlog.get_logger(__name__)

# Source → default trust label mapping
_SOURCE_LABEL_MAP: dict[str, TrustLabel] = {
    "user_query": TrustLabel.TRUSTED_INSTRUCTION,
    "system_policy": TrustLabel.TRUSTED_INSTRUCTION,
    "tool_result": TrustLabel.UNTRUSTED_DATA,
    "rag_retrieval": TrustLabel.UNTRUSTED_DATA,
    "memory": TrustLabel.UNTRUSTED_DATA,
    "agent_output": TrustLabel.DERIVED,
    "web_content": TrustLabel.RISKY_EXTERNAL,
    "email": TrustLabel.RISKY_EXTERNAL,
    "attachment": TrustLabel.RISKY_EXTERNAL,
    "third_party_agent": TrustLabel.UNTRUSTED_DATA,
    "derived": TrustLabel.DERIVED,
}


class TrustRouter:
    """
    Labels and routes context envelopes.

    Core invariant (§5.2):
        Data labelled UNTRUSTED_DATA or RISKY_EXTERNAL can contribute to
        what the agent *knows* but can never, on its own, determine what
        the agent *does*. Control flow derives only from TRUSTED_INSTRUCTION
        + policy.
    """

    def __init__(self, custom_label_map: dict[str, TrustLabel] | None = None) -> None:
        self._label_map = {**_SOURCE_LABEL_MAP, **(custom_label_map or {})}

    def assign_label(self, envelope: ContextEnvelope) -> ContextEnvelope:
        """
        Assign or verify a trust label based on the envelope's source.
        The envelope's own trust_label is accepted if it is already set;
        if the source map implies a more restrictive label, the stricter
        one wins (never-promote rule).
        """
        source = envelope.provenance.source
        source_label = self._label_map.get(source, TrustLabel.UNTRUSTED_DATA)

        # Never-promote: take the most restrictive of current vs source-default
        effective_label = TrustLabel.most_restrictive(
            [envelope.trust_label, source_label]
        )

        if effective_label != envelope.trust_label:
            logger.debug(
                "trust_router.label_adjusted",
                envelope_id=envelope.id,
                original=envelope.trust_label,
                adjusted=effective_label,
                reason="source_map_more_restrictive",
            )

        updated_taint = list(set(envelope.taint_set + [effective_label]))
        return envelope.model_copy(
            update={
                "trust_label": effective_label,
                "taint_set": updated_taint,
            }
        )

    def propagate_taint(
        self, derived: ContextEnvelope, parents: list[ContextEnvelope]
    ) -> ContextEnvelope:
        """
        Apply taint propagation: a derived value inherits the most restrictive
        label of all its parents (FR-TR-02).
        """
        all_labels = [p.trust_label for p in parents]
        all_taint: list[TrustLabel] = []
        for p in parents:
            all_taint.extend(p.taint_set)

        most_restrictive = TrustLabel.most_restrictive(all_labels + all_taint)
        combined_taint = list(set(all_taint + all_labels + [most_restrictive]))

        logger.debug(
            "trust_router.taint_propagated",
            derived_id=derived.id,
            parent_ids=[p.id for p in parents],
            result_label=most_restrictive,
        )

        return derived.model_copy(
            update={
                "trust_label": most_restrictive,
                "taint_set": combined_taint,
            }
        )

    def is_control_eligible(self, envelope: ContextEnvelope) -> bool:
        """
        Returns True only if this envelope may influence the agent's
        control / plan path (FR-TR-03).
        Only TRUSTED_INSTRUCTION envelopes qualify.
        """
        return envelope.trust_label == TrustLabel.TRUSTED_INSTRUCTION

    def separate_channels(
        self, envelopes: list[ContextEnvelope]
    ) -> tuple[list[ContextEnvelope], list[ContextEnvelope]]:
        """
        Split envelopes into (trusted_channel, untrusted_channel).
        The trusted channel feeds the plan; the untrusted channel feeds
        the quarantined LLM that processes data only (FR-TR-03).
        """
        trusted = [e for e in envelopes if self.is_control_eligible(e)]
        untrusted = [e for e in envelopes if not self.is_control_eligible(e)]
        return trusted, untrusted

    def route(self, envelope: ContextEnvelope) -> ContextEnvelope:
        """Convenience: assign label, update taint, return routed envelope."""
        return self.assign_label(envelope)
