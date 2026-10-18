"""
Tenant scoping for session ids (FR-AL-02, NFR-SEC-02 / security review Sec #6).

Session ids are chosen by clients. The audit hash chain and memory provenance
are keyed by them, so before tenancy two companies sending the same
``session_id`` shared one chain: either could replay the other's decision
trail, and their events interleaved in one sequence.

Rather than add a tenant column to the chain key (a unique-constraint change on
a table that may already hold years of events), the tenant is folded into the
session id at the API boundary: ``acme`` + ``s1`` -> ``acme::s1``. It is then
inside the hashed ``session_id`` field of every event, and every read and write
of that session is confined to the tenant whose key made the call.

Two rules make this sound:

- **The default tenant keeps raw ids**, so every chain written before tenancy
  replays exactly as it did.
- **A client id may not contain the separator.** Otherwise a default-tenant
  caller could send ``acme::s1`` and land in acme's chain. Tenant names cannot
  contain ``:`` (``_TENANT_RE`` in config.py), so the scoped form is
  unambiguous.
"""
from __future__ import annotations

from trust_mediator.config import settings

SEPARATOR = "::"
#: Longest client session id accepted. The scoped form is at most
#: 64 (tenant) + 2 + this, which must fit the 200-character session columns.
MAX_SESSION_ID = 128


class InvalidSessionId(ValueError):
    """A client-supplied session id contained the tenant separator."""


def scoped_session(tenant: str, session_id: str) -> str:
    """The internal session key for ``session_id`` as seen by ``tenant``."""
    if len(session_id) > MAX_SESSION_ID:
        # Rejected here rather than left to the database: PostgreSQL raises on
        # an overlong value inside the audit writer, where the event is dropped.
        raise InvalidSessionId(f"session_id longer than {MAX_SESSION_ID} characters")
    if SEPARATOR in session_id:
        raise InvalidSessionId(
            f"session_id may not contain {SEPARATOR!r}: it is reserved for tenant scoping"
        )
    if tenant == settings.default_tenant:
        return session_id
    return f"{tenant}{SEPARATOR}{session_id}"


#: First segment of every control-plane chain. ``#`` is not a legal tenant
#: character, and client ids cannot contain the separator, so no scoped client
#: session can ever equal a control-plane session.
CONTROL_PLANE = "#control-plane"


def control_session(tenant: str) -> str:
    """The audit chain that records a tenant's administrative actions."""
    return f"{CONTROL_PLANE}{SEPARATOR}{tenant}"
