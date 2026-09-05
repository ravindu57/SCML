"""
API key resolution with rotation and revocation (NFR-SEC-04).

``TRUST_MEDIATOR_API_KEYS`` is read once, when the settings singleton is built,
so rotating or revoking a key meant restarting every worker. During a
compromise that is the worst possible time to need a rolling restart, and on a
single-instance deployment it is an outage.

This adds a second source: ``TRUST_MEDIATOR_API_KEYS_FILE``. A file is what a
secrets manager actually delivers — a Kubernetes Secret volume, Vault Agent
template, and External Secrets Operator all render one — so pointing at a file
is what makes rotation an infrastructure concern rather than a deploy.

Rotation: add the new key alongside the old, let clients migrate, remove the
old one. Revocation: remove the entry. Both take effect within
``TRUST_MEDIATOR_API_KEYS_RELOAD_SECONDS`` (default 5).

**On read failure the last good key set is kept**, and the error is logged on
every attempt. The alternative — treating an unreadable file as "no keys" —
turns a transient mount or permission glitch into a total authentication
outage, and secret managers rewrite these files by atomic rename precisely so
readers never observe a partial state. The consequence is that *deleting* the
file does not revoke anything. Revoke by emptying it: an empty file is a
readable, deliberate "no keys configured", and is honoured immediately.
"""
from __future__ import annotations

import os
import threading
import time

import structlog

from trust_mediator.config import KeyEntry, parse_key_entries_with_tenant, settings

logger = structlog.get_logger(__name__)


class ApiKeyStore:
    """Caches parsed API keys, re-reading the key file as it changes."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: list[KeyEntry] = []
        self._signature: tuple[float, int] | None = None
        self._checked_at: float = 0.0
        self._loaded_path: str = ""

    def entries(self) -> list[KeyEntry]:
        """Current (tenant, principal, key) triples from whichever source is configured."""
        path = settings.api_keys_file
        if not path:
            # No file configured: the env var is static, so there is nothing to
            # cache or invalidate.
            return settings.api_key_entries

        now = time.monotonic()
        # Re-stat at most once per interval. entries() is on the request
        # path, and a stat syscall per request is a cost with no benefit —
        # the file changes on the order of days, not milliseconds.
        if path == self._loaded_path and now - self._checked_at < settings.api_keys_reload_seconds:
            return self._entries

        with self._lock:
            self._checked_at = now
            self._refresh_locked(path)
            return self._entries

    def principals(self) -> list[tuple[str | None, str]]:
        """Current (principal, key) pairs, tenant stripped."""
        return [(e.name, e.key) for e in self.entries()]

    def reload(self) -> None:
        """Force a re-read on the next call, ignoring the interval."""
        with self._lock:
            self._checked_at = 0.0
            self._signature = None

    def _refresh_locked(self, path: str) -> None:
        try:
            stat = os.stat(path)
            signature = (stat.st_mtime, stat.st_size)
        except OSError as exc:
            self._keep_last_good(path, exc)
            return

        # Unchanged since the last successful read — skip parsing.
        if signature == self._signature and path == self._loaded_path:
            return

        try:
            with open(path, encoding="utf-8") as fh:
                raw = fh.read()
        except OSError as exc:
            self._keep_last_good(path, exc)
            return

        entries = parse_key_entries_with_tenant(raw)
        first_load = self._loaded_path != path
        previous = len(self._entries)
        self._entries = entries
        self._signature = signature
        self._loaded_path = path

        if first_load or previous != len(entries):
            logger.info(
                "api_keys.loaded",
                path=path,
                key_count=len(entries),
                # Never the keys themselves; named principals are safe to log.
                principals=sorted(n for _, n, _ in entries if n),
            )

    def _keep_last_good(self, path: str, exc: OSError) -> None:
        """Retain the previous key set — but only for the same file.

        "Last good" is a property of a source, not of the process. If the
        configured path has changed, there is no last-good for the new source
        and the old one is no longer authoritative: continuing to honour keys
        from a file the operator has pointed away from would make repointing
        TRUST_MEDIATOR_API_KEYS_FILE silently fail open.
        """
        if path != self._loaded_path:
            dropped = len(self._entries)
            self._entries = []
            self._signature = None
            self._loaded_path = ""
            logger.error(
                "api_keys.new_source_unreadable",
                path=path,
                error=str(exc),
                dropped_key_count=dropped,
                hint="the key file was repointed to a path that cannot be read",
            )
            return

        logger.error(
            "api_keys.file_unreadable",
            path=path,
            error=str(exc),
            retaining_key_count=len(self._entries),
            hint="revoke by emptying the file, not by deleting it",
        )


#: Process-wide store. Stateless apart from the cache, so sharing is correct.
_store = ApiKeyStore()


def entries() -> list[KeyEntry]:
    """Current (tenant, principal, key) triples, honouring a rotating key file."""
    return _store.entries()


def principals() -> list[tuple[str | None, str]]:
    """Current (principal, key) pairs, honouring a rotating key file."""
    return _store.principals()


def reload_keys() -> None:
    """Drop the cache so the next lookup re-reads the file."""
    _store.reload()
