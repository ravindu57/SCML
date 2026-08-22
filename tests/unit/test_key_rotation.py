"""
NFR-SEC-04 — API keys rotate and revoke without restarting the process.

``TRUST_MEDIATOR_API_KEYS`` is read once when the settings singleton is built.
Rotating or revoking a key therefore meant restarting every worker, which
during an active compromise is exactly when a rolling restart is least
welcome, and on a single instance is an outage.

``TRUST_MEDIATOR_API_KEYS_FILE`` adds a source that can change underneath a
running process. A file is what secret managers actually deliver — Kubernetes
Secret volumes, Vault Agent templates and External Secrets Operator all render
one — so rotation becomes an infrastructure operation rather than a deploy.
"""
from __future__ import annotations

import os

import pytest

from trust_mediator.api.auth import ANONYMOUS, _validate_api_key, principal_for
from trust_mediator.api.key_store import ApiKeyStore, reload_keys
from trust_mediator.config import settings
from fastapi import HTTPException


@pytest.fixture(autouse=True)
def _isolate_store():
    """The process-wide store caches; do not leak a key set between tests."""
    reload_keys()
    yield
    reload_keys()


@pytest.fixture
def key_file(tmp_path, monkeypatch):
    """A key file wired into settings, with a helper to rewrite it."""
    path = tmp_path / "api-keys"
    path.write_text("alice:sk-alice\n")
    monkeypatch.setattr(settings, "api_keys_file", str(path))
    monkeypatch.setattr(settings, "api_keys_reload_seconds", 0.0)
    return path


class TestFileBackedKeys:
    def test_keys_load_from_the_file(self, key_file):
        assert principal_for("sk-alice") == "alice"

    def test_file_wins_over_the_environment_variable(self, key_file, monkeypatch):
        """A secrets manager mounting a file must not be silently merged with,
        or overridden by, a stale env var baked into the image."""
        monkeypatch.setattr(settings, "api_keys_raw", "bob:sk-from-env")
        assert principal_for("sk-alice") == "alice"
        assert principal_for("sk-from-env") is None

    def test_env_var_is_still_used_when_no_file_is_configured(self, monkeypatch):
        monkeypatch.setattr(settings, "api_keys_file", "")
        monkeypatch.setattr(settings, "api_keys_raw", "bob:sk-from-env")
        assert principal_for("sk-from-env") == "bob"

    def test_newlines_and_comments_are_accepted(self, key_file):
        key_file.write_text(
            "# issued 2026-08-22\n"
            "alice:sk-alice\n"
            "\n"
            "ops-bot:sk-bot\n"
            "   # trailing comment line\n"
        )
        reload_keys()
        assert principal_for("sk-alice") == "alice"
        assert principal_for("sk-bot") == "ops-bot"

    def test_comma_separated_still_works_inside_a_file(self, key_file):
        key_file.write_text("alice:sk-alice,ops-bot:sk-bot\n")
        reload_keys()
        assert principal_for("sk-bot") == "ops-bot"


class TestRotation:
    def test_a_new_key_works_without_a_restart(self, key_file):
        assert principal_for("sk-new") is None

        # Overlap window: both valid while clients migrate.
        key_file.write_text("alice:sk-alice\nalice:sk-new\n")
        reload_keys()

        assert principal_for("sk-alice") == "alice"
        assert principal_for("sk-new") == "alice"

    def test_removing_the_old_key_revokes_it(self, key_file):
        key_file.write_text("alice:sk-new\n")
        reload_keys()

        assert principal_for("sk-new") == "alice"
        assert principal_for("sk-alice") is None, "rotated-out key still authenticates"

    def test_emptying_the_file_revokes_everything(self, key_file, monkeypatch):
        """The documented way to revoke all access, as distinct from deleting
        the file (which is indistinguishable from a broken mount)."""
        key_file.write_text("")
        reload_keys()
        assert principal_for("sk-alice") is None

        # And in production that means the API rejects rather than opens up:
        # 403 for a presented-but-unknown key, 401 for no key at all.
        monkeypatch.setattr(settings, "env", "production")
        with pytest.raises(HTTPException) as exc:
            _validate_api_key("sk-alice")
        assert exc.value.status_code == 403
        with pytest.raises(HTTPException) as exc:
            _validate_api_key(None)
        assert exc.value.status_code == 401

    def test_emptying_the_file_revokes_even_in_development(self, key_file, monkeypatch):
        """Configuring a key file states that this deployment authenticates.

        The development pass-through (no keys -> open access) must not apply,
        or emptying the file to revoke access would instead open the API to
        everyone — the opposite of the intent, and the least likely thing an
        operator would think to re-check after a revocation.
        """
        monkeypatch.setattr(settings, "env", "development")
        key_file.write_text("")
        reload_keys()

        with pytest.raises(HTTPException) as exc:
            _validate_api_key(None)
        assert exc.value.status_code == 401, "revoking every key opened the API"

    def test_development_open_access_survives_when_no_file_is_configured(
        self, monkeypatch
    ):
        """The convenience itself is unchanged for the no-key-source case."""
        monkeypatch.setattr(settings, "api_keys_file", "")
        monkeypatch.setattr(settings, "api_keys_raw", "")
        monkeypatch.setattr(settings, "env", "development")
        assert _validate_api_key(None) == ANONYMOUS

    def test_revocation_takes_effect_through_the_auth_dependency(self, key_file):
        assert _validate_api_key("sk-alice") == "alice"
        key_file.write_text("bob:sk-bob\n")
        reload_keys()
        with pytest.raises(HTTPException) as exc:
            _validate_api_key("sk-alice")
        assert exc.value.status_code == 403


class TestFailureHandling:
    def test_an_unreadable_file_keeps_the_last_good_key_set(self, key_file):
        """A transient mount or permission glitch must not become a total
        authentication outage. Secret managers rewrite by atomic rename, so a
        missing file is far more likely to be breakage than intent."""
        assert principal_for("sk-alice") == "alice"

        os.remove(key_file)
        reload_keys()

        assert principal_for("sk-alice") == "alice", (
            "a deleted key file dropped every key — revoke by emptying, not deleting"
        )

    def test_repointing_to_an_unreadable_path_drops_the_old_keys(
        self, key_file, tmp_path, monkeypatch
    ):
        """Last-good belongs to a source, not to the process.

        Found by a test that only failed because the store leaked state
        between cases: retaining keys across a *path change* means repointing
        TRUST_MEDIATOR_API_KEYS_FILE at a bad path silently keeps honouring
        the file the operator just moved away from.
        """
        store = ApiKeyStore()
        assert [n for n, _ in store.principals()] == ["alice"]

        monkeypatch.setattr(settings, "api_keys_file", str(tmp_path / "elsewhere"))
        assert store.principals() == [], "keys from the previous file survived"

    def test_a_missing_file_at_startup_yields_no_keys(self, tmp_path, monkeypatch):
        """No last-good to fall back on, so the result is 'no keys configured'
        — which in production means everything is rejected."""
        monkeypatch.setattr(settings, "api_keys_file", str(tmp_path / "absent"))
        monkeypatch.setattr(settings, "api_keys_reload_seconds", 0.0)
        monkeypatch.setattr(settings, "api_keys_raw", "")
        assert principal_for("anything") is None

    def test_a_broken_mount_does_not_open_the_api_in_development(
        self, tmp_path, monkeypatch
    ):
        """A key file that cannot be read resolves to no keys — but because a
        file was configured, that means "everything is revoked", not "no
        authentication is in use". A misconfigured secret mount must fail
        closed even in development."""
        monkeypatch.setattr(settings, "api_keys_file", str(tmp_path / "absent"))
        monkeypatch.setattr(settings, "api_keys_reload_seconds", 0.0)
        monkeypatch.setattr(settings, "api_keys_raw", "")
        monkeypatch.setattr(settings, "env", "development")
        with pytest.raises(HTTPException) as exc:
            _validate_api_key(None)
        assert exc.value.status_code == 401


class TestReloadInterval:
    def test_the_file_is_not_stat_ed_on_every_request(self, key_file, monkeypatch):
        """principals() is on the request path. A stat syscall per request buys
        nothing when the file changes on the order of days."""
        monkeypatch.setattr(settings, "api_keys_reload_seconds", 3600.0)
        store = ApiKeyStore()

        calls = {"n": 0}
        real_stat = os.stat

        def counting_stat(*args, **kwargs):
            calls["n"] += 1
            return real_stat(*args, **kwargs)

        monkeypatch.setattr(os, "stat", counting_stat)

        for _ in range(50):
            store.principals()

        assert calls["n"] == 1, f"stat called {calls['n']} times for 50 lookups"

    def test_a_zero_interval_re_reads_every_time(self, key_file, monkeypatch):
        monkeypatch.setattr(settings, "api_keys_reload_seconds", 0.0)
        store = ApiKeyStore()
        assert [n for n, _ in store.principals()] == ["alice"]

        key_file.write_text("bob:sk-bob\nops:sk-ops\n")
        assert sorted(n for n, _ in store.principals()) == ["bob", "ops"]
