"""
NFR-SEC-04 — any setting can be read from ``<VAR>_FILE`` instead of the
environment.

A secret in an environment variable is visible in ``/proc/<pid>/environ``, in
``docker inspect``, in the pod spec, and in any crash dump that captures the
environment. Every secret manager already targets a file — Docker Compose
secrets, Kubernetes Secret volumes, Vault Agent, External Secrets Operator —
and the ``_FILE`` suffix is the convention the official Postgres, MySQL and
Redis images use, so it needs no explanation to an operator.

This is startup-only. Pooled database and Redis connections are built from
these values, so a file changing on disk has no effect until restart. API keys
are the exception and have their own live-reloading source; see
test_key_rotation.py.
"""
from __future__ import annotations

import pytest

from trust_mediator.config import SecretFileError, Settings


@pytest.fixture
def secret(tmp_path):
    """Write a secret file and return its path."""

    def _write(name: str, content: str):
        p = tmp_path / name
        p.write_text(content)
        return str(p)

    return _write


class TestFileOverridesEnvironment:
    def test_aliased_setting_is_read_from_its_file(self, secret, monkeypatch):
        """DATABASE_URL carries an explicit alias. An aliased field is only
        populated by that alias, so a source keying values by field name reads
        the file and silently changes nothing."""
        monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://from-env/x")
        monkeypatch.setenv(
            "DATABASE_URL_FILE", secret("db", "postgresql+asyncpg://from-file/x")
        )
        assert Settings().database_url == "postgresql+asyncpg://from-file/x"

    def test_prefixed_setting_is_read_from_its_file(self, secret, monkeypatch):
        """secret_key has no alias, so the variable is env_prefix + name."""
        monkeypatch.setenv("TRUST_MEDIATOR_SECRET_KEY", "from-env")
        monkeypatch.setenv("TRUST_MEDIATOR_SECRET_KEY_FILE", secret("sk", "from-file"))
        assert Settings().secret_key == "from-file"

    def test_environment_is_used_when_no_file_is_configured(self, monkeypatch):
        monkeypatch.delenv("TRUST_MEDIATOR_SECRET_KEY_FILE", raising=False)
        monkeypatch.setenv("TRUST_MEDIATOR_SECRET_KEY", "from-env")
        assert Settings().secret_key == "from-env"


class TestFileContentHandling:
    def test_a_trailing_newline_is_stripped(self, secret, monkeypatch):
        """`echo secret > file` appends one, and it is never part of the value."""
        monkeypatch.setenv("TRUST_MEDIATOR_SECRET_KEY_FILE", secret("sk", "abc123\n"))
        assert Settings().secret_key == "abc123"

    def test_internal_whitespace_is_preserved(self, secret, monkeypatch):
        """A passphrase may legitimately contain spaces, so only trailing
        newlines are removed — not all surrounding whitespace."""
        monkeypatch.setenv(
            "TRUST_MEDIATOR_SECRET_KEY_FILE", secret("sk", "correct horse battery\n")
        )
        assert Settings().secret_key == "correct horse battery"


class TestFailureIsLoud:
    def test_an_unreadable_secret_file_refuses_to_start(self, tmp_path, monkeypatch):
        """Unlike the API key file, this is read once at startup: there is no
        last-good value and no request in flight, so booting with a default
        password is strictly worse than not booting."""
        monkeypatch.setenv("TRUST_MEDIATOR_SECRET_KEY_FILE", str(tmp_path / "absent"))
        with pytest.raises(SecretFileError, match="could not be read"):
            Settings()

    def test_the_error_names_the_variable_and_the_path(self, tmp_path, monkeypatch):
        missing = str(tmp_path / "absent")
        monkeypatch.setenv("TRUST_MEDIATOR_SECRET_KEY_FILE", missing)
        with pytest.raises(SecretFileError) as exc:
            Settings()
        assert "TRUST_MEDIATOR_SECRET_KEY_FILE" in str(exc.value)
        assert missing in str(exc.value)


class TestApiKeysAreExcluded:
    def test_api_keys_file_does_not_feed_the_static_env_field(
        self, secret, monkeypatch
    ):
        """api_keys_raw is aliased TRUST_MEDIATOR_API_KEYS, so the generic rule
        would claim TRUST_MEDIATOR_API_KEYS_FILE — which is already a separate
        field with live-reload semantics. Two mechanisms reading one path, one
        of them a startup snapshot, is how a rotation half-applies.
        """
        path = secret("keys", "alice:sk-from-file\n")
        monkeypatch.setenv("TRUST_MEDIATOR_API_KEYS_FILE", path)
        monkeypatch.setenv("TRUST_MEDIATOR_API_KEYS", "bob:sk-from-env")

        s = Settings()
        assert s.api_keys_raw == "bob:sk-from-env", (
            "the generic _FILE source captured the rotating key file"
        )
        assert s.api_keys_file == path, "the dedicated live-reload field lost its path"
