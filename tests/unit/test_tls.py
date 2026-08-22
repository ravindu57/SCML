"""
NFR-SEC-03 — TLS/mTLS configuration, and the production plaintext guard.

Before this, both listeners were plaintext-only: uvicorn was started with no
ssl_* arguments and the gRPC server hardcoded ``add_insecure_port``, justified
by a comment reading "TLS terminates at the mesh/ingress". That is a real
deployment, but it was the *only* one available, and nothing checked that an
ingress actually existed. A production process would happily serve mediation
decisions — and accept ``X-API-Key`` headers — in the clear.

The guard inverts that default: production without a certificate refuses to
start unless TRUST_MEDIATOR_ALLOW_INSECURE_HTTP says the operator meant it.
The point is not that terminating TLS in front is wrong; it is that the choice
should be recorded somewhere greppable instead of being the silent default.
"""
from __future__ import annotations

import ssl

import httpx
import pytest

from trust_mediator.api.app import _ssl_kwargs, create_app
from trust_mediator.client import SCMLClient
from trust_mediator.config import (
    InsecureTransportError,
    require_secure_transport,
    settings,
)


@pytest.fixture
def certs(tmp_path):
    """Cert/key/CA paths. Contents are never parsed by the code under test."""
    cert = tmp_path / "server.crt"
    key = tmp_path / "server.key"
    ca = tmp_path / "ca.crt"
    for p in (cert, key, ca):
        p.write_bytes(b"-----BEGIN CERTIFICATE-----\nnot-a-real-cert\n")
    return cert, key, ca


@pytest.fixture
def tls_on(monkeypatch, certs):
    cert, key, ca = certs
    monkeypatch.setattr(settings, "tls_cert_file", str(cert))
    monkeypatch.setattr(settings, "tls_key_file", str(key))
    monkeypatch.setattr(settings, "tls_ca_file", str(ca))
    return cert, key, ca


class TestTlsSettings:
    def test_tls_needs_both_halves_of_the_keypair(self, monkeypatch, certs):
        cert, key, _ = certs
        monkeypatch.setattr(settings, "tls_cert_file", str(cert))
        monkeypatch.setattr(settings, "tls_key_file", "")
        assert not settings.tls_enabled, "a cert with no key is not TLS"

        monkeypatch.setattr(settings, "tls_key_file", str(key))
        assert settings.tls_enabled

    def test_mtls_requires_tls_a_ca_and_the_flag(self, monkeypatch, tls_on):
        monkeypatch.setattr(settings, "tls_require_client_cert", False)
        assert not settings.mtls_enabled

        monkeypatch.setattr(settings, "tls_require_client_cert", True)
        assert settings.mtls_enabled

        # Asking for client certs with no CA to verify them against is not mTLS.
        monkeypatch.setattr(settings, "tls_ca_file", "")
        assert not settings.mtls_enabled


class TestProductionPlaintextGuard:
    def test_development_without_tls_is_allowed(self, monkeypatch):
        monkeypatch.setattr(settings, "env", "development")
        monkeypatch.setattr(settings, "tls_cert_file", "")
        monkeypatch.setattr(settings, "tls_key_file", "")
        require_secure_transport("test")  # must not raise

    def test_production_without_tls_refuses_to_start(self, monkeypatch):
        monkeypatch.setattr(settings, "env", "production")
        monkeypatch.setattr(settings, "tls_cert_file", "")
        monkeypatch.setattr(settings, "tls_key_file", "")
        monkeypatch.setattr(settings, "allow_insecure_http", False)
        with pytest.raises(InsecureTransportError, match="production"):
            require_secure_transport("test")

    def test_production_plaintext_is_allowed_when_explicitly_opted_in(self, monkeypatch):
        """The supported "TLS terminates at the ingress" deployment."""
        monkeypatch.setattr(settings, "env", "production")
        monkeypatch.setattr(settings, "tls_cert_file", "")
        monkeypatch.setattr(settings, "tls_key_file", "")
        monkeypatch.setattr(settings, "allow_insecure_http", True)
        require_secure_transport("test")  # must not raise

    def test_production_with_tls_is_allowed(self, monkeypatch, tls_on):
        monkeypatch.setattr(settings, "env", "production")
        monkeypatch.setattr(settings, "allow_insecure_http", False)
        require_secure_transport("test")  # must not raise

    def test_create_app_enforces_the_guard(self, monkeypatch):
        """The guard lives in create_app, not main(), because the Dockerfile
        CMD and the systemd unit both run `uvicorn ...app:app` directly and
        never call main()."""
        monkeypatch.setattr(settings, "env", "production")
        monkeypatch.setattr(settings, "tls_cert_file", "")
        monkeypatch.setattr(settings, "tls_key_file", "")
        monkeypatch.setattr(settings, "allow_insecure_http", False)
        with pytest.raises(InsecureTransportError):
            create_app()


class TestUvicornSslArguments:
    def test_no_tls_configured_passes_no_ssl_arguments(self, monkeypatch):
        monkeypatch.setattr(settings, "tls_cert_file", "")
        monkeypatch.setattr(settings, "tls_key_file", "")
        assert _ssl_kwargs() == {}

    def test_tls_passes_the_keypair(self, monkeypatch, tls_on):
        cert, key, _ = tls_on
        monkeypatch.setattr(settings, "tls_require_client_cert", False)
        kwargs = _ssl_kwargs()
        assert kwargs["ssl_certfile"] == str(cert)
        assert kwargs["ssl_keyfile"] == str(key)
        assert "ssl_cert_reqs" not in kwargs, "client certs must be opt-in"

    def test_mtls_requires_a_verified_client_certificate(self, monkeypatch, tls_on):
        _, _, ca = tls_on
        monkeypatch.setattr(settings, "tls_require_client_cert", True)
        kwargs = _ssl_kwargs()
        assert kwargs["ssl_ca_certs"] == str(ca)
        assert kwargs["ssl_cert_reqs"] == ssl.CERT_REQUIRED


class TestGrpcTransportSecurity:
    @staticmethod
    def _fake_server(monkeypatch):
        grpc = pytest.importorskip("grpc")
        from trust_mediator.api.grpc import server as grpc_server

        record: dict[str, object] = {}

        class _Server:
            def add_generic_rpc_handlers(self, handlers):
                pass

            def add_registered_method_handlers(self, service, handlers):
                pass

            def add_secure_port(self, bind, credentials):
                record["secure"] = (bind, credentials)

            def add_insecure_port(self, bind):
                record["insecure"] = bind

        monkeypatch.setattr(grpc.aio, "server", lambda **kw: _Server())
        monkeypatch.setattr(
            grpc, "ssl_server_credentials", lambda *a, **kw: ("creds", kw)
        )
        return grpc_server, record

    @pytest.mark.asyncio
    async def test_tls_configured_uses_a_secure_port(self, monkeypatch, tls_on):
        monkeypatch.setattr(settings, "env", "development")
        monkeypatch.setattr(settings, "tls_require_client_cert", True)
        grpc_server, record = self._fake_server(monkeypatch)

        await grpc_server.create_grpc_server(pipeline=None)

        assert "secure" in record, "TLS configured but gRPC bound an insecure port"
        assert "insecure" not in record
        _, (_, kwargs) = record["secure"]
        assert kwargs["require_client_auth"] is True

    @pytest.mark.asyncio
    async def test_no_tls_still_binds_insecure_in_development(self, monkeypatch):
        monkeypatch.setattr(settings, "env", "development")
        monkeypatch.setattr(settings, "tls_cert_file", "")
        monkeypatch.setattr(settings, "tls_key_file", "")
        grpc_server, record = self._fake_server(monkeypatch)

        await grpc_server.create_grpc_server(pipeline=None)

        assert "insecure" in record
        assert "secure" not in record

    @pytest.mark.asyncio
    async def test_production_without_tls_refuses_to_bind(self, monkeypatch):
        monkeypatch.setattr(settings, "env", "production")
        monkeypatch.setattr(settings, "tls_cert_file", "")
        monkeypatch.setattr(settings, "tls_key_file", "")
        monkeypatch.setattr(settings, "allow_insecure_http", False)
        grpc_server, _ = self._fake_server(monkeypatch)

        with pytest.raises(InsecureTransportError):
            await grpc_server.create_grpc_server(pipeline=None)


class TestClientTransportSecurity:
    @staticmethod
    def _capture_client_kwargs(monkeypatch) -> dict:
        """Replace httpx.Client wholesale.

        Spying on the real __init__ is not an option: httpx builds the SSL
        context eagerly, so a CA path that does not exist on this machine
        raises before anything is recorded.
        """
        seen: dict = {}

        class _FakeClient:
            def __init__(self, **kwargs):
                seen.update(kwargs)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def request(self, *args, **kwargs):
                return _Ok()

        monkeypatch.setattr(httpx, "Client", _FakeClient)
        return seen

    def test_custom_ca_and_client_cert_reach_httpx(self, monkeypatch):
        """mTLS is why the sync path builds an httpx.Client: the module-level
        httpx.request() has no `cert` parameter.

        Uses certifi's bundle because building the context is real work — a CA
        path is parsed at construction, so an unparseable one raises here
        rather than on the first request.
        """
        import certifi

        seen = self._capture_client_kwargs(monkeypatch)
        client = SCMLClient(
            "https://mediator.internal",
            api_key="sk-test",
            verify=certifi.where(),
            client_cert=("/etc/ssl/client.crt", "/etc/ssl/client.key"),
        )
        client.request("GET", "/health")

        # A CA *path* is converted to a context — httpx 0.28 deprecates verify=<str>.
        assert isinstance(seen["verify"], ssl.SSLContext)
        assert seen["cert"] == ("/etc/ssl/client.crt", "/etc/ssl/client.key")

    def test_verification_is_on_by_default(self, monkeypatch):
        seen = self._capture_client_kwargs(monkeypatch)
        SCMLClient("https://mediator.internal").request("GET", "/health")
        assert seen["verify"] is True

    def test_plaintext_to_a_remote_host_warns(self):
        with pytest.warns(UserWarning, match="plaintext"):
            SCMLClient("http://mediator.internal:8000", api_key="sk-test")

    def test_plaintext_to_localhost_is_silent(self, recwarn):
        SCMLClient("http://localhost:8000", api_key="sk-test")
        SCMLClient("http://127.0.0.1:8000")
        assert [w for w in recwarn if "plaintext" in str(w.message)] == []

    def test_https_is_silent(self, recwarn):
        SCMLClient("https://mediator.internal", api_key="sk-test")
        assert [w for w in recwarn if "plaintext" in str(w.message)] == []


class _Ok:
    status_code = 200
    text = "{}"

    def raise_for_status(self) -> None:
        pass

    def json(self) -> dict:
        return {"decision": "allow"}
