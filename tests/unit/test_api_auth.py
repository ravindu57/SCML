"""
NFR-SEC-02 / FR-MI-05 — every mediation and administration endpoint requires
an API key.

Three FR-MI-05 quarantine-review routes shipped unauthenticated:

    GET    /v1/mediate/memory/quarantined
    POST   /v1/mediate/memory/quarantined/{id}/release
    DELETE /v1/mediate/memory/quarantined/{id}

``/write`` and ``/read`` on the same router both took ``AuthDep``, so this was
not a deliberate exemption. It was a signature accident: those three declared
``pipeline: PipelineDep = None`` with a default, and a non-defaulted
``_: AuthDep`` cannot follow a defaulted parameter, so auth was dropped rather
than the parameters reordered.

The release route is the highest-privilege call in the API — it takes content
the memory integrity layer quarantined and promotes it to ACTIVE. Unauthenticated,
an attacker whose poison was caught could re-admit it, and pass ``reviewer`` as a
query parameter to name whoever they liked as the human who approved it. The
hash chain would then faithfully attest to a review that never happened, which
is worse than no audit record: FR-AL-01 exists so the log can be trusted.

The structural test is the one that matters. Enumerating the three known routes
only re-checks a bug already fixed; asserting that *every* ``/v1`` route resolves
``_validate_api_key`` catches the next route added with a defaulted dependency.
"""
from __future__ import annotations

import pytest
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient

from trust_mediator.api.app import create_app
from trust_mediator.api.auth import _validate_api_key, key_fingerprint, principal_for
from trust_mediator.api.dependencies import get_pipeline
from trust_mediator.api.rate_limit import _key_func
from trust_mediator.config import settings

TEST_KEY = "test-key-for-auth-suite"

# Unauthenticated by design: liveness probes and Prometheus scraping both run
# before, or outside, any credential the mediator holds.
PUBLIC_PATHS = {"/health", "/metrics", "/docs", "/redoc", "/openapi.json"}


def _resolves_auth(dependant) -> bool:
    """True if _validate_api_key appears anywhere in this route's dependency graph."""
    if dependant.call is _validate_api_key:
        return True
    return any(_resolves_auth(sub) for sub in dependant.dependencies)


def _iter_api_routes(routes):
    """Walk the route tree, flattening included routers.

    ``include_router`` does not copy its routes into ``app.routes`` on every
    FastAPI version. On 0.139 it appends one ``fastapi.routing._IncludedRouter``
    per call, which holds the real routes on ``.original_router`` and exposes no
    ``.routes`` of its own. A flat ``isinstance(r, APIRoute)`` scan therefore
    finds only ``/health`` and ``/metrics``, and every assertion below passes
    vacuously — which is what ``test_at_least_one_route_was_discovered`` exists
    to catch. Handles both layouts.
    """
    for r in routes:
        if isinstance(r, APIRoute):
            yield r
            continue
        nested = getattr(r, "routes", None)
        if nested is None:
            nested = getattr(getattr(r, "original_router", None), "routes", None)
        for sub in nested or ():
            yield from _iter_api_routes([sub])


def _guarded_routes() -> list[APIRoute]:
    return [
        r
        for r in _iter_api_routes(create_app().routes)
        if r.path.startswith("/v1") and r.path not in PUBLIC_PATHS
    ]


@pytest.fixture
def keyed(monkeypatch):
    """Configure a key so auth enforces regardless of TRUST_MEDIATOR_ENV.

    ``api_keys`` is a computed property; ``api_keys_raw`` is the settable field
    behind it. With a key configured, _validate_api_key never takes the
    development-mode pass-through branch.
    """
    monkeypatch.setattr(settings, "api_keys_raw", TEST_KEY)
    return TEST_KEY


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


class _StubMemory:
    """No such record — enough to prove the handler ran, without a database."""

    async def review_and_release(self, memory_id: str, reviewer: str = "") -> bool:
        return False


class _StubPipeline:
    _memory = _StubMemory()


class TestEveryV1RouteResolvesAuth:
    """The regression guard: a new /v1 route cannot ship without a key check."""

    def test_at_least_one_route_was_discovered(self):
        # Guards against the assertion below passing vacuously if route
        # discovery or the /v1 prefix convention ever changes.
        assert len(_guarded_routes()) >= 8

    def test_all_v1_routes_require_a_key(self):
        unguarded = [
            f"{sorted(r.methods)} {r.path}"
            for r in _guarded_routes()
            if not _resolves_auth(r.dependant)
        ]
        assert not unguarded, (
            "these /v1 routes do not resolve _validate_api_key: "
            + ", ".join(unguarded)
        )


@pytest.mark.asyncio
class TestQuarantineRoutesRejectAnonymousCallers:
    """FR-MI-05 — the specific routes that shipped open."""

    @pytest.mark.parametrize(
        "method,path",
        [
            ("GET", "/v1/mediate/memory/quarantined"),
            ("POST", "/v1/mediate/memory/quarantined/mem-123/release"),
            ("DELETE", "/v1/mediate/memory/quarantined/mem-123"),
        ],
    )
    async def test_no_key_is_rejected(self, client, keyed, method, path):
        r = await client.request(method, path)
        assert r.status_code == 401, (
            f"{method} {path} returned {r.status_code}, not 401 — it is reachable "
            f"without a key"
        )

    async def test_wrong_key_is_rejected(self, client, keyed):
        r = await client.post(
            "/v1/mediate/memory/quarantined/mem-123/release",
            headers={"X-API-Key": "not-the-key"},
        )
        assert r.status_code == 403

    async def test_release_cannot_be_used_to_forge_a_reviewer(self, client, keyed):
        """The `reviewer` query parameter is attacker-chosen, so the route that
        writes it into the audit chain must be authenticated first."""
        r = await client.post(
            "/v1/mediate/memory/quarantined/mem-123/release",
            params={"reviewer": "security-team-lead"},
        )
        assert r.status_code == 401

    async def test_release_records_the_authenticated_principal_as_reviewer(
        self, app, client, monkeypatch
    ):
        """FR-MI-05/FR-AL-01 — the reviewer in the audit chain is whoever's key
        was used, not whoever the caller claimed to be."""
        monkeypatch.setattr(settings, "api_keys_raw", "alice:sk-alice-key")
        seen: dict[str, str] = {}

        class _Capturing(_StubMemory):
            async def review_and_release(self, memory_id, reviewer=""):
                seen["reviewer"] = reviewer
                return True

        class _P:
            _memory = _Capturing()

        app.dependency_overrides[get_pipeline] = _P
        try:
            r = await client.post(
                "/v1/mediate/memory/quarantined/mem-1/release",
                params={"reviewer": "security-team-lead"},  # ignored
                headers={"X-API-Key": "sk-alice-key"},
            )
        finally:
            app.dependency_overrides.clear()

        assert r.status_code == 200, r.text
        assert seen["reviewer"] == "alice"
        assert "security-team-lead" not in seen["reviewer"]

    async def test_valid_key_reaches_the_handler(self, app, client, keyed):
        """A correct key must get past auth, or the fix has locked out the
        legitimate reviewer too. The pipeline is stubbed so this asserts on
        auth alone and not on database fixture state."""
        app.dependency_overrides[get_pipeline] = _StubPipeline
        try:
            r = await client.post(
                "/v1/mediate/memory/quarantined/mem-123/release",
                headers={"X-API-Key": keyed},
            )
        finally:
            app.dependency_overrides.clear()
        assert r.status_code == 404, r.text  # handler ran, record absent


class TestPrincipalResolution:
    """TRUST_MEDIATOR_API_KEYS parsing and key→principal mapping."""

    def test_named_key_resolves_to_its_name(self, monkeypatch):
        monkeypatch.setattr(settings, "api_keys_raw", "alice:sk-a,ops-bot:sk-b")
        assert principal_for("sk-a") == "alice"
        assert principal_for("sk-b") == "ops-bot"

    def test_bare_key_resolves_to_a_fingerprint_not_the_key(self, monkeypatch):
        monkeypatch.setattr(settings, "api_keys_raw", "sk-secret-value")
        principal = principal_for("sk-secret-value")
        assert principal is not None
        assert principal.startswith("key-")
        assert "sk-secret-value" not in principal

    def test_unknown_key_resolves_to_none(self, monkeypatch):
        monkeypatch.setattr(settings, "api_keys_raw", "alice:sk-a")
        assert principal_for("sk-wrong") is None

    def test_bare_key_containing_a_colon_is_not_split(self, monkeypatch):
        """A key whose text before the colon is not identifier-shaped stays
        whole, so existing deployments keep authenticating."""
        monkeypatch.setattr(settings, "api_keys_raw", "sk-abc/def:ghi")
        assert settings.api_keys == ["sk-abc/def:ghi"]
        assert principal_for("sk-abc/def:ghi") is not None

    def test_api_keys_strips_the_principal_prefix(self, monkeypatch):
        monkeypatch.setattr(settings, "api_keys_raw", " alice:sk-a , sk-b ,, ")
        assert settings.api_keys == ["sk-a", "sk-b"]

    def test_fingerprint_is_stable_and_does_not_disclose_the_key(self):
        assert key_fingerprint("sk-x") == key_fingerprint("sk-x")
        assert key_fingerprint("sk-x") != key_fingerprint("sk-y")
        assert "sk-x" not in key_fingerprint("sk-x")


class TestCredentialsNeverLeakIntoBucketNames:
    """The rate-limit bucket lands in the Redis keyspace when REDIS_URL is set."""

    class _Req:
        def __init__(self, headers):
            self.headers = headers

    def test_bucket_carries_the_principal_not_the_key(self, monkeypatch):
        monkeypatch.setattr(settings, "api_keys_raw", "alice:sk-super-secret")
        bucket = _key_func(self._Req({"X-API-Key": "sk-super-secret"}))
        assert bucket == "principal:alice"
        assert "sk-super-secret" not in bucket

    def test_unnamed_key_bucket_uses_the_fingerprint(self, monkeypatch):
        monkeypatch.setattr(settings, "api_keys_raw", "sk-super-secret")
        bucket = _key_func(self._Req({"X-API-Key": "sk-super-secret"}))
        assert "sk-super-secret" not in bucket
        assert bucket.startswith("principal:key-")


class TestGrpcAuthMatchesRest:
    """FR-IG-02 — both transports must gate on the same condition."""

    @staticmethod
    def _interceptor():
        pytest.importorskip("grpc")
        from trust_mediator.api.grpc.server import _ApiKeyInterceptor

        return _ApiKeyInterceptor()

    class _Details:
        invocation_metadata = ()

    @pytest.mark.asyncio
    async def test_production_without_keys_is_not_open(self, monkeypatch):
        """`if not keys: allow` let gRPC serve anyone in production whenever
        TRUST_MEDIATOR_API_KEYS was unset, while REST returned 401."""
        interceptor = self._interceptor()
        monkeypatch.setattr(settings, "api_keys_raw", "")
        monkeypatch.setattr(settings, "env", "production")

        async def _continuation(details):
            return "REACHED_SERVICE"

        result = await interceptor.intercept_service(_continuation, self._Details())
        assert result != "REACHED_SERVICE", (
            "gRPC served an unauthenticated call in production with no keys set"
        )

    @pytest.mark.asyncio
    async def test_development_without_keys_stays_open(self, monkeypatch):
        interceptor = self._interceptor()
        monkeypatch.setattr(settings, "api_keys_raw", "")
        monkeypatch.setattr(settings, "env", "development")

        async def _continuation(details):
            return "REACHED_SERVICE"

        assert await interceptor.intercept_service(_continuation, self._Details()) == (
            "REACHED_SERVICE"
        )
