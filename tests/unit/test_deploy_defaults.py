"""
Deploy defaults (backlog #9; security review §8, Sec #13, #14, #16, E6).

Each test pins a default that used to be unsafe:

- the HTTP rate limiter limited nothing: slowapi could not see routes inside
  included routers, so every /v1 route was exempt
- `env` defaulted to development, where no keys means an open API
- a policy DB error fell back to the gateway YAML, re-granting tools the DB
  had revoked
- /metrics was public and labelled by raw path (ids, unbounded series)
- the escalation webhook put attacker text into Slack mrkdwn unescaped
- docker-compose shipped `tmpassword` and published Postgres and Redis
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient

from trust_mediator.api.app import create_app
from trust_mediator.config import Settings, settings

ROOT = Path(__file__).resolve().parents[2]


# ── Rate limiting ─────────────────────────────────────────────────────────────


def test_the_rate_limiter_can_see_every_v1_route():
    """slowapi's flat lookup found none of them, and 'not found' means exempt."""
    from starlette.routing import Match  # noqa: F401  (documents the matcher used)

    from tests.unit.test_api_auth import _guarded_routes
    from trust_mediator.api.rate_limit import find_route_handler

    routes = create_app().routes
    for route in _guarded_routes():
        path = route.path.replace("{", "").replace("}", "")
        method = sorted(route.methods)[0]
        scope = {"type": "http", "path": path, "method": method, "root_path": ""}
        assert find_route_handler(routes, scope) is route.endpoint, f"{method} {route.path}"


def test_slowapis_own_lookup_misses_them_which_is_why_this_exists():
    from slowapi.middleware import _find_route_handler

    scope = {"type": "http", "path": "/v1/mediate/output", "method": "POST", "root_path": ""}
    if _find_route_handler(create_app().routes, scope) is not None:  # pragma: no cover
        pytest.skip("slowapi now resolves nested routes; the custom middleware may be dropped")


@pytest.mark.asyncio
async def test_requests_beyond_the_limit_are_refused(monkeypatch):
    from limits import parse

    from trust_mediator.api import rate_limit

    monkeypatch.setattr(settings, "api_keys_raw", "sk-rl")
    limiter = rate_limit.limiter
    original = list(limiter._default_limits)
    from slowapi.wrappers import LimitGroup

    limiter._default_limits = [LimitGroup("3/minute", rate_limit._key_func, None, False, None, None, None, 1, False)]
    limiter._storage.reset()
    try:
        async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
            codes = [
                (await c.post("/v1/mediate/output", json={"content": "x"}, headers={"X-API-Key": "sk-rl"})).status_code
                for _ in range(5)
            ]
    finally:
        limiter._default_limits = original
        limiter._storage.reset()
    assert codes[:3] == [200, 200, 200] and 429 in codes[3:], codes
    assert parse("3/minute")  # the limits package parses what we configured


# ── Environment default ───────────────────────────────────────────────────────


def test_environment_defaults_to_production(monkeypatch):
    monkeypatch.delenv("TRUST_MEDIATOR_ENV", raising=False)
    assert Settings(_env_file=None).env == "production"


# ── Policy loader on DB error ─────────────────────────────────────────────────


class _Repo:
    def __init__(self):
        self.doc = None
        self.fail = False

    async def get_active_policy(self, tenant_id="default"):
        if self.fail:
            raise RuntimeError("db down")
        return self.doc


@pytest.mark.asyncio
class TestLoaderNeverFallsBackToYamlOnError:
    async def _loader(self):
        from trust_mediator.modules.tool_policy.policy_loader import PolicyLoader

        repo = _Repo()
        return PolicyLoader(policy_repo=repo, default_path=ROOT / "policies/default_policy.yaml"), repo

    async def test_db_error_serves_the_last_document_the_db_returned(self):
        loader, repo = await self._loader()
        repo.doc = {"agents": {"default": {"allowed_tools": []}}, "marker": "from-db"}
        await loader.get_policy()
        loader._cache_loaded_at.clear()  # TTL expired
        repo.fail = True
        assert (await loader.get_policy())["marker"] == "from-db"

    async def test_db_error_with_no_prior_read_is_deny_all_not_yaml(self):
        loader, repo = await self._loader()
        repo.fail = True
        policy = await loader.get_policy()
        assert "web_search_agent" not in policy["agents"]  # a YAML-only agent
        assert policy["agents"]["default"]["allowed_tools"] == []

    async def test_last_good_is_bounded_in_age(self):
        loader, repo = await self._loader()
        repo.doc = {"agents": {"default": {"allowed_tools": ["x"]}}, "marker": "old"}
        await loader.get_policy()
        stored_at, doc = loader._last_good["default"]
        loader._last_good["default"] = (stored_at - loader._LAST_GOOD_MAX_AGE - 1, doc)
        loader._cache_loaded_at.clear()
        repo.fail = True
        assert "marker" not in await loader.get_policy()  # too old: deny-all

    async def test_errors_back_off_instead_of_hitting_the_db_every_call(self):
        loader, repo = await self._loader()
        calls = 0

        async def failing(tenant_id="default"):
            nonlocal calls
            calls += 1
            raise RuntimeError("db down")

        repo.get_active_policy = failing
        for _ in range(5):
            await loader.get_policy()
        assert calls == 1

    async def test_an_empty_db_still_bootstraps_from_yaml(self):
        loader, _ = await self._loader()
        assert "web_search_agent" in (await loader.get_policy())["agents"]


# ── /metrics ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
class TestMetrics:
    async def _get(self, monkeypatch, headers=None, **cfg):
        for k, v in cfg.items():
            monkeypatch.setattr(settings, k, v)
        async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
            return await c.get("/metrics", headers=headers or {})

    async def test_production_without_a_token_refuses(self, monkeypatch):
        r = await self._get(monkeypatch, env="production", metrics_token="", metrics_public=False)
        assert r.status_code == 403

    async def test_a_token_is_required_when_configured(self, monkeypatch):
        assert (await self._get(monkeypatch, env="production", metrics_token="t0k")).status_code == 401
        ok = await self._get(monkeypatch, {"Authorization": "Bearer t0k"}, env="production", metrics_token="t0k")
        assert ok.status_code == 200

    async def test_explicit_public_opt_out(self, monkeypatch):
        r = await self._get(monkeypatch, env="production", metrics_token="", metrics_public=True)
        assert r.status_code == 200

    async def test_labels_are_route_templates_not_raw_paths(self, monkeypatch):
        from trust_mediator.db.base import Base, engine

        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        monkeypatch.setattr(settings, "env", "development")
        monkeypatch.setattr(settings, "api_keys_raw", "")
        async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
            await c.get("/v1/audit/replay/secret-session-xyz")
            body = (await c.get("/metrics")).text
        assert "secret-session-xyz" not in body
        assert "/v1/audit/replay/{session_id}" in body


# ── Escalation webhook ────────────────────────────────────────────────────────


class TestSlackEscape:
    def test_control_sequences_are_inert(self):
        from trust_mediator.modules.escalation.webhook import slack_escape

        out = slack_escape("<!channel> approve at <https://evil|here> & now")
        assert "<" not in out and ">" not in out
        assert "&lt;!channel&gt;" in out and "&amp;" in out

    def test_content_cannot_forge_a_new_field_line(self):
        from trust_mediator.modules.escalation.webhook import slack_escape

        assert "\n" not in slack_escape("fine\n>*Score:* `0.0`")
        assert "`" not in slack_escape("x`y")


# ── docker-compose ────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def compose():
    return yaml.safe_load((ROOT / "docker-compose.yml").read_text())


class TestCompose:

    def test_no_default_credentials(self):
        text = (ROOT / "docker-compose.yml").read_text()
        assert "tmpassword" not in text and "change-me" not in text
        assert "${POSTGRES_PASSWORD:?" in text and "${REDIS_PASSWORD:?" in text

    def test_datastores_are_not_published(self, compose):
        assert "ports" not in compose["services"]["postgres"]
        assert "ports" not in compose["services"]["redis"]

    def test_redis_requires_a_password(self, compose):
        assert "--requirepass" in compose["services"]["redis"]["command"]


def test_every_guarded_route_is_still_an_apiroute():
    """Guard for the route walk above: it must keep finding real routes."""
    from tests.unit.test_api_auth import _guarded_routes

    assert all(isinstance(r, APIRoute) for r in _guarded_routes())


@pytest.mark.asyncio
async def test_health_is_exempt_from_the_rate_limit():
    from trust_mediator.api.rate_limit import limiter

    assert "trust_mediator.api.app.health" in limiter._exempt_routes


def test_deploy_script_writes_no_default_credentials():
    text = (ROOT / "deploy.sh").read_text()
    assert "tmpassword" not in text
    assert "POSTGRES_PASSWORD REDIS_PASSWORD" in text and "token_urlsafe" in text
