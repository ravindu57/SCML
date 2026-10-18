#!/usr/bin/env bash
# Post-deploy smoke test (docs/DEPLOY_VPS.md). Read-only except one audited
# mediation call; never writes policy.
#
#   SCML_URL=https://scml.example.com SCML_API_KEY=sk-... ./scripts/smoke.sh
#
# Exits non-zero on the first check that fails.
set -euo pipefail
URL="${SCML_URL:?set SCML_URL}"
KEY="${SCML_API_KEY:?set SCML_API_KEY (a data-plane key)}"
fail() { echo "FAIL: $*" >&2; exit 1; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

[[ "$(code "$URL/health")" == 200 ]] || fail "/health is not 200"
echo "ok   /health"

[[ "$(code -X POST "$URL/v1/mediate/output" -H 'Content-Type: application/json' -d '{"content":"x"}')" == 401 ]] \
  || fail "a /v1 call without a key is not refused with 401"
echo "ok   no key -> 401"

[[ "$(code -X POST "$URL/v1/mediate/tool-call" -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
      -d '{"session_id":"smoke","agent_id":"smoke-test","tool_name":"nothing"}')" == 200 ]] \
  || fail "a data-plane key cannot mediate"
echo "ok   data key mediates (unknown agent -> deny-all, by design)"

[[ "$(code -X PUT "$URL/v1/policy" -H "X-API-Key: $KEY" -H 'Content-Type: application/json' -d '{"policy_data":{}}')" == 403 ]] \
  || fail "a data-plane key reached a control-plane write"
echo "ok   data key cannot write policy -> 403"

m="$(code "$URL/metrics")"
[[ "$m" == 404 || "$m" == 401 || "$m" == 403 ]] || fail "/metrics is publicly readable ($m)"
echo "ok   /metrics not public ($m)"

if [[ "$URL" == https://* ]]; then
  curl -sI "$URL/health" | grep -qi '^strict-transport-security' || fail "no HSTS header over HTTPS"
  echo "ok   HSTS"
fi
echo "smoke test passed"
