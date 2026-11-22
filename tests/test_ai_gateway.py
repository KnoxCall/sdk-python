"""AI Gateway resource — control-plane CRUD, token mint/revoke, usage.

All mocks return the REAL server envelope: single objects as
``{data, meta:{request_id}}``; paginated lists as
``{data:[...], meta:{total, page, per_page, total_pages, request_id}}``; the
mint endpoint as ``{data:{...token...}, meta:{note}}``. Never a bare array,
never a cursor field.
"""

from __future__ import annotations
import json

import httpx
import pytest

from knoxcall import KnoxCall, KnoxCallAsync
from knoxcall.auth.bootstrap import AccessToken

_BOOTSTRAP = AccessToken(access_token="kc_live_x")


def _meta(**extra) -> dict:
    return {"request_id": "req_00000000-0000-0000-0000-000000000000", **extra}


def _success(data, **meta_extra) -> httpx.Response:
    return httpx.Response(200, json={"data": data, "meta": _meta(**meta_extra)})


def _page(items: list, *, total: int, page: int, per_page: int) -> httpx.Response:
    total_pages = max(1, -(-total // per_page)) if total else 0
    return httpx.Response(200, json={
        "data": items,
        "meta": _meta(total=total, page=page, per_page=per_page, total_pages=total_pages),
    })


def _async_client(handler, **extra) -> KnoxCallAsync:
    return KnoxCallAsync(
        tenant="acme",
        base_url="https://api.example.test",
        bootstrap=_BOOTSTRAP,
        http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        **extra,
    )


def _sync_client(handler, **extra):
    return KnoxCall(
        tenant="acme",
        base_url="https://api.example.test",
        bootstrap=_BOOTSTRAP,
        http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        **extra,
    )


# ── Gateways ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_gateways_returns_typed_page_envelope():
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.method == "GET"
        assert req.url.path == "/v1/ai-gateway/gateways"
        params = dict(req.url.params)
        assert "cursor" not in params and "limit" not in params  # no cursor pagination
        assert params == {"page": "2", "per_page": "2"}
        return _page(
            [{"id": "gw_3", "slug": "prod"}, {"id": "gw_4", "slug": "eu"}],
            total=5, page=2, per_page=2,
        )

    async with _async_client(handler) as client:
        result = await client.ai_gateway.list_gateways(page=2, per_page=2)

    assert [g["id"] for g in result["data"]] == ["gw_3", "gw_4"]
    assert result["meta"] == {
        "total": 5, "page": 2, "per_page": 2, "total_pages": 3,
        "request_id": "req_00000000-0000-0000-0000-000000000000",
    }


@pytest.mark.asyncio
async def test_iterate_gateways_walks_all_pages():
    gws = [{"id": f"gw_{i}", "slug": f"g-{i}"} for i in range(1, 6)]
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/v1/ai-gateway/gateways"
        params = dict(req.url.params)
        seen.append(params.get("page"))
        page = int(params.get("page", 1))
        per_page = int(params.get("per_page", 20))
        return _page(gws[(page - 1) * per_page: page * per_page], total=len(gws), page=page, per_page=per_page)

    async with _async_client(handler) as client:
        ids = [g["id"] async for g in client.ai_gateway.iterate_gateways(per_page=2)]

    assert ids == [f"gw_{i}" for i in range(1, 6)]
    assert seen == ["1", "2", "3"]  # stopped at total_pages


@pytest.mark.asyncio
async def test_gateway_create_get_update_delete():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.method, req.url.path))
        if req.method == "POST" and req.url.path == "/v1/ai-gateway/gateways":
            assert json.loads(req.content) == {
                "name": "Prod", "slug": "prod", "budget_daily_usd": 25.0,
            }
            assert req.headers.get("x-idempotency-key")  # mutating → idempotency key
            return _success({"id": "gw_1", "name": "Prod", "slug": "prod", "status": "active"})
        if req.method == "GET" and req.url.path == "/v1/ai-gateway/gateways/gw_1":
            return _success({"id": "gw_1", "name": "Prod", "slug": "prod", "status": "active"})
        if req.method == "PATCH" and req.url.path == "/v1/ai-gateway/gateways/gw_1":
            assert json.loads(req.content) == {"name": "Prod EU"}
            return _success({"id": "gw_1", "name": "Prod EU", "slug": "prod", "status": "active"})
        if req.method == "DELETE" and req.url.path == "/v1/ai-gateway/gateways/gw_1":
            return _success({"id": "gw_1", "status": "archived"})
        return httpx.Response(404)

    async with _async_client(handler) as client:
        created = await client.ai_gateway.create_gateway(name="Prod", slug="prod", budget_daily_usd=25.0)
        assert created["id"] == "gw_1" and "meta" not in created
        got = await client.ai_gateway.get_gateway("gw_1")
        assert got["slug"] == "prod"
        updated = await client.ai_gateway.update_gateway("gw_1", name="Prod EU")
        assert updated["name"] == "Prod EU"
        archived = await client.ai_gateway.delete_gateway("gw_1")
        assert archived == {"id": "gw_1", "status": "archived"}

    assert ("POST", "/v1/ai-gateway/gateways") in calls
    assert ("GET", "/v1/ai-gateway/gateways/gw_1") in calls
    assert ("PATCH", "/v1/ai-gateway/gateways/gw_1") in calls
    assert ("DELETE", "/v1/ai-gateway/gateways/gw_1") in calls


# ── Agents ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_agent_list_create_get_update_delete():
    calls = []
    # AIGW-161. The server computes this from the tenant + the agent's slug on
    # every agent projection, so every mock below carries it.
    agent_url = "https://acme.knoxcall.com/v1/ai/summarizer"

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.method, req.url.path))
        if req.method == "GET" and req.url.path == "/v1/ai-gateway/gateways/gw_1/agents":
            return _page(
                [{"id": "ag_1", "slug": "summarizer", "agent_url": agent_url}],
                total=1, page=1, per_page=20,
            )
        if req.method == "POST" and req.url.path == "/v1/ai-gateway/gateways/gw_1/agents":
            assert json.loads(req.content) == {
                "name": "Summarizer", "slug": "summarizer",
                "default_model": "claude-sonnet-5", "model_allowlist": ["claude-sonnet-5"],
                "streaming_enabled": True,
            }
            return _success({
                "id": "ag_1", "gateway_id": "gw_1", "slug": "summarizer",
                "agent_url": agent_url,
            })
        if req.method == "GET" and req.url.path == "/v1/ai-gateway/agents/ag_1":
            return _success({
                "id": "ag_1", "gateway_id": "gw_1", "slug": "summarizer",
                "agent_url": agent_url,
            })
        if req.method == "PATCH" and req.url.path == "/v1/ai-gateway/agents/ag_1":
            assert json.loads(req.content) == {"default_model": "claude-opus-4-8"}
            return _success({
                "id": "ag_1", "default_model": "claude-opus-4-8", "agent_url": agent_url,
            })
        if req.method == "DELETE" and req.url.path == "/v1/ai-gateway/agents/ag_1":
            return _success({"id": "ag_1", "status": "archived"})
        return httpx.Response(404)

    async with _async_client(handler) as client:
        listed = await client.ai_gateway.list_agents("gw_1")
        assert listed["data"][0]["id"] == "ag_1"
        assert listed["meta"]["total"] == 1
        created = await client.ai_gateway.create_agent(
            "gw_1", name="Summarizer", slug="summarizer",
            default_model="claude-sonnet-5", model_allowlist=["claude-sonnet-5"],
            streaming_enabled=True,
        )
        assert created["id"] == "ag_1"
        got = await client.ai_gateway.get_agent("ag_1")
        assert got["slug"] == "summarizer"
        updated = await client.ai_gateway.update_agent("ag_1", default_model="claude-opus-4-8")
        assert updated["default_model"] == "claude-opus-4-8"
        archived = await client.ai_gateway.delete_agent("ag_1")
        assert archived == {"id": "ag_1", "status": "archived"}

        # AIGW-161: ``agent_url`` -- the data-plane base_url you point an AI SDK
        # at -- is on EVERY agent projection, so all four reads above must carry
        # it. Until AIGW-161 only create and the single GET returned it: a caller
        # that LISTED agents got a row shaped differently from the one create had
        # just handed it, and PATCH -- the one response where a slug rename MOVES
        # the URL, since the server derives it from the slug rather than storing
        # it -- omitted the field entirely, leaving the caller that had just
        # changed the slug with no way to learn the new URL but a follow-up GET.
        assert listed["data"][0]["agent_url"] == agent_url
        assert created["agent_url"] == agent_url
        assert got["agent_url"] == agent_url
        assert updated["agent_url"] == agent_url

    assert ("GET", "/v1/ai-gateway/gateways/gw_1/agents") in calls
    assert ("POST", "/v1/ai-gateway/gateways/gw_1/agents") in calls
    assert ("GET", "/v1/ai-gateway/agents/ag_1") in calls
    assert ("PATCH", "/v1/ai-gateway/agents/ag_1") in calls
    assert ("DELETE", "/v1/ai-gateway/agents/ag_1") in calls


@pytest.mark.asyncio
async def test_update_agent_renames_and_reports_the_moved_url():
    """AIGW-161. ``slug`` was missing from ``update_agent``, so this SDK could
    not RENAME an agent -- the one patch that MOVES the data-plane URL, because
    the server derives ``agent_url`` from the slug rather than storing it.
    A caller had to fall back to raw ``client.request``.
    """
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return _success({
            "id": "ag_1", "slug": "digest",
            "agent_url": "https://acme.knoxcall.com/v1/ai/digest",
        })

    async with _async_client(handler) as client:
        updated = await client.ai_gateway.update_agent("ag_1", slug="digest")

    assert seen["body"] == {"slug": "digest"}
    # The point of the rename: the new base_url comes back on the PATCH itself.
    assert updated["agent_url"] == "https://acme.knoxcall.com/v1/ai/digest"


@pytest.mark.asyncio
async def test_update_agent_sends_every_writable_column():
    """A keyword that never reaches the body is accepted and silently dropped,
    which is worse than not having it: the caller believes the setting stuck.

    The column list here is the server's ``UPDATABLE_COLUMNS``
    (src/ai-gateway/service.ts); the source-level comparison lives in
    tests/coverage/ai-gateway-sdk-typed-patch-parity.test.ts, and this test is
    the runtime half -- it proves the values reach the WIRE.
    """
    seen = {}
    patch = {
        "name": "Digest",
        "slug": "digest",
        "description": "nightly digest",
        "primary_route_id": "c0ffee00-1111-4a2b-8c3d-000000000001",
        "fallback_route_ids": ["c0ffee00-1111-4a2b-8c3d-000000000002"],
        "model_allowlist": ["claude-sonnet-5"],
        "model_denylist": ["gpt-4o"],
        "default_model": "claude-sonnet-5",
        "model_rewrite": {"fast": "claude-haiku-4-5"},
        "budget_daily_usd": 25.5,
        "budget_monthly_usd": 400.0,
        "budget_per_call_max_tokens": 8192,
        "budget_overage_action": "fallback",
        "fallback_agent_id": "c0ffee00-3333-4a2b-8c3d-000000000003",
        "pii_redact_policy_id": "c0ffee00-4444-4a2b-8c3d-000000000004",
        "pii_request_mode": "tokenize",
        "pii_response_mode": "detokenize",
        "pii_streaming_holdback_chars": 64,
        "pii_streaming_mode": "holdback",
        "tags": {"cost_center": "research"},
        "cache_mode": "semantic",
        "cache_ttl_seconds": 300,
        "cache_similarity_threshold": 0.92,
        "cache_embedding_model": "text-embedding-3-small",
        "streaming_enabled": True,
        "firewall_policy_id": "c0ffee00-5555-4a2b-8c3d-000000000005",
        "tool_allowlist": ["search"],
        "output_schema": {"type": "object"},
        "output_validation_action": "retry",
        "data_residency_region": "eu",
        "cmek_key_id": "c0ffee00-6666-4a2b-8c3d-000000000006",
        "routing_policy": {"max_attempts": 3},
        "guardrail_webhook_url": "https://guard.example.test/hook",
        "guardrail_webhook_secret_id": "c0ffee00-7777-4a2b-8c3d-000000000007",
        "guardrail_webhook_mode": "both",
        "guardrail_webhook_timeout_ms": 2000,
        "guardrail_webhook_failure_action": "fail_closed",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return _success({"id": "ag_1"})

    async with _async_client(handler) as client:
        await client.ai_gateway.update_agent("ag_1", **patch)

    assert seen["body"] == patch

    # And an unsent field is ABSENT, not null: a patch that names a column sets
    # it, so a null would clear a setting the caller never mentioned.
    async with _async_client(handler) as client:
        await client.ai_gateway.update_agent("ag_1", tags={"team": "core"})
    assert seen["body"] == {"tags": {"team": "core"}}


@pytest.mark.asyncio
async def test_create_agent_sends_provider_and_upstream_secret():
    """Without these an SDK-created agent comes out with primary_route_id null --
    no upstream, no credential template -- and its first data-plane call 502s.

    The server refuses provider AND primary_route_id together (400), so an SDK
    that quietly sent both would break the very flow the field exists for.
    """
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return _success({"id": "ag_prov", "provider": "azure-openai"})

    async with _async_client(handler) as client:
        await client.ai_gateway.create_agent(
            "gw_1",
            name="Summarizer",
            slug="summarizer",
            provider="azure-openai",
            upstream_secret_id="c0ffee00-2222-4a2b-8c3d-000000000009",
            upstream="https://acme.openai.azure.com",
        )

    assert seen["body"]["provider"] == "azure-openai"
    assert seen["body"]["upstream_secret_id"] == "c0ffee00-2222-4a2b-8c3d-000000000009"
    assert seen["body"]["upstream"] == "https://acme.openai.azure.com"
    assert "primary_route_id" not in seen["body"]


@pytest.mark.asyncio
async def test_gateway_level_tokens_list_and_revoke():
    """The agent-less shape POST /v1/oauth/token mints for MCP.

    ``list_tokens``/``revoke_token`` filter on ``agent_id`` and can never match
    it, so an SDK without this pair leaves the caller unable to withdraw a
    credential they can create.
    """
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.method, req.url.path))
        if req.method == "GET" and req.url.path == "/v1/ai-gateway/gateways/gw_1/tokens":
            return _page(
                [{"id": "tok_g", "kind": "tool", "prefix": "kc_live_t", "agent_id": None}],
                total=1, page=1, per_page=20,
            )
        if req.method == "DELETE" and req.url.path == "/v1/ai-gateway/gateways/gw_1/tokens/tok_g":
            return _success({"id": "tok_g", "revoked": True})
        return httpx.Response(404)

    async with _async_client(handler) as client:
        listed = await client.ai_gateway.list_gateway_tokens("gw_1")
        assert listed["data"][0]["agent_id"] is None
        assert "token" not in listed["data"][0]        # never plaintext
        assert await client.ai_gateway.revoke_gateway_token("gw_1", "tok_g") == {"id": "tok_g", "revoked": True}

    assert ("GET", "/v1/ai-gateway/gateways/gw_1/tokens") in calls
    assert ("DELETE", "/v1/ai-gateway/gateways/gw_1/tokens/tok_g") in calls


# ── MCP servers (AIGW-02) ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_mcp_server_list_create_get_update_delete():
    calls = []
    server = {
        "id": "mcp_1", "gateway_id": "gw_1", "name": "Vendor tools", "slug": "vendor-tools",
        "server_type": "upstream", "transport": "streamable_http",
        "upstream_url": "https://mcp.vendor.example/mcp",
        "allowed_tools": ["get_weather"], "pii_inspection": True, "auth": {}, "status": "active",
        # connect_url and resource are DIFFERENT concepts; both must survive the
        # SDK round-trip or a caller cannot both dial and mint.
        "connect_url": "https://acme.knoxcall.com/v1/mcp/vendor-tools",
        "resource": "https://api.knoxcall.com/v1/mcp/vendor-tools",
    }

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.method, req.url.path))
        if req.method == "GET" and req.url.path == "/v1/ai-gateway/gateways/gw_1/mcp-servers":
            return _page([server], total=1, page=1, per_page=20)
        if req.method == "POST" and req.url.path == "/v1/ai-gateway/gateways/gw_1/mcp-servers":
            assert json.loads(req.content) == {
                "name": "Vendor tools", "slug": "vendor-tools",
                "upstream_url": "https://mcp.vendor.example/mcp",
                "allowed_tools": ["get_weather"],
                "auth": {"headers": {"Authorization": "Bearer {{secret_id:11111111-2222-3333-4444-555555555555}}"}},
            }
            return _success(server, note="allowed_tools is empty, so this server advertises NO tools.")
        if req.method == "GET" and req.url.path == "/v1/ai-gateway/mcp-servers/mcp_1":
            return _success(server)
        if req.method == "PATCH" and req.url.path == "/v1/ai-gateway/mcp-servers/mcp_1":
            assert json.loads(req.content) == {"allowed_tools": [], "status": "paused"}
            return _success({**server, "allowed_tools": [], "status": "paused"})
        if req.method == "DELETE" and req.url.path == "/v1/ai-gateway/mcp-servers/mcp_1":
            return _success({"id": "mcp_1", "status": "archived"})
        return httpx.Response(404)

    async with _async_client(handler) as client:
        listed = await client.ai_gateway.list_mcp_servers("gw_1")
        assert listed["data"][0]["id"] == "mcp_1"
        assert listed["meta"]["total"] == 1
        created = await client.ai_gateway.create_mcp_server(
            "gw_1", name="Vendor tools", slug="vendor-tools",
            upstream_url="https://mcp.vendor.example/mcp",
            allowed_tools=["get_weather"],
            auth={"headers": {"Authorization": "Bearer {{secret_id:11111111-2222-3333-4444-555555555555}}"}},
        )
        assert created["id"] == "mcp_1"
        got = await client.ai_gateway.get_mcp_server("mcp_1")
        assert got["connect_url"] == "https://acme.knoxcall.com/v1/mcp/vendor-tools"
        assert got["resource"] == "https://api.knoxcall.com/v1/mcp/vendor-tools"
        paused = await client.ai_gateway.update_mcp_server("mcp_1", allowed_tools=[], status="paused")
        # An empty allowlist means "advertise nothing" — it must not be dropped
        # as a falsy value on the way out.
        assert paused["allowed_tools"] == []
        archived = await client.ai_gateway.delete_mcp_server("mcp_1")
        assert archived == {"id": "mcp_1", "status": "archived"}

    assert ("GET", "/v1/ai-gateway/gateways/gw_1/mcp-servers") in calls
    assert ("POST", "/v1/ai-gateway/gateways/gw_1/mcp-servers") in calls
    assert ("PATCH", "/v1/ai-gateway/mcp-servers/mcp_1") in calls
    assert ("DELETE", "/v1/ai-gateway/mcp-servers/mcp_1") in calls


@pytest.mark.asyncio
async def test_mcp_tools_list_upsert_update_delete():
    tool = {
        "id": "tl_1", "mcp_server_id": "mcp_1", "tool_name": "get_weather",
        "route_id": None, "description": None, "input_schema": {}, "enabled": True,
    }

    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "GET" and req.url.path == "/v1/ai-gateway/mcp-servers/mcp_1/tools":
            return _page([tool], total=1, page=1, per_page=20)
        if req.method == "POST" and req.url.path == "/v1/ai-gateway/mcp-servers/mcp_1/tools":
            assert json.loads(req.content) == {"tool_name": "get_weather", "enabled": True}
            return _success(tool)
        if req.method == "PATCH" and req.url.path == "/v1/ai-gateway/mcp-servers/mcp_1/tools/tl_1":
            assert json.loads(req.content) == {"enabled": False}
            return _success({**tool, "enabled": False})
        if req.method == "DELETE" and req.url.path == "/v1/ai-gateway/mcp-servers/mcp_1/tools/tl_1":
            return _success({"id": "tl_1", "deleted": True})
        return httpx.Response(404)

    async with _async_client(handler) as client:
        listed = await client.ai_gateway.list_mcp_tools("mcp_1")
        assert listed["data"][0]["tool_name"] == "get_weather"
        assert (await client.ai_gateway.upsert_mcp_tool("mcp_1", tool_name="get_weather", enabled=True))["id"] == "tl_1"
        assert (await client.ai_gateway.update_mcp_tool("mcp_1", "tl_1", enabled=False))["enabled"] is False
        assert await client.ai_gateway.delete_mcp_tool("mcp_1", "tl_1") == {"id": "tl_1", "deleted": True}


# ── Tokens ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_tokens_list_never_returns_plaintext():
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/v1/ai-gateway/agents/ag_1/tokens"
        assert req.method == "GET"
        return _page(
            [{"id": "tk_1", "name": "ci", "kind": "agent", "prefix": "kc_live_ab",
              "dpop_required": False, "expires_at": None}],
            total=1, page=1, per_page=20,
        )

    async with _async_client(handler) as client:
        page = await client.ai_gateway.list_tokens("ag_1")

    row = page["data"][0]
    assert row["prefix"] == "kc_live_ab"
    assert "token" not in row  # plaintext never appears in a list


@pytest.mark.asyncio
async def test_mint_token_returns_plaintext_once():
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.method == "POST"
        assert req.url.path == "/v1/ai-gateway/agents/ag_1/tokens"
        assert json.loads(req.content) == {"name": "ci", "kind": "agent", "expires_in_seconds": 3600}
        return httpx.Response(200, json={
            "data": {
                "id": "tk_2", "name": "ci", "kind": "agent", "prefix": "kc_live_cd",
                "token": "kc_live_cd_PLAINTEXTONCE", "dpop_required": False,
                "expires_at": "2026-07-06T01:00:00Z",
            },
            "meta": {"note": "Save this token now — it will not be shown again."},
        })

    async with _async_client(handler) as client:
        minted = await client.ai_gateway.mint_token(
            "ag_1", name="ci", kind="agent", expires_in_seconds=3600
        )

    assert minted["token"] == "kc_live_cd_PLAINTEXTONCE"  # plaintext surfaced
    assert minted["prefix"] == "kc_live_cd"
    assert "meta" not in minted  # unwrapped to data


@pytest.mark.asyncio
async def test_revoke_token():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.method, req.url.path))
        return _success({"id": "tk_2", "revoked": True})

    async with _async_client(handler) as client:
        result = await client.ai_gateway.revoke_token("ag_1", "tk_2")

    assert result == {"id": "tk_2", "revoked": True}
    assert ("DELETE", "/v1/ai-gateway/agents/ag_1/tokens/tk_2") in calls


# ── Usage ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_usage_carries_period_and_agent_filter():
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/v1/ai-gateway/usage"
        assert dict(req.url.params) == {"period": "7d", "agent_id": "ag_1"}
        return _success({
            "period_days": 7,
            "by_model": [{
                "provider": "anthropic", "model": "claude-sonnet-5",
                "requests": 12, "input_tokens": 3400, "output_tokens": 900,
                "cost_usd": 0.42, "unpriced_requests": 0,
            }],
            "totals": {
                "requests": 12, "input_tokens": 3400, "output_tokens": 900,
                "cost_usd": 0.42, "unpriced_requests": 0,
            },
        })

    async with _async_client(handler) as client:
        usage = await client.ai_gateway.usage(period="7d", agent_id="ag_1")

    assert usage["period_days"] == 7
    assert usage["by_model"][0]["model"] == "claude-sonnet-5"
    assert usage["totals"]["cost_usd"] == 0.42
    assert "meta" not in usage


@pytest.mark.asyncio
async def test_export_usage_sends_group_by_and_format_and_unwraps_rows():
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.method == "GET"
        assert req.url.path == "/v1/ai-gateway/usage/export"
        # group_by is required, format=json is always sent, filters passed through
        assert dict(req.url.params) == {
            "group_by": "agent", "format": "json", "period": "30d", "agent_id": "ag_1",
        }
        return _success({
            "group_by": "agent",
            "period_days": 30,
            "rows": [
                {
                    "group": "ag_1", "requests": 12, "input_tokens": 3400,
                    "output_tokens": 900, "cost_usd": 0.42, "unpriced_requests": 0,
                },
                {
                    "group": None, "requests": 3, "input_tokens": 100,
                    "output_tokens": 50, "cost_usd": 0.01, "unpriced_requests": 3,
                },
            ],
        })

    async with _async_client(handler) as client:
        export = await client.ai_gateway.export_usage(
            group_by="agent", period="30d", agent_id="ag_1"
        )

    # unwrapped from the {data, meta} envelope
    assert "meta" not in export
    assert export["group_by"] == "agent"
    assert export["period_days"] == 30
    assert [r["group"] for r in export["rows"]] == ["ag_1", None]
    assert export["rows"][0]["cost_usd"] == 0.42


# ── Sync facade ───────────────────────────────────────────────────────────────


def test_ai_gateway_on_sync_facade():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "GET" and req.url.path == "/v1/ai-gateway/gateways":
            return _page([{"id": "gw_1", "slug": "prod"}], total=1, page=1, per_page=20)
        if req.method == "POST" and req.url.path == "/v1/ai-gateway/agents/ag_1/tokens":
            return _success(
                {"id": "tk_9", "kind": "agent", "prefix": "kc_live_z", "token": "kc_live_z_SECRET"},
                note="Save this token now — it will not be shown again.",
            )
        return httpx.Response(404)

    with _sync_client(handler) as client:
        page = client.ai_gateway.list_gateways()
        assert page["data"][0]["id"] == "gw_1"
        minted = client.ai_gateway.mint_token("ag_1", kind="agent")
        assert minted["token"] == "kc_live_z_SECRET"


# ── Sandbox client is unaffected: no env param, mints via the test data plane ──


def test_sandbox_client_mints_without_env_param():
    """A sandbox/test client mints test-env tokens server-side; the SDK method
    signature carries NO env param and the management path is unchanged."""
    captured = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured["path"] = req.url.path
        captured["body"] = json.loads(req.content) if req.content else {}
        return _success(
            {"id": "tk_s", "kind": "agent", "prefix": "kc_test_a", "token": "kp_test_a_SANDBOX"},
            note="Save this token now — it will not be shown again.",
        )

    with _sync_client(handler, sandbox=True) as client:
        assert client._async.sandbox is True
        minted = client.ai_gateway.mint_token("ag_1", kind="agent")

    assert minted["token"] == "kp_test_a_SANDBOX"
    assert captured["path"] == "/v1/ai-gateway/agents/ag_1/tokens"
    # No environment leaked into the body — env is a server-side property of the key.
    assert "environment" not in captured["body"] and "env" not in captured["body"]

# ── Firewall policies (AIGW-03) ───────────────────────────────────────────────


_POLICY = {
    "id": "fp_1",
    "tenant_id": "ten_1",
    "name": "Strict",
    "version": 1,
    "heuristics": [{"name": "no_competitor", "kind": "regex", "pattern": "CompetitorAI", "flags": "i"}],
    "canary_enabled": True,
    "vector_classifier_enabled": False,
    "lakera_enabled": False,
    "model_classifier_id": None,
    "action": "block",
    "created_at": "2026-08-24T00:00:00Z",
}


def test_firewall_policy_crud_and_tester():
    """Every mock is the REAL server envelope: the list gets {data:[...], meta:PageMeta},
    the single-object writes get {data:{...}, meta:{request_id}} (PARITY section 4)."""
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.method, req.url.path))
        path, method = req.url.path, req.method
        if path == "/v1/ai-gateway/firewall-policies" and method == "GET":
            return _page([_POLICY], total=1, page=1, per_page=20)
        if path == "/v1/ai-gateway/firewall-policies" and method == "POST":
            return _success({**_POLICY, "id": "fp_new", "version": 2})
        if path == "/v1/ai-gateway/firewall-policies/test" and method == "POST":
            return _success({
                "matched": True,
                "matches": [{"rule": "ignore_previous_instructions", "span": [0, 32], "matched": "Ignore all previous instructions"}],
                "skipped": [],
            })
        if path == "/v1/ai-gateway/firewall-policies/fp_1" and method == "GET":
            return _success(_POLICY)
        if path == "/v1/ai-gateway/firewall-policies/fp_1" and method == "PATCH":
            return _success({**_POLICY, "action": "warn"})
        if path == "/v1/ai-gateway/firewall-policies/fp_1" and method == "DELETE":
            return _success({"id": "fp_1", "deleted": True})
        return httpx.Response(404)

    with _sync_client(handler) as client:
        page = client.ai_gateway.list_firewall_policies()
        assert page["data"][0]["action"] == "block"
        assert page["meta"]["per_page"] == 20

        created = client.ai_gateway.create_firewall_policy(
            name="Strict",
            action="block",
            heuristics=[{"name": "no_competitor", "kind": "regex", "pattern": "CompetitorAI"}],
        )
        # Re-using an existing name yields the next version, not a conflict.
        assert created["id"] == "fp_new" and created["version"] == 2

        assert client.ai_gateway.get_firewall_policy("fp_1")["name"] == "Strict"
        assert client.ai_gateway.update_firewall_policy("fp_1", action="warn")["action"] == "warn"
        assert client.ai_gateway.delete_firewall_policy("fp_1") == {"id": "fp_1", "deleted": True}

        tested = client.ai_gateway.test_firewall_rules(text="Ignore all previous instructions")
        assert tested["matched"] is True
        assert tested["matches"][0]["rule"] == "ignore_previous_instructions"
        assert tested["skipped"] == []

    # /test must reach its own path, not be captured as a policy id.
    assert ("POST", "/v1/ai-gateway/firewall-policies/test") in seen


# ── PII policies + recognizers (AIGW-160) ───────────────────────────────


_PII_POLICY = {
    "id": "pp_1",
    "tenant_id": "ten_1",
    "name": "HIPAA",
    "version": 1,
    "recognizer_ids": ["pr_1"],
    "default_action": "redact",
    "description": "PHI in prompts",
    "created_at": "2026-09-07T00:00:00Z",
}

_PII_RECOGNIZER = {
    "id": "pr_1",
    "tenant_id": "ten_1",
    "name": "member_id",
    "kind": "regex",
    "pattern": "MEM-[0-9]{6}",
    "context_words": ["member", "patient"],
    "confidence": 0.9,
    "action": "redact",
    "format": None,
    "enabled": True,
    "created_at": "2026-09-07T00:00:00Z",
}


def test_pii_policy_crud_over_the_sync_facade():
    """Driven through the SYNC facade on purpose: every async method needs a
    ``_SyncAIGateway`` wrapper or a sync user gets AttributeError, and nothing
    else in this suite would notice. Envelopes are the REAL ones — the list gets
    {data:[...], meta:PageMeta}, the single-object writes {data:{...},
    meta:{request_id}} (PARITY section 4)."""
    seen = []
    bodies = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.method, req.url.path))
        path, method = req.url.path, req.method
        if req.content:
            bodies[(method, path)] = json.loads(req.content)
        if path == "/v1/ai-gateway/pii-policies" and method == "GET":
            return _page([_PII_POLICY], total=1, page=1, per_page=20)
        if path == "/v1/ai-gateway/pii-policies" and method == "POST":
            # An empty recognizer_ids echoes back empty: it means "every enabled
            # recognizer this tenant owns", not "none".
            return _success({**_PII_POLICY, "id": "pp_new", "recognizer_ids": []})
        if path == "/v1/ai-gateway/pii-policies/pp_1" and method == "GET":
            return _success(_PII_POLICY)
        if path == "/v1/ai-gateway/pii-policies/pp_1" and method == "PATCH":
            return _success({**_PII_POLICY, "default_action": "tokenize"})
        if path == "/v1/ai-gateway/pii-policies/pp_1" and method == "DELETE":
            return _success({"id": "pp_1", "deleted": True})
        return httpx.Response(404)

    with _sync_client(handler) as client:
        page = client.ai_gateway.list_pii_policies()
        assert page["data"][0]["default_action"] == "redact"
        assert page["data"][0]["recognizer_ids"] == ["pr_1"]
        assert page["meta"]["per_page"] == 20

        created = client.ai_gateway.create_pii_policy(
            name="HIPAA",
            recognizer_ids=[],
            default_action="redact",
            description="PHI in prompts",
        )
        # [] is the WIDEST policy (every enabled recognizer), never "no redaction".
        assert created["id"] == "pp_new" and created["recognizer_ids"] == []
        # It must actually be SENT — dropping an explicit [] would silently change
        # the policy's meaning on the server's defaulting path.
        assert bodies[("POST", "/v1/ai-gateway/pii-policies")] == {
            "name": "HIPAA",
            "recognizer_ids": [],
            "default_action": "redact",
            "description": "PHI in prompts",
        }

        assert client.ai_gateway.get_pii_policy("pp_1")["name"] == "HIPAA"

        updated = client.ai_gateway.update_pii_policy(
            "pp_1", default_action="tokenize", recognizer_ids=["pr_1", "pr_2"]
        )
        assert updated["default_action"] == "tokenize"
        assert bodies[("PATCH", "/v1/ai-gateway/pii-policies/pp_1")] == {
            "recognizer_ids": ["pr_1", "pr_2"],
            "default_action": "tokenize",
        }

        assert client.ai_gateway.delete_pii_policy("pp_1") == {"id": "pp_1", "deleted": True}

    assert ("GET", "/v1/ai-gateway/pii-policies/pp_1") in seen
    assert ("DELETE", "/v1/ai-gateway/pii-policies/pp_1") in seen


def test_pii_recognizer_crud_and_tester_over_the_sync_facade():
    seen = []
    bodies = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.method, req.url.path))
        path, method = req.url.path, req.method
        if req.content:
            bodies[(method, path)] = json.loads(req.content)
        if path == "/v1/ai-gateway/pii-recognizers" and method == "GET":
            return _page([_PII_RECOGNIZER], total=1, page=1, per_page=20)
        if path == "/v1/ai-gateway/pii-recognizers" and method == "POST":
            return _success({**_PII_RECOGNIZER, "id": "pr_new"})
        if path == "/v1/ai-gateway/pii-recognizers/test" and method == "POST":
            return _success({
                "matched": True,
                "matches": [{
                    "span": [9, 19],
                    "matched": "MEM-123456",
                    "replacement": "<MEMBER_ID>",
                    "entity_type": "member_id",
                }],
            })
        if path == "/v1/ai-gateway/pii-recognizers/pr_1" and method == "GET":
            return _success(_PII_RECOGNIZER)
        if path == "/v1/ai-gateway/pii-recognizers/pr_1" and method == "PATCH":
            return _success({**_PII_RECOGNIZER, "enabled": False})
        if path == "/v1/ai-gateway/pii-recognizers/pr_1" and method == "DELETE":
            return _success({"id": "pr_1", "deleted": True})
        return httpx.Response(404)

    with _sync_client(handler) as client:
        page = client.ai_gateway.list_pii_recognizers()
        assert page["data"][0]["kind"] == "regex"
        assert page["data"][0]["format"] is None
        assert page["meta"]["total_pages"] == 1

        created = client.ai_gateway.create_pii_recognizer(
            name="member_id",
            kind="regex",
            pattern="MEM-[0-9]{6}",
            context_words=["member", "patient"],
            confidence=0.9,
        )
        assert created["id"] == "pr_new"
        assert bodies[("POST", "/v1/ai-gateway/pii-recognizers")] == {
            "name": "member_id",
            "kind": "regex",
            "pattern": "MEM-[0-9]{6}",
            "context_words": ["member", "patient"],
            "confidence": 0.9,
        }

        # The tester is side-effect free, so it carries NO idempotency_key —
        # exactly like test_firewall_rules.
        tested = client.ai_gateway.test_pii_recognizer(
            pattern="MEM-[0-9]{6}", text="member MEM-123456", kind="regex"
        )
        assert tested["matched"] is True
        assert tested["matches"][0]["span"] == [9, 19]
        assert tested["matches"][0]["replacement"] == "<MEMBER_ID>"
        assert tested["matches"][0]["entity_type"] == "member_id"

        assert client.ai_gateway.get_pii_recognizer("pr_1")["name"] == "member_id"
        # enabled=False mutes without losing the definition; False must survive
        # the "if ... is not None" body build rather than being dropped.
        assert client.ai_gateway.update_pii_recognizer("pr_1", enabled=False)["enabled"] is False
        assert bodies[("PATCH", "/v1/ai-gateway/pii-recognizers/pr_1")] == {"enabled": False}
        assert client.ai_gateway.delete_pii_recognizer("pr_1") == {"id": "pr_1", "deleted": True}

    # /test must reach its own path, not be captured as a recognizer id.
    assert ("POST", "/v1/ai-gateway/pii-recognizers/test") in seen


def test_pii_mutators_forward_an_explicit_idempotency_key():
    """Python is the only SDK that threads an explicit ``idempotency_key``; if a
    mutator drops the kwarg the core silently substitutes a fresh ULID, so a
    retry would be treated as a new write."""
    seen_keys = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen_keys[(req.method, req.url.path)] = req.headers.get("X-Idempotency-Key")
        if req.method == "POST" and req.url.path == "/v1/ai-gateway/pii-policies":
            return _success(_PII_POLICY)
        if req.method == "POST" and req.url.path == "/v1/ai-gateway/pii-recognizers":
            return _success(_PII_RECOGNIZER)
        if req.method == "DELETE" and req.url.path == "/v1/ai-gateway/pii-recognizers/pr_1":
            return _success({"id": "pr_1", "deleted": True})
        if req.method == "POST" and req.url.path == "/v1/ai-gateway/pii-recognizers/test":
            return _success({"matched": False, "matches": []})
        return httpx.Response(404)

    with _sync_client(handler) as client:
        client.ai_gateway.create_pii_policy(name="HIPAA", idempotency_key="idem_pol")
        client.ai_gateway.create_pii_recognizer(
            name="member_id", kind="regex", pattern="MEM-1", idempotency_key="idem_rec"
        )
        client.ai_gateway.delete_pii_recognizer("pr_1", idempotency_key="idem_del")
        client.ai_gateway.test_pii_recognizer(pattern="MEM-1", text="none here")

    assert seen_keys[("POST", "/v1/ai-gateway/pii-policies")] == "idem_pol"
    assert seen_keys[("POST", "/v1/ai-gateway/pii-recognizers")] == "idem_rec"
    assert seen_keys[("DELETE", "/v1/ai-gateway/pii-recognizers/pr_1")] == "idem_del"


@pytest.mark.asyncio
async def test_iterate_pii_policies_and_recognizers_walk_all_pages():
    policies = [{**_PII_POLICY, "id": f"pp_{i}"} for i in range(1, 6)]
    recognizers = [{**_PII_RECOGNIZER, "id": f"pr_{i}"} for i in range(1, 4)]

    def handler(req: httpx.Request) -> httpx.Response:
        params = dict(req.url.params)
        page = int(params.get("page", 1))
        per_page = int(params.get("per_page", 20))
        rows = policies if req.url.path.endswith("/pii-policies") else recognizers
        return _page(
            rows[(page - 1) * per_page: page * per_page],
            total=len(rows), page=page, per_page=per_page,
        )

    async with _async_client(handler) as client:
        pol_ids = [p["id"] async for p in client.ai_gateway.iterate_pii_policies(per_page=2)]
        rec_ids = [r["id"] async for r in client.ai_gateway.iterate_pii_recognizers(per_page=2)]

    assert pol_ids == ["pp_1", "pp_2", "pp_3", "pp_4", "pp_5"]
    assert rec_ids == ["pr_1", "pr_2", "pr_3"]
