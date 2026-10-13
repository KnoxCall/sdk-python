"""AI Gateway resource — mirrors the /v1 AI Gateway control plane
(``src/client-api/ai-gateway.ts``).

Flat methods grouped by sub-collection (gateways / agents / tokens) plus
``usage()`` — the same flat style routes/vaults use for their sub-collections
(``list_actions`` / ``list_tokens`` …). Gateways and agents are addressed by
UUID; a token is minted for an agent and its plaintext is returned exactly once.
"""

from __future__ import annotations
from typing import Any, AsyncIterator, TYPE_CHECKING
from urllib.parse import quote

from .._envelope import unwrap
from ..types import (
    AIGateway,
    AIGatewayFirewallDeleteResult,
    AIGatewayFirewallPolicy,
    AIGatewayFirewallPolicyPage,
    AIGatewayFirewallRule,
    AIGatewayFirewallTestResult,
    AIGatewayAgent,
    AIGatewayAgentPage,
    AIGatewayArchiveResult,
    AIGatewayMcpServer,
    AIGatewayMcpServerPage,
    AIGatewayMcpTool,
    AIGatewayMcpToolDeleteResult,
    AIGatewayMcpToolPage,
    AIGatewayMintedToken,
    AIGatewayPage,
    AIGatewayPiiDeleteResult,
    AIGatewayPiiPolicy,
    AIGatewayPiiPolicyPage,
    AIGatewayPiiRecognizer,
    AIGatewayPiiRecognizerPage,
    AIGatewayPiiTestResult,
    AIGatewayToken,
    AIGatewayTokenPage,
    AIGatewayTokenRevokeResult,
    AIGatewayUsage,
    AIGatewayUsageExport,
)

if TYPE_CHECKING:
    from ..core import APIClient


class AIGatewayResource:
    def __init__(self, client: "APIClient") -> None:
        self._client = client

    # ── Gateways ──────────────────────────────────────────────────────────────

    async def list_gateways(
        self, *, page: int | None = None, per_page: int | None = None
    ) -> AIGatewayPage:
        """List AI gateways (paginated — server default 20/page, cap 100)."""
        query: dict[str, Any] = {}
        if page is not None:
            query["page"] = page
        if per_page is not None:
            query["per_page"] = per_page
        return await self._client.request(
            method="GET", path="/v1/ai-gateway/gateways", query=query or None
        )

    async def iterate_gateways(
        self, *, page: int = 1, per_page: int | None = None
    ) -> AsyncIterator[AIGateway]:
        """Yield every gateway, walking pages until ``meta.total_pages``."""
        current = page
        while True:
            result = await self.list_gateways(page=current, per_page=per_page)
            data = result.get("data") or []
            for g in data:
                yield g
            meta = result.get("meta") or {}
            if not data or current >= int(meta.get("total_pages") or 0):
                return
            current += 1

    async def create_gateway(
        self,
        *,
        name: str,
        slug: str,
        description: str | None = None,
        budget_daily_usd: float | None = None,
        budget_monthly_usd: float | None = None,
        budget_overage_action: str | None = None,
        idempotency_key: str | None = None,
    ) -> AIGateway:
        """Create a gateway.

        ``budget_overage_action`` (AIGW-150) is ``"block"`` (the default) or
        ``"warn"``: what happens once a cap above is spent. ``"block"`` refuses
        on BOTH data planes. No ``"fallback"`` -- that action swaps an agent's
        route and model, which a gateway does not have.
        """
        body: dict[str, Any] = {"name": name, "slug": slug}
        if description is not None:
            body["description"] = description
        if budget_daily_usd is not None:
            body["budget_daily_usd"] = budget_daily_usd
        if budget_monthly_usd is not None:
            body["budget_monthly_usd"] = budget_monthly_usd
        if budget_overage_action is not None:
            body["budget_overage_action"] = budget_overage_action
        return unwrap(await self._client.request(
            method="POST",
            path="/v1/ai-gateway/gateways",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def get_gateway(self, gateway_id: str) -> AIGateway:
        return unwrap(await self._client.request(
            method="GET", path=f"/v1/ai-gateway/gateways/{quote(gateway_id, safe='')}"
        ))

    async def update_gateway(
        self,
        gateway_id: str,
        *,
        name: str | None = None,
        description: str | None = None,
        budget_daily_usd: float | None = None,
        budget_monthly_usd: float | None = None,
        budget_overage_action: str | None = None,
        idempotency_key: str | None = None,
    ) -> AIGateway:
        """Patch a gateway. Only the arguments you pass are sent.

        ``budget_overage_action`` (AIGW-150): ``"block"`` or ``"warn"``.
        """
        body: dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if description is not None:
            body["description"] = description
        if budget_daily_usd is not None:
            body["budget_daily_usd"] = budget_daily_usd
        if budget_monthly_usd is not None:
            body["budget_monthly_usd"] = budget_monthly_usd
        if budget_overage_action is not None:
            body["budget_overage_action"] = budget_overage_action
        return unwrap(await self._client.request(
            method="PATCH",
            path=f"/v1/ai-gateway/gateways/{quote(gateway_id, safe='')}",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def delete_gateway(
        self, gateway_id: str, *, idempotency_key: str | None = None
    ) -> AIGatewayArchiveResult:
        """Archive (soft-delete) a gateway. Returns ``{id, status}``."""
        return unwrap(await self._client.request(
            method="DELETE",
            path=f"/v1/ai-gateway/gateways/{quote(gateway_id, safe='')}",
            idempotency_key=idempotency_key,
        ))

    # ── Agents ────────────────────────────────────────────────────────────────

    async def list_agents(
        self,
        gateway_id: str,
        *,
        page: int | None = None,
        per_page: int | None = None,
    ) -> AIGatewayAgentPage:
        """List a gateway's agents (paginated — server default 20/page, cap 100)."""
        query: dict[str, Any] = {}
        if page is not None:
            query["page"] = page
        if per_page is not None:
            query["per_page"] = per_page
        return await self._client.request(
            method="GET",
            path=f"/v1/ai-gateway/gateways/{quote(gateway_id, safe='')}/agents",
            query=query or None,
        )

    async def iterate_agents(
        self, gateway_id: str, *, page: int = 1, per_page: int | None = None
    ) -> AsyncIterator[AIGatewayAgent]:
        """Yield every agent under a gateway, walking pages until ``meta.total_pages``."""
        current = page
        while True:
            result = await self.list_agents(gateway_id, page=current, per_page=per_page)
            data = result.get("data") or []
            for a in data:
                yield a
            meta = result.get("meta") or {}
            if not data or current >= int(meta.get("total_pages") or 0):
                return
            current += 1

    async def create_agent(
        self,
        gateway_id: str,
        *,
        name: str,
        slug: str,
        description: str | None = None,
        primary_route_id: str | None = None,
        provider: str | None = None,
        upstream_secret_id: str | None = None,
        upstream: str | None = None,
        default_model: str | None = None,
        model_allowlist: list[str] | None = None,
        model_denylist: list[str] | None = None,
        budget_daily_usd: float | None = None,
        budget_monthly_usd: float | None = None,
        streaming_enabled: bool | None = None,
        firewall_policy_id: str | None = None,
        pii_redact_policy_id: str | None = None,
        pii_request_mode: str | None = None,
        pii_response_mode: str | None = None,
        pii_detokenize_response: bool | None = None,
        pii_streaming_holdback_chars: int | None = None,
        pii_streaming_mode: str | None = None,
        fallback_route_ids: list[str] | None = None,
        model_rewrite: dict[str, str] | None = None,
        budget_per_call_max_tokens: int | None = None,
        budget_overage_action: str | None = None,
        fallback_agent_id: str | None = None,
        tags: dict[str, str] | None = None,
        cache_mode: str | None = None,
        cache_ttl_seconds: int | None = None,
        cache_similarity_threshold: float | None = None,
        cache_embedding_model: str | None = None,
        tool_allowlist: list[str] | None = None,
        output_schema: dict[str, Any] | None = None,
        output_validation_action: str | None = None,
        data_residency_region: str | None = None,
        cmek_key_id: str | None = None,
        routing_policy: dict[str, Any] | None = None,
        guardrail_webhook_url: str | None = None,
        guardrail_webhook_secret_id: str | None = None,
        guardrail_webhook_mode: str | None = None,
        guardrail_webhook_timeout_ms: int | None = None,
        guardrail_webhook_failure_action: str | None = None,
        idempotency_key: str | None = None,
    ) -> AIGatewayAgent:
        """Create an agent under a gateway.

        ``provider`` composes the upstream route for you, INSTEAD of
        ``primary_route_id``: KnoxCall creates an ``ai-gateway-<slug>`` route
        pointing at the provider, injecting ``upstream_secret_id`` through the
        envelope store, and sets ``default_model`` from its pricebook default.

        It is a plain string and the catalog is SERVER-side -- fourteen ids at
        the time of writing (anthropic, openai, gemini, cohere, azure-openai,
        ollama, groq, together, mistral, deepseek, fireworks, xai, bedrock,
        openai-compatible) and growing. Send the string and surface the
        server's 400, which names the valid set; an SDK-side enum would reject
        a provider the API accepts.

        ``upstream`` is required for the four providers whose endpoint is
        yours rather than the vendor's: azure-openai, ollama, bedrock and
        openai-compatible. It is not defaulted: a bedrock or
        openai-compatible agent created without ``upstream`` is refused with
        a 400 at create time. ``openai-compatible`` also requires
        ``default_model``.

        Supply ``provider`` or ``primary_route_id``, NEVER BOTH (400). Supplying
        neither creates an agent with no upstream and no credential template,
        whose first data-plane call 502s.
        """
        body: dict[str, Any] = {"name": name, "slug": slug}
        if description is not None:
            body["description"] = description
        if primary_route_id is not None:
            body["primary_route_id"] = primary_route_id
        if provider is not None:
            body["provider"] = provider
        if upstream_secret_id is not None:
            body["upstream_secret_id"] = upstream_secret_id
        if upstream is not None:
            body["upstream"] = upstream
        if default_model is not None:
            body["default_model"] = default_model
        if model_allowlist is not None:
            body["model_allowlist"] = model_allowlist
        if model_denylist is not None:
            body["model_denylist"] = model_denylist
        if budget_daily_usd is not None:
            body["budget_daily_usd"] = budget_daily_usd
        if budget_monthly_usd is not None:
            body["budget_monthly_usd"] = budget_monthly_usd
        if streaming_enabled is not None:
            body["streaming_enabled"] = streaming_enabled
        if firewall_policy_id is not None:
            body["firewall_policy_id"] = firewall_policy_id
        if pii_redact_policy_id is not None:
            body["pii_redact_policy_id"] = pii_redact_policy_id
        # AIGW-100. ``pii_request_mode`` ("off" | "tokenize", default
        # "tokenize") is what decides whether the PROMPT is tokenized before it
        # leaves KnoxCall; ``pii_response_mode`` ("redact" | "detokenize",
        # default "detokenize") decides what happens to the answer. They used to
        # be one flag, and the response half gated both.
        if pii_request_mode is not None:
            body["pii_request_mode"] = pii_request_mode
        if pii_response_mode is not None:
            body["pii_response_mode"] = pii_response_mode
        # Everything below is accepted at CREATE and was reachable only by a
        # follow-up PATCH until 2026-09-15. A field that needs create-then-patch
        # cannot be modelled declaratively: the second call can fail and leave
        # an agent that is not what the caller asked for.
        if pii_detokenize_response is not None:
            body["pii_detokenize_response"] = pii_detokenize_response
        if pii_streaming_holdback_chars is not None:
            body["pii_streaming_holdback_chars"] = pii_streaming_holdback_chars
        # "holdback" | "buffer" | "monitor" -- "monitor" reports detections
        # without rewriting, so the raw value reaches the client.
        if pii_streaming_mode is not None:
            body["pii_streaming_mode"] = pii_streaming_mode
        if fallback_route_ids is not None:
            body["fallback_route_ids"] = fallback_route_ids
        if model_rewrite is not None:
            body["model_rewrite"] = model_rewrite
        if budget_per_call_max_tokens is not None:
            body["budget_per_call_max_tokens"] = budget_per_call_max_tokens
        # "block" | "warn" | "fallback"; "fallback" needs fallback_agent_id or
        # the overage behaves as "block".
        if budget_overage_action is not None:
            body["budget_overage_action"] = budget_overage_action
        if fallback_agent_id is not None:
            body["fallback_agent_id"] = fallback_agent_id
        if tags is not None:
            body["tags"] = tags
        # "semantic" additionally needs cache_embedding_model; without one the
        # cache reports itself degraded and serves nothing.
        if cache_mode is not None:
            body["cache_mode"] = cache_mode
        if cache_ttl_seconds is not None:
            body["cache_ttl_seconds"] = cache_ttl_seconds
        if cache_similarity_threshold is not None:
            body["cache_similarity_threshold"] = cache_similarity_threshold
        if cache_embedding_model is not None:
            body["cache_embedding_model"] = cache_embedding_model
        if tool_allowlist is not None:
            body["tool_allowlist"] = tool_allowlist
        if output_schema is not None:
            body["output_schema"] = output_schema
        if output_validation_action is not None:
            body["output_validation_action"] = output_validation_action
        # us | eu | uk | ca | au | jp | in -- not a cloud region id; anything
        # else is a 400.
        if data_residency_region is not None:
            body["data_residency_region"] = data_residency_region
        if cmek_key_id is not None:
            body["cmek_key_id"] = cmek_key_id
        # AIGW-42 retry/fail-over policy; the server normalises and CLAMPS it.
        if routing_policy is not None:
            body["routing_policy"] = routing_policy
        # AIGW-45 external guardrail webhook. The destination is resolved and
        # refused at write time AND on every call.
        if guardrail_webhook_url is not None:
            body["guardrail_webhook_url"] = guardrail_webhook_url
        if guardrail_webhook_secret_id is not None:
            body["guardrail_webhook_secret_id"] = guardrail_webhook_secret_id
        if guardrail_webhook_mode is not None:
            body["guardrail_webhook_mode"] = guardrail_webhook_mode
        if guardrail_webhook_timeout_ms is not None:
            body["guardrail_webhook_timeout_ms"] = guardrail_webhook_timeout_ms
        if guardrail_webhook_failure_action is not None:
            body["guardrail_webhook_failure_action"] = guardrail_webhook_failure_action
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/ai-gateway/gateways/{quote(gateway_id, safe='')}/agents",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def get_agent(self, agent_id: str) -> AIGatewayAgent:
        return unwrap(await self._client.request(
            method="GET", path=f"/v1/ai-gateway/agents/{quote(agent_id, safe='')}"
        ))

    async def update_agent(
        self,
        agent_id: str,
        *,
        name: str | None = None,
        slug: str | None = None,
        description: str | None = None,
        primary_route_id: str | None = None,
        fallback_route_ids: list[str] | None = None,
        model_allowlist: list[str] | None = None,
        model_denylist: list[str] | None = None,
        default_model: str | None = None,
        model_rewrite: dict[str, str] | None = None,
        budget_daily_usd: float | None = None,
        budget_monthly_usd: float | None = None,
        budget_per_call_max_tokens: int | None = None,
        budget_overage_action: str | None = None,
        fallback_agent_id: str | None = None,
        pii_redact_policy_id: str | None = None,
        pii_detokenize_response: bool | None = None,
        pii_request_mode: str | None = None,
        pii_response_mode: str | None = None,
        pii_streaming_holdback_chars: int | None = None,
        pii_streaming_mode: str | None = None,
        tags: dict[str, str] | None = None,
        cache_mode: str | None = None,
        cache_ttl_seconds: int | None = None,
        cache_similarity_threshold: float | None = None,
        cache_embedding_model: str | None = None,
        streaming_enabled: bool | None = None,
        firewall_policy_id: str | None = None,
        tool_allowlist: list[str] | None = None,
        output_schema: dict[str, Any] | None = None,
        output_validation_action: str | None = None,
        data_residency_region: str | None = None,
        cmek_key_id: str | None = None,
        routing_policy: dict[str, Any] | None = None,
        guardrail_webhook_url: str | None = None,
        guardrail_webhook_secret_id: str | None = None,
        guardrail_webhook_mode: str | None = None,
        guardrail_webhook_timeout_ms: int | None = None,
        guardrail_webhook_failure_action: str | None = None,
        idempotency_key: str | None = None,
    ) -> AIGatewayAgent:
        """PATCH /v1/ai-gateway/agents/:id.

        Every keyword here is a column the server's ``UPDATABLE_COLUMNS``
        accepts, and every one of those columns is a keyword here — a typed
        patch is the only thing between a caller and a server capability, so a
        field missing from this signature is a feature this SDK does not have.
        Pinned from the server side by
        ``tests/coverage/ai-gateway-sdk-typed-patch-parity.test.ts``.

        ``slug`` RENAMES the agent, which MOVES its data-plane URL: the server
        computes ``agent_url`` from the slug, so callers pointed at the old one
        404 from the moment this returns. Re-read ``agent_url``.

        KNOWN LIMITATION (FOLLOW-UPS §6, 2026-09-12): ``None`` means "leave it
        alone", so a
        nullable column cannot be CLEARED through these keywords. Use the
        free-form ``client.request`` escape hatch to send an explicit null.
        """
        body: dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if slug is not None:
            body["slug"] = slug
        if description is not None:
            body["description"] = description
        if primary_route_id is not None:
            body["primary_route_id"] = primary_route_id
        if fallback_route_ids is not None:
            body["fallback_route_ids"] = fallback_route_ids
        if model_allowlist is not None:
            body["model_allowlist"] = model_allowlist
        if model_denylist is not None:
            body["model_denylist"] = model_denylist
        if default_model is not None:
            body["default_model"] = default_model
        if model_rewrite is not None:
            body["model_rewrite"] = model_rewrite
        if budget_daily_usd is not None:
            body["budget_daily_usd"] = budget_daily_usd
        if budget_monthly_usd is not None:
            body["budget_monthly_usd"] = budget_monthly_usd
        if budget_per_call_max_tokens is not None:
            body["budget_per_call_max_tokens"] = budget_per_call_max_tokens
        # "block" | "warn" | "fallback"; "fallback" needs fallback_agent_id, or
        # the overage behaves as "block".
        if budget_overage_action is not None:
            body["budget_overage_action"] = budget_overage_action
        if fallback_agent_id is not None:
            body["fallback_agent_id"] = fallback_agent_id
        if pii_redact_policy_id is not None:
            body["pii_redact_policy_id"] = pii_redact_policy_id
        # AIGW-100: legacy alias for pii_response_mode. Sending both with
        # contradictory values is a 400.
        if pii_detokenize_response is not None:
            body["pii_detokenize_response"] = pii_detokenize_response
        if pii_request_mode is not None:
            body["pii_request_mode"] = pii_request_mode
        if pii_response_mode is not None:
            body["pii_response_mode"] = pii_response_mode
        if pii_streaming_holdback_chars is not None:
            body["pii_streaming_holdback_chars"] = pii_streaming_holdback_chars
        # "holdback" | "buffer" | "monitor": how a STREAMED answer is
        # rewritten. "monitor" reports detections without rewriting, so the raw
        # value reaches the client — an observability mode, not a redaction one.
        if pii_streaming_mode is not None:
            body["pii_streaming_mode"] = pii_streaming_mode
        # FinOps attribution labels (cost_center/team/project/…) echoed onto
        # this agent's usage rows.
        if tags is not None:
            body["tags"] = tags
        # "off" | "exact" | "semantic"; "semantic" also needs
        # cache_embedding_model, and cache_similarity_threshold is the cosine
        # floor for a hit (lower = more hits, and more wrong ones).
        if cache_mode is not None:
            body["cache_mode"] = cache_mode
        if cache_ttl_seconds is not None:
            body["cache_ttl_seconds"] = cache_ttl_seconds
        if cache_similarity_threshold is not None:
            body["cache_similarity_threshold"] = cache_similarity_threshold
        if cache_embedding_model is not None:
            body["cache_embedding_model"] = cache_embedding_model
        if streaming_enabled is not None:
            body["streaming_enabled"] = streaming_enabled
        if firewall_policy_id is not None:
            body["firewall_policy_id"] = firewall_policy_id
        if tool_allowlist is not None:
            body["tool_allowlist"] = tool_allowlist
        # output_schema is the JSON Schema the answer is validated against;
        # output_validation_action is "block" | "retry" | "warn".
        if output_schema is not None:
            body["output_schema"] = output_schema
        if output_validation_action is not None:
            body["output_validation_action"] = output_validation_action
        if data_residency_region is not None:
            body["data_residency_region"] = data_residency_region
        if cmek_key_id is not None:
            body["cmek_key_id"] = cmek_key_id
        # AIGW-42 retry/fail-over policy; the server normalises and CLAMPS it.
        if routing_policy is not None:
            body["routing_policy"] = routing_policy
        # AIGW-45 external guardrail webhook. The destination is resolved and
        # refused at write time AND on every call, so a private, loopback,
        # link-local or cloud-metadata address is a 400 here.
        if guardrail_webhook_url is not None:
            body["guardrail_webhook_url"] = guardrail_webhook_url
        if guardrail_webhook_secret_id is not None:
            body["guardrail_webhook_secret_id"] = guardrail_webhook_secret_id
        if guardrail_webhook_mode is not None:
            body["guardrail_webhook_mode"] = guardrail_webhook_mode
        if guardrail_webhook_timeout_ms is not None:
            body["guardrail_webhook_timeout_ms"] = guardrail_webhook_timeout_ms
        if guardrail_webhook_failure_action is not None:
            body["guardrail_webhook_failure_action"] = guardrail_webhook_failure_action
        return unwrap(await self._client.request(
            method="PATCH",
            path=f"/v1/ai-gateway/agents/{quote(agent_id, safe='')}",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def delete_agent(
        self, agent_id: str, *, idempotency_key: str | None = None
    ) -> AIGatewayArchiveResult:
        """Archive (soft-delete) an agent. Returns ``{id, status}``."""
        return unwrap(await self._client.request(
            method="DELETE",
            path=f"/v1/ai-gateway/agents/{quote(agent_id, safe='')}",
            idempotency_key=idempotency_key,
        ))


    # ── MCP servers ───────────────────────────────────────────────────────────

    async def list_mcp_servers(
        self,
        gateway_id: str,
        *,
        page: int | None = None,
        per_page: int | None = None,
    ) -> AIGatewayMcpServerPage:
        """List a gateway's MCP servers (paginated — server default 20/page, cap 100)."""
        query: dict[str, Any] = {}
        if page is not None:
            query["page"] = page
        if per_page is not None:
            query["per_page"] = per_page
        return await self._client.request(
            method="GET",
            path=f"/v1/ai-gateway/gateways/{quote(gateway_id, safe='')}/mcp-servers",
            query=query or None,
        )

    async def iterate_mcp_servers(
        self, gateway_id: str, *, page: int = 1, per_page: int | None = None
    ) -> AsyncIterator[AIGatewayMcpServer]:
        """Yield every MCP server under a gateway, walking pages until ``meta.total_pages``."""
        current = page
        while True:
            result = await self.list_mcp_servers(gateway_id, page=current, per_page=per_page)
            data = result.get("data") or []
            for s in data:
                yield s
            meta = result.get("meta") or {}
            if not data or current >= int(meta.get("total_pages") or 0):
                return
            current += 1

    async def create_mcp_server(
        self,
        gateway_id: str,
        *,
        name: str,
        slug: str,
        upstream_url: str,
        description: str | None = None,
        transport: str | None = None,          # streamable_http (default) | sse
        allowed_tools: list[str] | None = None,
        pii_inspection: bool | None = None,
        auth: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> AIGatewayMcpServer:
        """Register an upstream MCP server under a gateway.

        ``upstream_url`` must be a public ``https://`` address — private,
        loopback, link-local and cloud-metadata destinations are refused,
        because the request carries your decrypted upstream credential.

        Every value in ``auth["headers"]`` must reference a KnoxCall secret,
        e.g. ``{"Authorization": "Bearer {{secret_id:<uuid>}}"}``. A literal
        credential is refused — it would sit in cleartext in the control plane.

        ``allowed_tools`` EMPTY (the default) means the server advertises
        nothing. The result's ``connect_url`` is where an MCP client points;
        ``resource`` is the RFC 8707 value a token for it must be bound to.

        ``server_type='collection'`` is not accepted: the data plane does not
        serve it yet.
        """
        body: dict[str, Any] = {"name": name, "slug": slug, "upstream_url": upstream_url}
        if description is not None:
            body["description"] = description
        if transport is not None:
            body["transport"] = transport
        if allowed_tools is not None:
            body["allowed_tools"] = allowed_tools
        if pii_inspection is not None:
            body["pii_inspection"] = pii_inspection
        if auth is not None:
            body["auth"] = auth
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/ai-gateway/gateways/{quote(gateway_id, safe='')}/mcp-servers",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def get_mcp_server(self, server_id: str) -> AIGatewayMcpServer:
        return unwrap(await self._client.request(
            method="GET", path=f"/v1/ai-gateway/mcp-servers/{quote(server_id, safe='')}"
        ))

    async def update_mcp_server(
        self,
        server_id: str,
        *,
        name: str | None = None,
        description: str | None = None,
        upstream_url: str | None = None,
        transport: str | None = None,
        allowed_tools: list[str] | None = None,
        pii_inspection: bool | None = None,
        auth: dict[str, Any] | None = None,
        status: str | None = None,             # active | paused (DELETE archives)
        idempotency_key: str | None = None,
    ) -> AIGatewayMcpServer:
        body: dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if description is not None:
            body["description"] = description
        if upstream_url is not None:
            body["upstream_url"] = upstream_url
        if transport is not None:
            body["transport"] = transport
        if allowed_tools is not None:
            body["allowed_tools"] = allowed_tools
        if pii_inspection is not None:
            body["pii_inspection"] = pii_inspection
        if auth is not None:
            body["auth"] = auth
        if status is not None:
            body["status"] = status
        return unwrap(await self._client.request(
            method="PATCH",
            path=f"/v1/ai-gateway/mcp-servers/{quote(server_id, safe='')}",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def delete_mcp_server(
        self, server_id: str, *, idempotency_key: str | None = None
    ) -> AIGatewayArchiveResult:
        """Archive (soft-delete) an MCP server. Returns ``{id, status}``."""
        return unwrap(await self._client.request(
            method="DELETE",
            path=f"/v1/ai-gateway/mcp-servers/{quote(server_id, safe='')}",
            idempotency_key=idempotency_key,
        ))

    # ── MCP tools ─────────────────────────────────────────────────────────────

    async def list_mcp_tools(
        self,
        server_id: str,
        *,
        page: int | None = None,
        per_page: int | None = None,
    ) -> AIGatewayMcpToolPage:
        """List an MCP server's tool rows (paginated).

        Tool rows are metadata. What a client can call is the intersection of the
        server's ``allowed_tools``, the upstream's real tools, and the token's
        own tool scope.
        """
        query: dict[str, Any] = {}
        if page is not None:
            query["page"] = page
        if per_page is not None:
            query["per_page"] = per_page
        return await self._client.request(
            method="GET",
            path=f"/v1/ai-gateway/mcp-servers/{quote(server_id, safe='')}/tools",
            query=query or None,
        )

    async def iterate_mcp_tools(
        self, server_id: str, *, page: int = 1, per_page: int | None = None
    ) -> AsyncIterator[AIGatewayMcpTool]:
        """Yield every tool row for a server, walking pages until ``meta.total_pages``."""
        current = page
        while True:
            result = await self.list_mcp_tools(server_id, page=current, per_page=per_page)
            data = result.get("data") or []
            for t in data:
                yield t
            meta = result.get("meta") or {}
            if not data or current >= int(meta.get("total_pages") or 0):
                return
            current += 1

    async def upsert_mcp_tool(
        self,
        server_id: str,
        *,
        tool_name: str,
        description: str | None = None,
        input_schema: dict[str, Any] | None = None,
        enabled: bool | None = None,
        idempotency_key: str | None = None,
    ) -> AIGatewayMcpTool:
        """Insert or update a tool row by ``tool_name``."""
        body: dict[str, Any] = {"tool_name": tool_name}
        if description is not None:
            body["description"] = description
        if input_schema is not None:
            body["input_schema"] = input_schema
        if enabled is not None:
            body["enabled"] = enabled
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/ai-gateway/mcp-servers/{quote(server_id, safe='')}/tools",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def update_mcp_tool(
        self,
        server_id: str,
        tool_id: str,
        *,
        description: str | None = None,
        input_schema: dict[str, Any] | None = None,
        enabled: bool | None = None,
        idempotency_key: str | None = None,
    ) -> AIGatewayMcpTool:
        """Enable, disable or re-describe a tool row."""
        body: dict[str, Any] = {}
        if description is not None:
            body["description"] = description
        if input_schema is not None:
            body["input_schema"] = input_schema
        if enabled is not None:
            body["enabled"] = enabled
        return unwrap(await self._client.request(
            method="PATCH",
            path=(
                f"/v1/ai-gateway/mcp-servers/{quote(server_id, safe='')}"
                f"/tools/{quote(tool_id, safe='')}"
            ),
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def delete_mcp_tool(
        self, server_id: str, tool_id: str, *, idempotency_key: str | None = None
    ) -> AIGatewayMcpToolDeleteResult:
        """Delete a tool row. Returns ``{id, deleted: True}``."""
        return unwrap(await self._client.request(
            method="DELETE",
            path=(
                f"/v1/ai-gateway/mcp-servers/{quote(server_id, safe='')}"
                f"/tools/{quote(tool_id, safe='')}"
            ),
            idempotency_key=idempotency_key,
        ))

    # ── Delegated-OAuth connections (AIGW-190) ────────────────────────────────
    #
    # A connection holds ONE person's upstream refresh token, envelope-encrypted
    # under the tenant key. Nothing here returns it, redacted or otherwise.
    #
    # There is deliberately no ``connect_mcp_server``: consent has to be given by
    # the person whose credential it is, so the flow starts from a signed-in
    # KnoxCall session in the admin console. An API key is not a person.

    async def list_mcp_grants(
        self, server_id: str, *, page: int | None = None, per_page: int | None = None
    ) -> dict[str, Any]:
        """One page of the people who have connected their account to this server."""
        query: dict[str, Any] = {}
        if page is not None:
            query["page"] = page
        if per_page is not None:
            query["per_page"] = per_page
        return await self._client.request(
            method="GET",
            path=f"/v1/ai-gateway/mcp-servers/{quote(server_id, safe='')}/grants",
            query=query or None,
        )

    async def iterate_mcp_grants(
        self, server_id: str, *, page: int = 1, per_page: int | None = None
    ) -> AsyncIterator[dict[str, Any]]:
        """Yield every connection on this server, walking pages until ``meta.total_pages``."""
        current = page
        while True:
            result = await self.list_mcp_grants(server_id, page=current, per_page=per_page)
            data = result.get("data") or []
            for g in data:
                yield g
            meta = result.get("meta") or {}
            if not data or current >= int(meta.get("total_pages") or 0):
                return
            current += 1

    async def revoke_mcp_grant(
        self, server_id: str, grant_id: str, *, idempotency_key: str | None = None
    ) -> dict[str, Any]:
        """Revoke ONE person's connection. The stored tokens are destroyed."""
        return unwrap(await self._client.request(
            method="DELETE",
            path=(
                f"/v1/ai-gateway/mcp-servers/{quote(server_id, safe='')}"
                f"/grants/{quote(grant_id, safe='')}"
            ),
            idempotency_key=idempotency_key,
        ))

    async def revoke_all_mcp_grants(
        self, server_id: str, *, idempotency_key: str | None = None
    ) -> dict[str, Any]:
        """Revoke EVERY connection on this server (offboarding in one call)."""
        return unwrap(await self._client.request(
            method="DELETE",
            path=f"/v1/ai-gateway/mcp-servers/{quote(server_id, safe='')}/grants",
            idempotency_key=idempotency_key,
        ))

    # ── Tokens ────────────────────────────────────────────────────────────────

    async def list_tokens(
        self,
        agent_id: str,
        *,
        page: int | None = None,
        per_page: int | None = None,
    ) -> AIGatewayTokenPage:
        """List an agent's phantom tokens (paginated; plaintext is NEVER returned)."""
        query: dict[str, Any] = {}
        if page is not None:
            query["page"] = page
        if per_page is not None:
            query["per_page"] = per_page
        return await self._client.request(
            method="GET",
            path=f"/v1/ai-gateway/agents/{quote(agent_id, safe='')}/tokens",
            query=query or None,
        )

    async def iterate_tokens(
        self, agent_id: str, *, page: int = 1, per_page: int | None = None
    ) -> AsyncIterator[AIGatewayToken]:
        """Yield every token for an agent, walking pages until ``meta.total_pages``."""
        current = page
        while True:
            result = await self.list_tokens(agent_id, page=current, per_page=per_page)
            data = result.get("data") or []
            for t in data:
                yield t
            meta = result.get("meta") or {}
            if not data or current >= int(meta.get("total_pages") or 0):
                return
            current += 1

    async def mint_token(
        self,
        agent_id: str,
        *,
        name: str | None = None,
        kind: str | None = None,  # agent | read | tool | oneshot
        dpop_required: bool | None = None,
        dpop_jkt: str | None = None,
        # Defaults to 30 days when omitted; clamped to [60s, 90d]. A non-expiring token cannot be minted.
        expires_in_seconds: int | None = None,
        idempotency_key: str | None = None,
    ) -> AIGatewayMintedToken:
        """Mint a phantom token for an agent.

        ``token`` in the result is the plaintext and is shown exactly ONCE —
        persist it now. Set ``dpop_required=True`` together with ``dpop_jkt``
        (the base64url SHA-256 thumbprint of your DPoP public key) to bind it.
        """
        body: dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if kind is not None:
            body["kind"] = kind
        if dpop_required is not None:
            body["dpop_required"] = dpop_required
        if dpop_jkt is not None:
            body["dpop_jkt"] = dpop_jkt
        if expires_in_seconds is not None:
            body["expires_in_seconds"] = expires_in_seconds
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/ai-gateway/agents/{quote(agent_id, safe='')}/tokens",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def revoke_token(
        self, agent_id: str, token_id: str, *, idempotency_key: str | None = None
    ) -> AIGatewayTokenRevokeResult:
        """Revoke a token. Returns ``{id, revoked: True}``."""
        return unwrap(await self._client.request(
            method="DELETE",
            path=f"/v1/ai-gateway/agents/{quote(agent_id, safe='')}/tokens/{quote(token_id, safe='')}",
            idempotency_key=idempotency_key,
        ))

    # ── Firewall policies ─────────────────────────────────────────────────────

    async def list_firewall_policies(
        self, *, page: int | None = None, per_page: int | None = None
    ) -> AIGatewayFirewallPolicyPage:
        """List prompt-firewall policies (paginated). Tenant-scoped, not per gateway."""
        query: dict[str, Any] = {}
        if page is not None:
            query["page"] = page
        if per_page is not None:
            query["per_page"] = per_page
        return await self._client.request(
            method="GET", path="/v1/ai-gateway/firewall-policies", query=query or None
        )

    async def iterate_firewall_policies(
        self, *, per_page: int | None = None
    ) -> AsyncIterator[AIGatewayFirewallPolicy]:
        """Yield every firewall policy across all pages."""
        page = 1
        while True:
            result = await self.list_firewall_policies(page=page, per_page=per_page)
            rows = result.get("data") or []
            for row in rows:
                yield row
            meta = result.get("meta") or {}
            if page >= int(meta.get("total_pages") or 1) or not rows:
                return
            page += 1

    async def create_firewall_policy(
        self,
        *,
        name: str,
        heuristics: list[AIGatewayFirewallRule] | None = None,
        canary_enabled: bool | None = None,
        action: str | None = None,
        idempotency_key: str | None = None,
    ) -> AIGatewayFirewallPolicy:
        """Create a policy. Re-using an existing ``name`` creates version N+1.

        Every ``kind="regex"`` rule is compiled server-side before it is stored,
        so an unsupported pattern is a 400 here rather than a rule that silently
        matches nothing at scan time.
        """
        body: dict[str, Any] = {"name": name}
        if heuristics is not None:
            body["heuristics"] = heuristics
        if canary_enabled is not None:
            body["canary_enabled"] = canary_enabled
        if action is not None:
            body["action"] = action
        return unwrap(await self._client.request(
            method="POST",
            path="/v1/ai-gateway/firewall-policies",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def get_firewall_policy(self, policy_id: str) -> AIGatewayFirewallPolicy:
        return unwrap(await self._client.request(
            method="GET",
            path=f"/v1/ai-gateway/firewall-policies/{quote(policy_id, safe='')}",
        ))

    async def update_firewall_policy(
        self,
        policy_id: str,
        *,
        heuristics: list[AIGatewayFirewallRule] | None = None,
        canary_enabled: bool | None = None,
        action: str | None = None,
        idempotency_key: str | None = None,
    ) -> AIGatewayFirewallPolicy:
        """Update in place (the version is NOT bumped). Rules are re-validated."""
        body: dict[str, Any] = {}
        if heuristics is not None:
            body["heuristics"] = heuristics
        if canary_enabled is not None:
            body["canary_enabled"] = canary_enabled
        if action is not None:
            body["action"] = action
        return unwrap(await self._client.request(
            method="PATCH",
            path=f"/v1/ai-gateway/firewall-policies/{quote(policy_id, safe='')}",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def delete_firewall_policy(
        self, policy_id: str, *, idempotency_key: str | None = None
    ) -> AIGatewayFirewallDeleteResult:
        """Delete a policy. Refused with 409 ``policy_in_use`` while any agent or
        MCP server is still attached."""
        return unwrap(await self._client.request(
            method="DELETE",
            path=f"/v1/ai-gateway/firewall-policies/{quote(policy_id, safe='')}",
            idempotency_key=idempotency_key,
        ))

    async def test_firewall_rules(
        self, *, text: str, heuristics: list[AIGatewayFirewallRule] | None = None
    ) -> AIGatewayFirewallTestResult:
        """Dry-run rules against ``text``. Saves nothing; rules are compiled first,
        so this refuses exactly what create/update refuse."""
        body: dict[str, Any] = {"text": text}
        if heuristics is not None:
            body["heuristics"] = heuristics
        return unwrap(await self._client.request(
            method="POST", path="/v1/ai-gateway/firewall-policies/test", body=body
        ))



    async def list_gateway_tokens(
        self,
        gateway_id: str,
        *,
        page: int | None = None,
        per_page: int | None = None,
    ) -> AIGatewayTokenPage:
        """Every token under a gateway, INCLUDING gateway-level ones with no agent.

        ``POST /v1/oauth/token`` mints MCP tokens with no agent, and
        :meth:`list_tokens` filters on ``agent_id``, so it cannot see them.
        Plaintext is never returned by any list endpoint.
        """
        query: dict[str, Any] = {}
        if page is not None:
            query["page"] = page
        if per_page is not None:
            query["per_page"] = per_page
        return await self._client.request(
            method="GET",
            path=f"/v1/ai-gateway/gateways/{quote(gateway_id, safe='')}/tokens",
            query=query or None,
        )

    async def iterate_gateway_tokens(
        self, gateway_id: str, *, page: int = 1, per_page: int | None = None
    ) -> AsyncIterator[AIGatewayToken]:
        """Yield every token under a gateway, walking pages until ``meta.total_pages``."""
        current = page
        while True:
            result = await self.list_gateway_tokens(gateway_id, page=current, per_page=per_page)
            data = result.get("data") or []
            for t in data:
                yield t
            meta = result.get("meta") or {}
            if not data or current >= int(meta.get("total_pages") or 0):
                return
            current += 1

    async def revoke_gateway_token(
        self, gateway_id: str, token_id: str, *, idempotency_key: str | None = None
    ) -> AIGatewayTokenRevokeResult:
        """Revoke any token under a gateway, including a gateway-level one.

        Use this rather than :meth:`revoke_token` for a token minted by
        ``POST /v1/oauth/token`` — that token has no agent, so the per-agent
        revoke can never match it. Returns ``{id, revoked: True}``.
        """
        return unwrap(await self._client.request(
            method="DELETE",
            path=(
                f"/v1/ai-gateway/gateways/{quote(gateway_id, safe='')}"
                f"/tokens/{quote(token_id, safe='')}"
            ),
            idempotency_key=idempotency_key,
        ))

    # ── PII policies (AIGW-160) ─────────────────────────────────────
    #
    # Tenant-scoped like firewall policies: ONE policy attaches to any number of
    # agents through ``pii_redact_policy_id``, so these sit at the mount root
    # rather than under a gateway id. Until AIGW-160 they existed only on the
    # session-cookie admin plane, so :meth:`create_agent` accepted a
    # ``pii_redact_policy_id`` that no ``/v1`` call could produce.

    async def list_pii_policies(
        self, *, page: int | None = None, per_page: int | None = None
    ) -> AIGatewayPiiPolicyPage:
        """List PII redaction policies (paginated). Tenant-scoped, not per gateway."""
        query: dict[str, Any] = {}
        if page is not None:
            query["page"] = page
        if per_page is not None:
            query["per_page"] = per_page
        return await self._client.request(
            method="GET", path="/v1/ai-gateway/pii-policies", query=query or None
        )

    async def iterate_pii_policies(
        self, *, per_page: int | None = None
    ) -> AsyncIterator[AIGatewayPiiPolicy]:
        """Yield every PII policy across all pages."""
        page = 1
        while True:
            result = await self.list_pii_policies(page=page, per_page=per_page)
            rows = result.get("data") or []
            for row in rows:
                yield row
            meta = result.get("meta") or {}
            if page >= int(meta.get("total_pages") or 1) or not rows:
                return
            page += 1

    async def create_pii_policy(
        self,
        *,
        name: str,
        recognizer_ids: list[str] | None = None,
        default_action: str | None = None,
        description: str | None = None,
        idempotency_key: str | None = None,
    ) -> AIGatewayPiiPolicy:
        """Create a PII policy. ``name`` is 2-64 chars and unique per tenant.

        An EMPTY ``recognizer_ids`` — omitted, or an explicit ``[]`` — means
        "every enabled recognizer this tenant owns", NOT "none". The empty list
        is the WIDEST policy you can author, not the narrowest.

        Every id you DO pass must be a recognizer this tenant owns: a foreign or
        unknown id is a 400 ``recognizer_not_found`` at write time rather than a
        stored value that resolves to nothing at scan time, which would leave the
        policy silently running fewer detectors than it lists.

        ``default_action`` is what a matching detector does: ``"redact"``
        (placeholder), ``"tokenize"`` (a reversible token the gateway restores in
        the response), ``"warn"`` (record the hit, forward the value unchanged)
        or ``"whitelist"`` (exempt the shape from every other detector). The
        server default is ``"redact"``.
        """
        body: dict[str, Any] = {"name": name}
        if recognizer_ids is not None:
            body["recognizer_ids"] = recognizer_ids
        if default_action is not None:
            body["default_action"] = default_action
        if description is not None:
            body["description"] = description
        return unwrap(await self._client.request(
            method="POST",
            path="/v1/ai-gateway/pii-policies",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def get_pii_policy(self, policy_id: str) -> AIGatewayPiiPolicy:
        return unwrap(await self._client.request(
            method="GET",
            path=f"/v1/ai-gateway/pii-policies/{quote(policy_id, safe='')}",
        ))

    async def update_pii_policy(
        self,
        policy_id: str,
        *,
        recognizer_ids: list[str] | None = None,
        default_action: str | None = None,
        description: str | None = None,
        idempotency_key: str | None = None,
    ) -> AIGatewayPiiPolicy:
        """Update a PII policy in place (the version is NOT bumped).

        ``recognizer_ids`` REPLACES the list rather than merging into it, and
        passing ``[]`` therefore WIDENS the policy to every enabled recognizer
        instead of disabling redaction. Each id is re-checked against this
        tenant's recognizers, so a foreign id is a 400 ``recognizer_not_found``.
        """
        body: dict[str, Any] = {}
        if recognizer_ids is not None:
            body["recognizer_ids"] = recognizer_ids
        if default_action is not None:
            body["default_action"] = default_action
        if description is not None:
            body["description"] = description
        return unwrap(await self._client.request(
            method="PATCH",
            path=f"/v1/ai-gateway/pii-policies/{quote(policy_id, safe='')}",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def delete_pii_policy(
        self, policy_id: str, *, idempotency_key: str | None = None
    ) -> AIGatewayPiiDeleteResult:
        """Delete a PII policy. Returns ``{id, deleted: True}``.

        Refused with 409 ``policy_in_use`` while ANY agent still references it.
        That refusal is load-bearing: the foreign key is ``ON DELETE SET NULL``,
        so an unchecked delete would detach every bound agent and turn redaction
        OFF for each of them with no error anywhere. Re-point or clear the
        agents' ``pii_redact_policy_id`` first.
        """
        return unwrap(await self._client.request(
            method="DELETE",
            path=f"/v1/ai-gateway/pii-policies/{quote(policy_id, safe='')}",
            idempotency_key=idempotency_key,
        ))

    # ── PII recognizers (AIGW-160) ─────────────────────────────────

    async def list_pii_recognizers(
        self, *, page: int | None = None, per_page: int | None = None
    ) -> AIGatewayPiiRecognizerPage:
        """List this tenant's custom PII recognizers (paginated)."""
        query: dict[str, Any] = {}
        if page is not None:
            query["page"] = page
        if per_page is not None:
            query["per_page"] = per_page
        return await self._client.request(
            method="GET", path="/v1/ai-gateway/pii-recognizers", query=query or None
        )

    async def iterate_pii_recognizers(
        self, *, per_page: int | None = None
    ) -> AsyncIterator[AIGatewayPiiRecognizer]:
        """Yield every PII recognizer across all pages."""
        page = 1
        while True:
            result = await self.list_pii_recognizers(page=page, per_page=per_page)
            rows = result.get("data") or []
            for row in rows:
                yield row
            meta = result.get("meta") or {}
            if page >= int(meta.get("total_pages") or 1) or not rows:
                return
            page += 1

    async def create_pii_recognizer(
        self,
        *,
        name: str,
        kind: str,
        pattern: str,
        context_words: list[str] | None = None,
        confidence: float | None = None,
        action: str | None = None,
        format: str | None = None,
        enabled: bool | None = None,
        idempotency_key: str | None = None,
    ) -> AIGatewayPiiRecognizer:
        """Create a custom recognizer.

        ``kind`` is one of ``"regex"``, ``"aho_corasick"``,
        ``"presidio_pattern"``, ``"presidio_ner"`` or ``"presidio_custom"``; the
        first two run in-process, the ``presidio_*`` kinds go to a sidecar.

        A ``"regex"`` ``pattern`` is compiled server-side with a linear-time
        engine BEFORE it is stored, so lookahead, lookbehind and backreferences
        are a 400 here rather than a recognizer that is saved and then silently
        skipped when the policy runs. Dry-run with
        :meth:`test_pii_recognizer` — never with a local :mod:`re` compile,
        which accepts all three.

        ``confidence`` is 0-1 (server default 0.85), ``action`` defaults to the
        owning policy's ``default_action``, and ``format`` is the token template
        used only when ``action="tokenize"``. A ``"whitelist"`` recognizer
        exempts its shape from every OTHER detector, so one that matches
        arbitrary text is a kill switch for the built-in tier and the server
        refuses it.
        """
        body: dict[str, Any] = {"name": name, "kind": kind, "pattern": pattern}
        if context_words is not None:
            body["context_words"] = context_words
        if confidence is not None:
            body["confidence"] = confidence
        if action is not None:
            body["action"] = action
        if format is not None:
            body["format"] = format
        if enabled is not None:
            body["enabled"] = enabled
        return unwrap(await self._client.request(
            method="POST",
            path="/v1/ai-gateway/pii-recognizers",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def test_pii_recognizer(
        self,
        *,
        pattern: str,
        text: str,
        kind: str | None = None,
        action: str | None = None,
        context_words: list[str] | None = None,
        name: str | None = None,
    ) -> AIGatewayPiiTestResult:
        """Dry-run a candidate ``pattern`` against sample ``text``. Saves nothing,
        so — like :meth:`test_firewall_rules` — it takes NO ``idempotency_key``.

        It compiles with the SAME engine the data plane runs, so a pattern that
        passes here is one that will actually execute. Do NOT preview locally
        with :mod:`re`: Python's engine accepts lookahead, lookbehind and
        backreferences that the server refuses, so a local preview shows matches
        for a recognizer that can never run and then 400s on save.

        Returns ``{matched, matches: [{span, matched, replacement, entity_type}]}``
        — ``replacement`` is what the data plane would substitute for ``action``.
        """
        body: dict[str, Any] = {"pattern": pattern, "text": text}
        if kind is not None:
            body["kind"] = kind
        if action is not None:
            body["action"] = action
        if context_words is not None:
            body["context_words"] = context_words
        if name is not None:
            body["name"] = name
        return unwrap(await self._client.request(
            method="POST", path="/v1/ai-gateway/pii-recognizers/test", body=body
        ))

    async def get_pii_recognizer(self, recognizer_id: str) -> AIGatewayPiiRecognizer:
        return unwrap(await self._client.request(
            method="GET",
            path=f"/v1/ai-gateway/pii-recognizers/{quote(recognizer_id, safe='')}",
        ))

    async def update_pii_recognizer(
        self,
        recognizer_id: str,
        *,
        name: str | None = None,
        kind: str | None = None,
        pattern: str | None = None,
        context_words: list[str] | None = None,
        confidence: float | None = None,
        action: str | None = None,
        format: str | None = None,
        enabled: bool | None = None,
        idempotency_key: str | None = None,
    ) -> AIGatewayPiiRecognizer:
        """Update a recognizer. Every field is a partial of the create body.

        The server validates the MERGED state, not the patch, so
        ``action="whitelist"`` on its own is still checked against the STORED
        pattern — and can be refused because of it.
        """
        body: dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if kind is not None:
            body["kind"] = kind
        if pattern is not None:
            body["pattern"] = pattern
        if context_words is not None:
            body["context_words"] = context_words
        if confidence is not None:
            body["confidence"] = confidence
        if action is not None:
            body["action"] = action
        if format is not None:
            body["format"] = format
        if enabled is not None:
            body["enabled"] = enabled
        return unwrap(await self._client.request(
            method="PATCH",
            path=f"/v1/ai-gateway/pii-recognizers/{quote(recognizer_id, safe='')}",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def delete_pii_recognizer(
        self, recognizer_id: str, *, idempotency_key: str | None = None
    ) -> AIGatewayPiiDeleteResult:
        """Delete a recognizer. Returns ``{id, deleted: True}``.

        Refused with 409 ``recognizer_in_use`` while any PII policy still lists
        it — because an empty ``recognizer_ids`` means "every enabled
        recognizer", dropping the id would WIDEN the policy rather than shrink
        it. Remove it from each policy first, or
        :meth:`update_pii_recognizer` with ``enabled=False`` to mute it while
        keeping the definition.
        """
        return unwrap(await self._client.request(
            method="DELETE",
            path=f"/v1/ai-gateway/pii-recognizers/{quote(recognizer_id, safe='')}",
            idempotency_key=idempotency_key,
        ))

    # ── Usage ─────────────────────────────────────────────────────────────────

    async def usage(
        self, *, period: str | None = None, agent_id: str | None = None
    ) -> AIGatewayUsage:
        """Cost + tokens by model over ``period`` (``"7d"`` | ``"30d"`` | ``"90d"``,
        default 30d). Scope to a single agent with ``agent_id``."""
        query: dict[str, Any] = {}
        if period is not None:
            query["period"] = period
        if agent_id is not None:
            query["agent_id"] = agent_id
        return unwrap(await self._client.request(
            method="GET", path="/v1/ai-gateway/usage", query=query or None
        ))

    async def export_usage(
        self,
        *,
        group_by: str,
        period: str | None = None,
        agent_id: str | None = None,
    ) -> AIGatewayUsageExport:
        """FinOps export: aggregated spend grouped by ``group_by`` (one of
        ``"user"`` | ``"team"`` | ``"agent"`` | ``"model"`` | ``"provider"`` |
        ``"tag:<key>"``) over ``period`` (``"7d"`` | ``"30d"`` | ``"90d"``,
        default 30d), optionally scoped to a single agent. Returns the JSON rows.
        """
        query: dict[str, Any] = {"group_by": group_by, "format": "json"}
        if period is not None:
            query["period"] = period
        if agent_id is not None:
            query["agent_id"] = agent_id
        return unwrap(await self._client.request(
            method="GET", path="/v1/ai-gateway/usage/export", query=query
        ))
