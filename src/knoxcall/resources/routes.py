"""Routes resource — mirrors routes.ts."""

from __future__ import annotations
from typing import Any, AsyncIterator, TYPE_CHECKING
from urllib.parse import quote

from .._envelope import unwrap
from ..types import (
    Route,
    RouteAction,
    RouteDetail,
    RouteEnvironmentConfig,
    RouteEnvironmentListItem,
    RouteFull,
    RouteLogPage,
    RoutePage,
)

if TYPE_CHECKING:
    from ..core import APIClient


class RoutesResource:
    def __init__(self, client: "APIClient") -> None:
        self._client = client

    async def list(self, *, page: int | None = None, per_page: int | None = None) -> RoutePage:
        """List routes (paginated — server default 20/page, cap 100)."""
        query: dict[str, Any] = {}
        if page is not None:
            query["page"] = page
        if per_page is not None:
            query["per_page"] = per_page
        return await self._client.request(method="GET", path="/v1/routes", query=query or None)

    async def iterate(
        self, *, page: int = 1, per_page: int | None = None
    ) -> AsyncIterator[Route]:
        """Yield every route, walking pages until ``meta.total_pages``."""
        current = page
        while True:
            result = await self.list(page=current, per_page=per_page)
            data = result.get("data") or []
            for r in data:
                yield r
            meta = result.get("meta") or {}
            if not data or current >= int(meta.get("total_pages") or 0):
                return
            current += 1

    async def get(self, route_id: str) -> RouteDetail:
        return unwrap(await self._client.request(
            method="GET", path=f"/v1/routes/{quote(route_id, safe='')}"
        ))

    async def create(
        self,
        *,
        name: str,
        target_base_url: str,
        idempotency_key: str | None = None,
    ) -> RouteFull:
        return unwrap(await self._client.request(
            method="POST",
            path="/v1/routes",
            body={"name": name, "target_base_url": target_base_url},
            idempotency_key=idempotency_key,
        ))

    async def update(
        self,
        route_id: str,
        *,
        name: str | None = None,
        target_base_url: str | None = None,
        enabled: bool | None = None,
        requires_clients: bool | None = None,
        intercept_enabled: bool | None = None,
        idempotency_key: str | None = None,
    ) -> RouteFull:
        body: dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if target_base_url is not None:
            body["target_base_url"] = target_base_url
        if enabled is not None:
            body["enabled"] = enabled
        if requires_clients is not None:
            body["requires_clients"] = requires_clients
        if intercept_enabled is not None:
            body["intercept_enabled"] = intercept_enabled
        return unwrap(await self._client.request(
            method="PATCH",
            path=f"/v1/routes/{quote(route_id, safe='')}",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def delete(self, route_id: str, *, idempotency_key: str | None = None) -> None:
        await self._client.request(
            method="DELETE",
            path=f"/v1/routes/{quote(route_id, safe='')}",
            idempotency_key=idempotency_key,
        )

    async def get_logs(
        self, route_id: str, *, page: int | None = None, per_page: int | None = None
    ) -> RouteLogPage:
        query: dict[str, Any] = {}
        if page is not None:
            query["page"] = page
        if per_page is not None:
            query["per_page"] = per_page
        return await self._client.request(
            method="GET",
            path=f"/v1/routes/{quote(route_id, safe='')}/logs",
            query=query or None,
        )

    async def list_environments(self, route_id: str) -> list[RouteEnvironmentListItem]:
        return unwrap(await self._client.request(
            method="GET", path=f"/v1/routes/{quote(route_id, safe='')}/environments"
        ))

    async def upsert_environment(
        self,
        route_id: str,
        env_name: str,
        *,
        target_base_url: str | None = None,
        inject_headers: dict[str, Any] | None = None,
        inject_body: dict[str, Any] | None = None,
        # DEPRECATED: never applied to any request, and this endpoint never even
        # read it -- the handler did not destructure the field, so it was silently
        # dropped on every call. It is now refused with 400 (wave-2 row 2-273);
        # an empty list is still accepted as a no-op. Use {{secret_id:<uuid>}} /
        # {{secret:<name>}} placeholders in the request body your client sends.
        # Retained so the API's own explanatory refusal reaches the caller.
        injection_rules: list[Any] | None = None,
        ip_allowlist: list[str] | None = None,
        require_signature: bool | None = None,
        signature_tolerance_sec: int | None = None,
        rate_limit_enabled: bool | None = None,
        rate_limit_requests: int | None = None,
        rate_limit_window_sec: int | None = None,
        rate_limit_burst: int | None = None,
        allowed_methods: list[str] | None = None,
        intercept_enabled: bool | None = None,
        idempotency_key: str | None = None,
    ) -> RouteEnvironmentConfig:
        body: dict[str, Any] = {}
        if intercept_enabled is not None:
            body["intercept_enabled"] = intercept_enabled
        if target_base_url is not None:
            body["target_base_url"] = target_base_url
        if inject_headers is not None:
            body["inject_headers_json"] = inject_headers
        if inject_body is not None:
            body["inject_body_json"] = inject_body
        if injection_rules is not None:
            body["injection_rules"] = injection_rules
        if ip_allowlist is not None:
            body["ip_allowlist"] = ip_allowlist
        if require_signature is not None:
            body["require_signature"] = require_signature
        if signature_tolerance_sec is not None:
            body["signature_tolerance_sec"] = signature_tolerance_sec
        if rate_limit_enabled is not None:
            body["rate_limit_enabled"] = rate_limit_enabled
        if rate_limit_requests is not None:
            body["rate_limit_requests"] = rate_limit_requests
        if rate_limit_window_sec is not None:
            body["rate_limit_window_sec"] = rate_limit_window_sec
        if rate_limit_burst is not None:
            body["rate_limit_burst"] = rate_limit_burst
        if allowed_methods is not None:
            body["allowed_methods"] = allowed_methods
        return unwrap(await self._client.request(
            method="PUT",
            path=f"/v1/routes/{quote(route_id, safe='')}/environments/{quote(env_name, safe='')}",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def delete_environment(
        self, route_id: str, env_name: str, *, idempotency_key: str | None = None
    ) -> None:
        await self._client.request(
            method="DELETE",
            path=f"/v1/routes/{quote(route_id, safe='')}/environments/{quote(env_name, safe='')}",
            idempotency_key=idempotency_key,
        )

    # ── Relay field-actions (declarative field-level encrypt/decrypt/tokenize) ──

    async def list_actions(self, route_id: str) -> list[RouteAction]:
        return unwrap(await self._client.request(
            method="GET", path=f"/v1/routes/{quote(route_id, safe='')}/actions"
        ))

    async def create_action(
        self,
        route_id: str,
        *,
        direction: str,
        action: str,
        selectors: list[str],
        key_name: str | None = None,
        data_role: str | None = None,
        content_type: str | None = None,
        sort_order: int | None = None,
        idempotency_key: str | None = None,
    ) -> RouteAction:
        """Create a field-action.

        ``direction``: ``"request"`` | ``"response"``;
        ``action``: ``"encrypt"`` | ``"decrypt"`` | ``"tokenize"`` | ``"detokenize"``.
        """
        body: dict[str, Any] = {"direction": direction, "action": action, "selectors": selectors}
        if key_name is not None:
            body["key_name"] = key_name
        if data_role is not None:
            body["data_role"] = data_role
        if content_type is not None:
            body["content_type"] = content_type
        if sort_order is not None:
            body["sort_order"] = sort_order
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/routes/{quote(route_id, safe='')}/actions",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def delete_action(
        self, route_id: str, action_id: str, *, idempotency_key: str | None = None
    ) -> None:
        await self._client.request(
            method="DELETE",
            path=f"/v1/routes/{quote(route_id, safe='')}/actions/{quote(action_id, safe='')}",
            idempotency_key=idempotency_key,
        )
