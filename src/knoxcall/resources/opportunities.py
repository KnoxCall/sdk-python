"""Opportunities resource — mirrors opportunities.ts.

Promotion opportunities: "we detected outbound API usage → create a route",
from two sources (agent_monitor + gateway_traffic). :meth:`list` refreshes
gateway detection on read; :meth:`accept` promotes a suggestion to a durable
route + secret binding.
"""

from __future__ import annotations
from typing import Any, AsyncIterator, Literal, TYPE_CHECKING
from urllib.parse import quote

from .._envelope import unwrap
from ..types import (
    AcceptOpportunityResult,
    Opportunity,
    OpportunityDismissResult,
    OpportunityPage,
)

if TYPE_CHECKING:
    from ..core import APIClient

OpportunityStatus = Literal["pending", "snoozed", "onboarded", "dismissed"]


class OpportunitiesResource:
    def __init__(self, client: "APIClient") -> None:
        self._client = client

    async def list(
        self,
        *,
        status: OpportunityStatus | None = None,
        page: int | None = None,
        per_page: int | None = None,
    ) -> OpportunityPage:
        """List promotion opportunities (refreshes gateway detection on read)."""
        query: dict[str, Any] = {}
        if status is not None:
            query["status"] = status
        if page is not None:
            query["page"] = page
        if per_page is not None:
            query["per_page"] = per_page
        return await self._client.request(
            method="GET", path="/v1/opportunities", query=query or None
        )

    async def iterate(
        self,
        *,
        status: OpportunityStatus | None = None,
        page: int = 1,
        per_page: int | None = None,
    ) -> AsyncIterator[Opportunity]:
        current = page
        while True:
            result = await self.list(status=status, page=current, per_page=per_page)
            data = result.get("data") or []
            for o in data:
                yield o
            meta = result.get("meta") or {}
            if not data or current >= int(meta.get("total_pages") or 0):
                return
            current += 1

    async def accept(
        self,
        opportunity_id: str,
        *,
        collection_name: str | None = None,
        environment: str | None = None,
        secret: str | None = None,
        header_name: str | None = None,
        value_prefix: str | None = None,
        idempotency_key: str | None = None,
    ) -> AcceptOpportunityResult:
        """Promote a gateway suggestion to a durable route + secret binding.

        With no fields, the suggestion's own collection/environment are used and
        an escrowed wrap credential for the destination host is auto-bound. The
        injected header defaults to ``Authorization`` with a ``"Bearer "`` prefix.
        """
        body: dict[str, Any] = {}
        for k, v in (
            ("collection_name", collection_name),
            ("environment", environment),
            ("secret", secret),
            ("header_name", header_name),
            ("value_prefix", value_prefix),
        ):
            if v is not None:
                body[k] = v
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/opportunities/{quote(opportunity_id, safe='')}/accept",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def dismiss(
        self, opportunity_id: str, *, idempotency_key: str | None = None
    ) -> OpportunityDismissResult:
        """Dismiss a pending suggestion."""
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/opportunities/{quote(opportunity_id, safe='')}/dismiss",
            idempotency_key=idempotency_key,
        ))
