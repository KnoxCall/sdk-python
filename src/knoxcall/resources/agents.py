"""Agents resource — mirrors agents.ts."""

from __future__ import annotations
from typing import TYPE_CHECKING
from urllib.parse import quote

from .._envelope import unwrap
from ..types import Agent, AgentCreateResult, AgentRevokeResult, TamperEvent

if TYPE_CHECKING:
    from ..core import APIClient


class AgentsResource:
    def __init__(self, client: "APIClient") -> None:
        self._client = client

    async def list(self) -> list[Agent]:
        """List agents (bare array — not paginated)."""
        return unwrap(await self._client.request(method="GET", path="/v1/agents"))

    async def create(
        self, *, name: str, idempotency_key: str | None = None
    ) -> AgentCreateResult:
        """Register an agent. ``agent_secret`` is returned once — save it immediately.

        Requires an explicit `agent:create` policy grant: a wildcard (`*:*`) rule
        does not satisfy it, including the `legacy_admin` policy every key created
        before 2026-06-30 still carries. The seeded Key - Infrastructure and Key -
        Editor roles name the action literally and are unaffected. Without it the
        call returns 403. Every successful mint also emails the account's owners.
        """
        return unwrap(await self._client.request(
            method="POST", path="/v1/agents", body={"name": name}, idempotency_key=idempotency_key
        ))

    async def revoke(
        self, agent_id: str, *, idempotency_key: str | None = None
    ) -> AgentRevokeResult:
        return unwrap(await self._client.request(
            method="DELETE",
            path=f"/v1/agents/{quote(agent_id, safe='')}",
            idempotency_key=idempotency_key,
        ))

    async def get_tamper_events(self, agent_id: str) -> list[TamperEvent]:
        """List tamper events for an agent (bare array, most recent 50)."""
        return unwrap(await self._client.request(
            method="GET", path=f"/v1/agents/{quote(agent_id, safe='')}/tamper-events"
        ))
