"""Environments resource — mirrors environments.ts."""

from __future__ import annotations
from typing import Any, TYPE_CHECKING
from urllib.parse import quote

from .._envelope import unwrap
from ..types import Environment, EnvironmentFull

if TYPE_CHECKING:
    from ..core import APIClient


class EnvironmentsResource:
    def __init__(self, client: "APIClient") -> None:
        self._client = client

    async def list(self) -> list[Environment]:
        """List environments (bare array — not paginated)."""
        return unwrap(await self._client.request(method="GET", path="/v1/environments"))

    async def create(
        self,
        *,
        name: str,
        display_name: str | None = None,
        description: str | None = None,
        color: str | None = None,
        is_default: bool | None = None,
        idempotency_key: str | None = None,
    ) -> EnvironmentFull:
        body: dict[str, Any] = {"name": name}
        if display_name is not None:
            body["display_name"] = display_name
        if description is not None:
            body["description"] = description
        if color is not None:
            body["color"] = color
        if is_default is not None:
            body["is_default"] = is_default
        return unwrap(await self._client.request(
            method="POST", path="/v1/environments", body=body, idempotency_key=idempotency_key
        ))

    async def update(
        self,
        env_id: str,
        *,
        name: str | None = None,
        display_name: str | None = None,
        description: str | None = None,
        color: str | None = None,
        is_default: bool | None = None,
        idempotency_key: str | None = None,
    ) -> EnvironmentFull:
        body: dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if display_name is not None:
            body["display_name"] = display_name
        if description is not None:
            body["description"] = description
        if color is not None:
            body["color"] = color
        if is_default is not None:
            body["is_default"] = is_default
        return unwrap(await self._client.request(
            method="PATCH",
            path=f"/v1/environments/{quote(env_id, safe='')}",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def delete(self, env_id: str, *, idempotency_key: str | None = None) -> None:
        await self._client.request(
            method="DELETE",
            path=f"/v1/environments/{quote(env_id, safe='')}",
            idempotency_key=idempotency_key,
        )
