"""Clients resource — mirrors clients.ts."""

from __future__ import annotations
from typing import Any, AsyncIterator, TYPE_CHECKING
from urllib.parse import quote

from .._envelope import unwrap
from ..types import Client, ClientCredential, ClientDetail, ClientFull, ClientPage

if TYPE_CHECKING:
    from ..core import APIClient


class ClientsResource:
    def __init__(self, client: "APIClient") -> None:
        self._client = client

    async def list(self, *, page: int | None = None, per_page: int | None = None) -> ClientPage:
        """List clients (paginated — server default 20/page, cap 100)."""
        query: dict[str, Any] = {}
        if page is not None:
            query["page"] = page
        if per_page is not None:
            query["per_page"] = per_page
        return await self._client.request(method="GET", path="/v1/clients", query=query or None)

    async def iterate(
        self, *, page: int = 1, per_page: int | None = None
    ) -> AsyncIterator[Client]:
        """Yield every client, walking pages until ``meta.total_pages``."""
        current = page
        while True:
            result = await self.list(page=current, per_page=per_page)
            data = result.get("data") or []
            for c in data:
                yield c
            meta = result.get("meta") or {}
            if not data or current >= int(meta.get("total_pages") or 0):
                return
            current += 1

    async def get(self, client_id: str) -> ClientDetail:
        return unwrap(await self._client.request(
            method="GET", path=f"/v1/clients/{quote(client_id, safe='')}"
        ))

    async def create(
        self,
        *,
        name: str,
        ip_address: str | None = None,
        type: str = "server",
        description: str | None = None,
        idempotency_key: str | None = None,
    ) -> ClientFull:
        body: dict[str, Any] = {"name": name, "type": type}
        if ip_address is not None:
            body["ip_address"] = ip_address
        if description is not None:
            body["description"] = description
        return unwrap(await self._client.request(
            method="POST", path="/v1/clients", body=body, idempotency_key=idempotency_key
        ))

    async def update(
        self,
        client_id: str,
        *,
        name: str | None = None,
        ip_address: str | None = None,
        description: str | None = None,
        enabled: bool | None = None,
        idempotency_key: str | None = None,
    ) -> ClientFull:
        body: dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if ip_address is not None:
            body["ip_address"] = ip_address
        if description is not None:
            body["description"] = description
        if enabled is not None:
            body["enabled"] = enabled
        return unwrap(await self._client.request(
            method="PATCH",
            path=f"/v1/clients/{quote(client_id, safe='')}",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def delete(self, client_id: str, *, idempotency_key: str | None = None) -> None:
        await self._client.request(
            method="DELETE",
            path=f"/v1/clients/{quote(client_id, safe='')}",
            idempotency_key=idempotency_key,
        )

    # ── Credentials sub-resource ──────────────────────────────────────────────
    # kind: "ip" | "mtls_thumbprint" | etc. — check API docs for valid kinds.

    async def list_credentials(self, client_id: str) -> list[ClientCredential]:
        """List a client's credentials (bare array — not paginated)."""
        return unwrap(await self._client.request(
            method="GET", path=f"/v1/clients/{quote(client_id, safe='')}/credentials"
        ))

    async def create_credential(
        self,
        client_id: str,
        *,
        kind: str,
        data: dict[str, Any],
        label: str | None = None,
        idempotency_key: str | None = None,
    ) -> ClientCredential:
        """Create a credential. For mTLS ``{"mode": "issue"}`` the one-shot
        ``reveal`` field carries the issued PEMs — save them immediately."""
        body: dict[str, Any] = {"kind": kind, "data": data}
        if label is not None:
            body["label"] = label
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/clients/{quote(client_id, safe='')}/credentials",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def update_credential(
        self,
        client_id: str,
        credential_id: str,
        *,
        enabled: bool | None = None,
        label: str | None = None,
        idempotency_key: str | None = None,
    ) -> ClientCredential:
        body: dict[str, Any] = {}
        if enabled is not None:
            body["enabled"] = enabled
        if label is not None:
            body["label"] = label
        return unwrap(await self._client.request(
            method="PATCH",
            path=f"/v1/clients/{quote(client_id, safe='')}/credentials/{quote(credential_id, safe='')}",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def delete_credential(
        self,
        client_id: str,
        credential_id: str,
        *,
        idempotency_key: str | None = None,
    ) -> None:
        await self._client.request(
            method="DELETE",
            path=f"/v1/clients/{quote(client_id, safe='')}/credentials/{quote(credential_id, safe='')}",
            idempotency_key=idempotency_key,
        )
