"""Vaults resource — mirrors vaults.ts (data tokenization)."""

from __future__ import annotations
from typing import Any, AsyncIterator, TYPE_CHECKING
from urllib.parse import quote

from .._envelope import unwrap
from ..types import (
    BulkTokenizeResult,
    DetokenizeResult,
    DeleteResult,
    RotateResult,
    TokenUpdateResult,
    Vault,
    VaultDetail,
    VaultPage,
    VaultToken,
    VaultTokenListItem,
    VaultTokenPage,
)

if TYPE_CHECKING:
    from ..core import APIClient


class VaultsResource:
    def __init__(self, client: "APIClient") -> None:
        self._client = client

    # ── Vault CRUD ────────────────────────────────────────────────────────────

    async def list(self, *, page: int | None = None, per_page: int | None = None) -> VaultPage:
        """List vaults (paginated — server default 20/page, cap 100)."""
        query: dict[str, Any] = {}
        if page is not None:
            query["page"] = page
        if per_page is not None:
            query["per_page"] = per_page
        return await self._client.request(method="GET", path="/v1/vaults", query=query or None)

    async def iterate(
        self, *, page: int = 1, per_page: int | None = None
    ) -> AsyncIterator[Vault]:
        """Yield every vault, walking pages until ``meta.total_pages``."""
        current = page
        while True:
            result = await self.list(page=current, per_page=per_page)
            data = result.get("data") or []
            for v in data:
                yield v
            meta = result.get("meta") or {}
            if not data or current >= int(meta.get("total_pages") or 0):
                return
            current += 1

    async def get(self, name_or_id: str) -> VaultDetail:
        return unwrap(await self._client.request(
            method="GET", path=f"/v1/vaults/{quote(name_or_id, safe='')}"
        ))

    async def create(
        self,
        *,
        name: str,
        token_format: str | None = None,
        default_ttl_seconds: int | None = None,
        description: str | None = None,
        metadata: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> Vault:
        body: dict[str, Any] = {"name": name}
        if token_format is not None:
            body["token_format"] = token_format
        if default_ttl_seconds is not None:
            body["default_ttl_seconds"] = default_ttl_seconds
        if description is not None:
            body["description"] = description
        if metadata is not None:
            body["metadata_jsonb"] = metadata
        return unwrap(await self._client.request(
            method="POST", path="/v1/vaults", body=body, idempotency_key=idempotency_key
        ))

    async def update(
        self,
        name_or_id: str,
        *,
        default_ttl_seconds: int | None = None,
        description: str | None = None,
        enabled: bool | None = None,
        metadata: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> Vault:
        body: dict[str, Any] = {}
        if default_ttl_seconds is not None:
            body["default_ttl_seconds"] = default_ttl_seconds
        if description is not None:
            body["description"] = description
        if enabled is not None:
            body["enabled"] = enabled
        if metadata is not None:
            body["metadata_jsonb"] = metadata
        return unwrap(await self._client.request(
            method="PATCH",
            path=f"/v1/vaults/{quote(name_or_id, safe='')}",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def delete(
        self, name_or_id: str, *, idempotency_key: str | None = None
    ) -> DeleteResult:
        """Cryptographically shred the vault and all its tokens. Returns
        ``{"deleted": True}``."""
        return unwrap(await self._client.request(
            method="DELETE",
            path=f"/v1/vaults/{quote(name_or_id, safe='')}",
            idempotency_key=idempotency_key,
        ))

    async def rotate(
        self, name_or_id: str, *, idempotency_key: str | None = None
    ) -> RotateResult:
        """Rotate the vault's crypto key to a new version."""
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/vaults/{quote(name_or_id, safe='')}/rotate",
            body={},
            idempotency_key=idempotency_key,
        ))

    # ── Token operations ──────────────────────────────────────────────────────

    async def tokenize(
        self,
        name_or_id: str,
        *,
        value: str,
        metadata: dict[str, Any] | None = None,
        ttl_seconds: int | None = None,
        card_exp_month: int | None = None,
        card_exp_year: int | None = None,
        idempotency_key: str | None = None,
    ) -> VaultToken:
        """Tokenize a single value. Returns ``token``, ``id``, ``expires_at``.

        ``card_exp_month`` / ``card_exp_year`` are the CARD's own expiry, for a
        ``pan`` vault only -- not ``ttl_seconds``, which is how long the TOKEN
        lives. Both or neither; the year is four digits (2029, never 29).
        Supplying them subscribes the token to the ``vault.token.expiring``
        webhook, emitted 60 and 30 days before the card expires. Offering them
        to a non-``pan`` vault raises a ``validation_error``.
        """
        body: dict[str, Any] = {"value": value}
        if metadata is not None:
            body["metadata"] = metadata
        if ttl_seconds is not None:
            body["ttl_seconds"] = ttl_seconds
        if card_exp_month is not None:
            body["card_exp_month"] = card_exp_month
        if card_exp_year is not None:
            body["card_exp_year"] = card_exp_year
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/vaults/{quote(name_or_id, safe='')}/tokens",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def bulk_tokenize(
        self,
        name_or_id: str,
        *,
        values: list[dict[str, Any]],
        idempotency_key: str | None = None,
    ) -> BulkTokenizeResult:
        """Tokenize up to 1000 values in a single request.

        Each item in ``values`` must have a ``value`` key. Optional keys:
        ``metadata`` (dict), ``ttl_seconds`` (int), and -- for a ``pan`` vault --
        ``card_exp_month`` / ``card_exp_year`` (the CARD's own expiry, both or
        neither). A refusal names the offending index and rolls the whole batch
        back; nothing is stored.
        """
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/vaults/{quote(name_or_id, safe='')}/tokens/bulk",
            body={"values": values},
            idempotency_key=idempotency_key,
        ))

    async def list_tokens(
        self,
        name_or_id: str,
        *,
        page: int | None = None,
        per_page: int | None = None,
    ) -> VaultTokenPage:
        """List vault tokens (paginated; metadata only — values are never returned in lists)."""
        query: dict[str, Any] = {}
        if page is not None:
            query["page"] = page
        if per_page is not None:
            query["per_page"] = per_page
        return await self._client.request(
            method="GET",
            path=f"/v1/vaults/{quote(name_or_id, safe='')}/tokens",
            query=query or None,
        )

    async def iterate_tokens(
        self,
        name_or_id: str,
        *,
        page: int = 1,
        per_page: int | None = None,
    ) -> AsyncIterator[VaultTokenListItem]:
        """Yield every token in the vault, walking pages until ``meta.total_pages``."""
        current = page
        while True:
            result = await self.list_tokens(name_or_id, page=current, per_page=per_page)
            data = result.get("data") or []
            for t in data:
                yield t
            meta = result.get("meta") or {}
            if not data or current >= int(meta.get("total_pages") or 0):
                return
            current += 1

    async def detokenize(self, name_or_id: str, id_or_token: str) -> DetokenizeResult:
        """Retrieve the plaintext value for a token."""
        return unwrap(await self._client.request(
            method="GET",
            path=f"/v1/vaults/{quote(name_or_id, safe='')}/tokens/{quote(id_or_token, safe='')}",
        ))

    async def update_token(
        self,
        name_or_id: str,
        id_or_token: str,
        *,
        metadata: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> TokenUpdateResult:
        return unwrap(await self._client.request(
            method="PATCH",
            path=f"/v1/vaults/{quote(name_or_id, safe='')}/tokens/{quote(id_or_token, safe='')}",
            body={"metadata": metadata},
            idempotency_key=idempotency_key,
        ))

    async def delete_token(
        self,
        name_or_id: str,
        id_or_token: str,
        *,
        idempotency_key: str | None = None,
    ) -> DeleteResult:
        """Delete a token. Returns ``{"deleted": True}``."""
        return unwrap(await self._client.request(
            method="DELETE",
            path=f"/v1/vaults/{quote(name_or_id, safe='')}/tokens/{quote(id_or_token, safe='')}",
            idempotency_key=idempotency_key,
        ))
