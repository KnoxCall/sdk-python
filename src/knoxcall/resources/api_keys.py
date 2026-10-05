"""API Keys resource — mirrors api-keys.ts."""

from __future__ import annotations
from typing import Any, AsyncIterator, TYPE_CHECKING
from urllib.parse import quote

from .._envelope import unwrap
from ..types import ApiKey, ApiKeyCreateResult, ApiKeyPage, ApiKeyRevokeResult, Role, RolePage

if TYPE_CHECKING:
    from ..core import APIClient


class ApiKeysResource:
    def __init__(self, client: "APIClient") -> None:
        self._client = client

    async def list(self, *, page: int | None = None, per_page: int | None = None) -> ApiKeyPage:
        """List API keys (paginated — server default 20/page, cap 100)."""
        query: dict[str, Any] = {}
        if page is not None:
            query["page"] = page
        if per_page is not None:
            query["per_page"] = per_page
        return await self._client.request(method="GET", path="/v1/api-keys", query=query or None)

    async def iterate(
        self, *, page: int = 1, per_page: int | None = None
    ) -> AsyncIterator[ApiKey]:
        """Yield every API key, walking pages until ``meta.total_pages``."""
        current = page
        while True:
            result = await self.list(page=current, per_page=per_page)
            data = result.get("data") or []
            for k in data:
                yield k
            meta = result.get("meta") or {}
            if not data or current >= int(meta.get("total_pages") or 0):
                return
            current += 1

    async def create(
        self,
        *,
        name: str,
        rate_limit_requests: int | None = None,
        rate_limit_window_sec: int | None = None,
        role_ids: list[str] | None = None,
        idempotency_key: str | None = None,
    ) -> ApiKeyCreateResult:
        """Create an API key. ``api_key`` is returned once — save it immediately.

        ``role_ids`` attaches permission roles in the SAME transaction as the key.
        Only the SEEDED key roles are accepted (``seeded: True`` — Key — Invoke,
        Key — Read-only, Key — Editor, Key — Infrastructure); any other role is
        refused ``403 forbidden``, because custom roles are being retired.
        Discover them with ``client.roles.list(subject_kind="api_key")`` and
        filter on ``seeded``. A key created with no role is default-denied on
        every policy-gated endpoint.

        A key can never mint a key more privileged than itself: if a requested
        role grants something this credential does not hold, the server answers
        ``403 privilege_escalation`` (a :class:`PermissionDeniedError` whose
        ``code`` is ``"privilege_escalation"``) and names the offending grant
        verbatim.
        """
        body: dict[str, Any] = {"name": name}
        if rate_limit_requests is not None:
            body["rate_limit_requests"] = rate_limit_requests
        if rate_limit_window_sec is not None:
            body["rate_limit_window_sec"] = rate_limit_window_sec
        if role_ids is not None:
            body["role_ids"] = role_ids
        return unwrap(await self._client.request(
            method="POST", path="/v1/api-keys", body=body, idempotency_key=idempotency_key
        ))

    async def revoke(self, key_id: str, *, idempotency_key: str | None = None) -> ApiKeyRevokeResult:
        return unwrap(await self._client.request(
            method="DELETE",
            path=f"/v1/api-keys/{quote(key_id, safe='')}",
            idempotency_key=idempotency_key,
        ))


class RolesResource:
    """Read-only role catalog.

    ``/v1`` exposes it so ``api_keys.create(role_ids=...)`` can be written in
    code instead of by copying a UUID out of a browser URL bar. Only seeded key
    roles (``seeded: True``) are accepted in ``role_ids``. Custom roles are
    being retired: none can be created, and the list still returns any a tenant
    already has (``seeded: False``) — filter on ``seeded``.
    """

    def __init__(self, client: "APIClient") -> None:
        self._client = client

    async def list(
        self,
        *,
        subject_kind: str | None = None,
        page: int | None = None,
        per_page: int | None = None,
    ) -> RolePage:
        """List roles (paginated). ``subject_kind="api_key"`` filters to key-audience roles.

        Of those, only the ``seeded`` ones are accepted in ``role_ids``.
        """
        query: dict[str, Any] = {}
        if subject_kind is not None:
            query["subject_kind"] = subject_kind
        if page is not None:
            query["page"] = page
        if per_page is not None:
            query["per_page"] = per_page
        return await self._client.request(method="GET", path="/v1/roles", query=query or None)

    async def iterate(
        self, *, subject_kind: str | None = None, page: int = 1, per_page: int | None = None
    ) -> AsyncIterator[Role]:
        """Yield every role, walking pages until ``meta.total_pages``."""
        current = page
        while True:
            result = await self.list(subject_kind=subject_kind, page=current, per_page=per_page)
            data = result.get("data") or []
            for r in data:
                yield r
            meta = result.get("meta") or {}
            if not data or current >= int(meta.get("total_pages") or 0):
                return
            current += 1
