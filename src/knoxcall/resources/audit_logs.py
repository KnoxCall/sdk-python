"""Audit Logs resource — mirrors audit-logs.ts."""

from __future__ import annotations
from typing import Any, AsyncIterator, TYPE_CHECKING

from ..types import AuditEventPage, AuditLogEntry, AuditLogPage

if TYPE_CHECKING:
    from ..core import APIClient


class AuditLogsResource:
    def __init__(self, client: "APIClient") -> None:
        self._client = client

    async def list(
        self,
        *,
        page: int | None = None,
        per_page: int | None = None,
        action: str | None = None,
        resource_type: str | None = None,
    ) -> AuditLogPage:
        """List audit logs (paginated — server default 20/page, cap 100)."""
        query: dict[str, Any] = {}
        if page is not None:
            query["page"] = page
        if per_page is not None:
            query["per_page"] = per_page
        if action is not None:
            query["action"] = action
        if resource_type is not None:
            query["resource_type"] = resource_type
        return await self._client.request(
            method="GET", path="/v1/audit-logs", query=query or None
        )

    async def iterate(
        self,
        *,
        page: int = 1,
        per_page: int | None = None,
        action: str | None = None,
        resource_type: str | None = None,
    ) -> AsyncIterator[AuditLogEntry]:
        """Yield every audit-log entry, walking pages until ``meta.total_pages``."""
        current = page
        while True:
            result = await self.list(
                page=current, per_page=per_page, action=action, resource_type=resource_type
            )
            data = result.get("data") or []
            for entry in data:
                yield entry
            meta = result.get("meta") or {}
            if not data or current >= int(meta.get("total_pages") or 0):
                return
            current += 1

    async def events(
        self,
        *,
        cursor: str | None = None,
        limit: int | None = None,
        action: str | None = None,
        action_prefix: str | None = None,
        resource_type: str | None = None,
    ) -> AuditEventPage:
        """One page of the keyset audit event feed — the endpoint a SIEM uses.

        ``list()`` is offset-paginated over ``created_at DESC``, which is right
        for a console and wrong for a feed: rows written while you page shift
        the offsets underneath you, so events are skipped or repeated with no
        way to tell which. This is ordered by a monotonic sequence and resumes
        from an opaque cursor.

        ``action`` is exact-match; ``action_prefix`` subscribes to a whole
        SURFACE — ``"ai_gateway."`` covers every AI-gateway action INCLUDING
        names added after your integration was built, which exact-match cannot.

        Delivery is AT LEAST ONCE — dedupe on ``id``. ``meta["next_cursor"]``
        is OPAQUE; pass it back verbatim.
        """
        query: dict[str, Any] = {}
        if cursor is not None:
            query["cursor"] = cursor
        if limit is not None:
            query["limit"] = limit
        if action is not None:
            query["action"] = action
        if action_prefix is not None:
            query["action_prefix"] = action_prefix
        if resource_type is not None:
            query["resource_type"] = resource_type
        return await self._client.request(
            method="GET", path="/v1/audit-logs/events", query=query or None
        )

    async def iterate_events(
        self,
        *,
        cursor: str | None = None,
        limit: int | None = None,
        action: str | None = None,
        action_prefix: str | None = None,
        resource_type: str | None = None,
    ) -> AsyncIterator[AuditLogEntry]:
        """Walk the event feed until it is drained to the watermark."""
        current = cursor
        while True:
            page = await self.events(
                cursor=current,
                limit=limit,
                action=action,
                action_prefix=action_prefix,
                resource_type=resource_type,
            )
            for row in page.get("data") or []:
                yield row
            nxt = (page.get("meta") or {}).get("next_cursor")
            if nxt is None:
                return
            current = nxt
