"""Request Logs resource — mirrors logs.ts.

Distinct from ``audit_logs``, which is the CHANGE log (who edited what). This is
the record of requests that went THROUGH the proxy, and ``proof()`` is the
evidence that a given entry existed, unaltered, when it was anchored.
"""

from __future__ import annotations
from typing import Any, AsyncIterator, TYPE_CHECKING

from ..types import RequestLog, RequestLogPage, RequestLogProof

if TYPE_CHECKING:
    from ..core import APIClient


class LogsResource:
    def __init__(self, client: "APIClient") -> None:
        self._client = client

    async def list(
        self,
        *,
        cursor: str | None = None,
        limit: int | None = None,
        route_id: str | None = None,
        status_code: int | None = None,
    ) -> RequestLogPage:
        """One page of the request log feed.

        Keyset, not offset: ordering is ascending ``cursor`` and stable across
        calls. Delivery is AT LEAST ONCE — dedupe on ``request_id``.
        ``meta["next_cursor"]`` is OPAQUE; pass it back verbatim rather than
        parsing it. ``None`` means the feed is drained to the watermark, NOT
        that it has ended — poll again later with your last non-null cursor.
        """
        query: dict[str, Any] = {}
        if cursor is not None:
            query["cursor"] = cursor
        if limit is not None:
            query["limit"] = limit
        if route_id is not None:
            query["route_id"] = route_id
        if status_code is not None:
            query["status_code"] = status_code
        return await self._client.request(
            method="GET", path="/v1/logs", query=query or None
        )

    async def iterate(
        self,
        *,
        cursor: str | None = None,
        limit: int | None = None,
        route_id: str | None = None,
        status_code: int | None = None,
    ) -> AsyncIterator[RequestLog]:
        """Walk the feed until it is drained to the watermark.

        Terminates on ``next_cursor is None`` rather than polling forever — a
        generator that blocked would be unusable from a batch job. To keep
        following the feed, call again later with the last cursor you saw.
        """
        current = cursor
        while True:
            page = await self.list(
                cursor=current, limit=limit, route_id=route_id, status_code=status_code
            )
            for row in page.get("data") or []:
                yield row
            nxt = (page.get("meta") or {}).get("next_cursor")
            if nxt is None:
                return
            current = nxt

    async def get(self, request_id: str) -> RequestLog:
        """Fetch one request by its ``request_id`` (the ``X-Request-Id`` header)."""
        result = await self._client.request(
            method="GET", path=f"/v1/logs/{request_id}"
        )
        return result["data"]

    async def proof(self, request_id: str) -> RequestLogProof:
        """Merkle inclusion proof for one request.

        Returns for every outcome — read ``anchored`` and ``verified`` rather
        than catching. ``verified`` False with ``reason == "range_incomplete"``
        is the expected result for an old entry whose anchored range has since
        been trimmed by retention, and is NOT a sign of tampering;
        ``"root_mismatch"`` is.
        """
        result = await self._client.request(
            method="GET", path=f"/v1/logs/{request_id}/proof"
        )
        return result["data"]
