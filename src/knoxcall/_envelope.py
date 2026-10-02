"""Server response-envelope helper.

The server wraps every JSON success response in ``{"data": ..., "meta": ...}``
(see the /v1 response-shape catalog). The client core's ``request()`` stays
envelope-agnostic; unwrapping lives in the resource layer via this helper.

Paginated list methods do NOT unwrap — they return the full typed page
``{data: [...], meta: {total, page, per_page, total_pages, request_id}}``.
"""

from __future__ import annotations

from typing import Any


def unwrap(resp: Any) -> Any:
    """Return the ``data`` member of a ``{data, meta}`` server envelope.

    Non-dict responses (raw PEM / CRL text) pass through untouched, as do
    dicts without a ``data`` member (defensive — the server always wraps).
    """
    if isinstance(resp, dict) and "data" in resp:
        return resp["data"]
    return resp
