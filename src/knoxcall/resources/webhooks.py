"""Webhooks resource — mirrors webhooks.ts."""

from __future__ import annotations
import base64
import datetime as _dt
import hashlib
import hmac
import json
import time
from typing import Any, AsyncIterator, Mapping, TYPE_CHECKING
from urllib.parse import quote

from .._envelope import unwrap
from ..errors import WebhookSignatureVerificationError
from ..types import (
    Webhook,
    WebhookCreateResult,
    WebhookDetail,
    WebhookEvent,
    WebhookEventTypesData,
    WebhookLogPage,
    WebhookPage,
    WebhookTestResult,
    WebhookUpdateResult,
)

if TYPE_CHECKING:
    from ..core import APIClient


class WebhooksResource:
    def __init__(self, client: "APIClient") -> None:
        self._client = client

    async def list(self, *, page: int | None = None, per_page: int | None = None) -> WebhookPage:
        query: dict[str, Any] = {}
        if page is not None:
            query["page"] = page
        if per_page is not None:
            query["per_page"] = per_page
        return await self._client.request(method="GET", path="/v1/webhooks", query=query or None)

    async def iterate(
        self, *, page: int = 1, per_page: int | None = None
    ) -> AsyncIterator[Webhook]:
        current = page
        while True:
            result = await self.list(page=current, per_page=per_page)
            data = result.get("data") or []
            for w in data:
                yield w
            meta = result.get("meta") or {}
            if not data or current >= int(meta.get("total_pages") or 0):
                return
            current += 1

    async def get(self, webhook_id: str) -> WebhookDetail:
        return unwrap(await self._client.request(
            method="GET", path=f"/v1/webhooks/{quote(webhook_id, safe='')}"
        ))

    async def create(
        self,
        *,
        name: str,
        url: str,
        event_types: list[str],
        description: str | None = None,
        method: str | None = None,
        auth_type: str | None = None,
        auth_config: dict[str, Any] | None = None,
        request_headers: dict[str, str] | None = None,
        route_filter: str | None = None,
        include_request_body: bool | None = None,
        include_response_body: bool | None = None,
        include_headers: bool | None = None,
        timeout_seconds: int | None = None,
        retry_on_failure: bool | None = None,
        max_retries: int | None = None,
        enabled: bool | None = None,
        idempotency_key: str | None = None,
    ) -> WebhookCreateResult:
        """Create a webhook. ``secret_key`` is returned once — save it immediately."""
        body: dict[str, Any] = {"name": name, "url": url, "event_types": event_types}
        if description is not None:
            body["description"] = description
        if method is not None:
            body["method"] = method
        if auth_type is not None:
            body["auth_type"] = auth_type
        if auth_config is not None:
            body["auth_config"] = auth_config
        if request_headers is not None:
            body["request_headers"] = request_headers
        if route_filter is not None:
            body["route_filter"] = route_filter
        if include_request_body is not None:
            body["include_request_body"] = include_request_body
        if include_response_body is not None:
            body["include_response_body"] = include_response_body
        if include_headers is not None:
            body["include_headers"] = include_headers
        if timeout_seconds is not None:
            body["timeout_seconds"] = timeout_seconds
        if retry_on_failure is not None:
            body["retry_on_failure"] = retry_on_failure
        if max_retries is not None:
            body["max_retries"] = max_retries
        if enabled is not None:
            body["enabled"] = enabled
        return unwrap(await self._client.request(
            method="POST", path="/v1/webhooks", body=body, idempotency_key=idempotency_key
        ))

    async def update(
        self,
        webhook_id: str,
        *,
        name: str | None = None,
        url: str | None = None,
        event_types: list[str] | None = None,
        description: str | None = None,
        auth_type: str | None = None,
        auth_config: dict[str, Any] | None = None,
        request_headers: dict[str, str] | None = None,
        route_filter: str | None = None,
        include_request_body: bool | None = None,
        include_response_body: bool | None = None,
        include_headers: bool | None = None,
        timeout_seconds: int | None = None,
        retry_on_failure: bool | None = None,
        max_retries: int | None = None,
        enabled: bool | None = None,
        idempotency_key: str | None = None,
    ) -> WebhookUpdateResult:
        body: dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if url is not None:
            body["url"] = url
        if event_types is not None:
            body["event_types"] = event_types
        if description is not None:
            body["description"] = description
        if auth_type is not None:
            body["auth_type"] = auth_type
        if auth_config is not None:
            body["auth_config"] = auth_config
        if request_headers is not None:
            body["request_headers"] = request_headers
        if route_filter is not None:
            body["route_filter"] = route_filter
        if include_request_body is not None:
            body["include_request_body"] = include_request_body
        if include_response_body is not None:
            body["include_response_body"] = include_response_body
        if include_headers is not None:
            body["include_headers"] = include_headers
        if timeout_seconds is not None:
            body["timeout_seconds"] = timeout_seconds
        if retry_on_failure is not None:
            body["retry_on_failure"] = retry_on_failure
        if max_retries is not None:
            body["max_retries"] = max_retries
        if enabled is not None:
            body["enabled"] = enabled
        return unwrap(await self._client.request(
            method="PATCH",
            path=f"/v1/webhooks/{quote(webhook_id, safe='')}",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def delete(self, webhook_id: str, *, idempotency_key: str | None = None) -> None:
        await self._client.request(
            method="DELETE",
            path=f"/v1/webhooks/{quote(webhook_id, safe='')}",
            idempotency_key=idempotency_key,
        )

    async def get_logs(
        self, webhook_id: str, *, page: int | None = None, per_page: int | None = None
    ) -> WebhookLogPage:
        query: dict[str, Any] = {}
        if page is not None:
            query["page"] = page
        if per_page is not None:
            query["per_page"] = per_page
        return await self._client.request(
            method="GET",
            path=f"/v1/webhooks/{quote(webhook_id, safe='')}/logs",
            query=query or None,
        )

    async def list_event_types(self) -> WebhookEventTypesData:
        """List the webhook event types that can be subscribed to."""
        return unwrap(await self._client.request(method="GET", path="/v1/webhooks/event-types"))

    async def test(self, webhook_id: str, *, idempotency_key: str | None = None) -> WebhookTestResult:
        """Fire a synthetic ``webhook.test`` event and return the delivery result."""
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/webhooks/{quote(webhook_id, safe='')}/test",
            idempotency_key=idempotency_key,
        ))

    @staticmethod
    def construct_event(
        raw_body: str | bytes,
        headers: Mapping[str, str],
        secret: str,
        *,
        format: str = "legacy",
        tolerance_seconds: int | None = 300,
        header_name: str | None = None,
    ) -> WebhookEvent:
        """Verify a webhook delivery AND return the typed event.

        See :func:`construct_webhook_event` (same helper, also exported at
        the package root). Raises :class:`WebhookSignatureVerificationError`
        on any failure. Pure computation — no HTTP, so it is not a coroutine.
        """
        return construct_webhook_event(
            raw_body,
            headers,
            secret,
            format=format,
            tolerance_seconds=tolerance_seconds,
            header_name=header_name,
        )


def verify_webhook_signature(
    *,
    raw_body: str | bytes,
    signature: str,
    secret: str,
    timestamp: int | None = None,
    tolerance_seconds: int | None = None,
) -> bool:
    """Verify an incoming KnoxCall webhook signature (HMAC-SHA256, constant-time).

    Pass ``timestamp`` + ``tolerance_seconds`` to reject replays.
    Also available as ``client.verify_signature()``. For a verify-and-parse
    helper that returns the typed event, use :func:`construct_webhook_event`.
    """
    if timestamp is not None and tolerance_seconds is not None:
        if abs(int(time.time()) - timestamp) > tolerance_seconds:
            return False
    body = raw_body.encode() if isinstance(raw_body, str) else raw_body
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


# Signature header per format (all HMAC-SHA256, mirroring the server's
# webhook hmac-formats). ``custom`` uses a caller-named header.
_FORMAT_HEADERS = {
    "legacy": "x-webhook-signature",
    "stripe": "stripe-signature",
    "github": "x-hub-signature-256",
    "slack": "x-slack-signature",
    "aws-sns": "x-amz-sns-signature",
}


def _strip_sha256_prefix(value: str) -> str:
    return value[7:] if value.startswith("sha256=") else value


def construct_webhook_event(
    raw_body: str | bytes,
    headers: Mapping[str, str],
    secret: str,
    *,
    format: str = "legacy",
    tolerance_seconds: int | None = 300,
    header_name: str | None = None,
) -> WebhookEvent:
    """Verify a webhook delivery and return the parsed, typed event.

    Pass the RAW request body (bytes or str — never re-serialized JSON), the
    delivery headers (looked up case-insensitively), and the endpoint secret.

    ``format`` is the webhook's configured ``hmac_format``: ``"legacy"``
    (default), ``"stripe"``, ``"github"``, ``"slack"``, ``"aws-sns"``, or
    ``"custom"`` (requires ``header_name``).

    ``tolerance_seconds`` (default 300) bounds replay: for ``stripe``/``slack``
    it is enforced against the signed header timestamp; for the other formats
    against the envelope's ``timestamp`` field. Pass ``None`` (or ``0``) to
    explicitly disable the timestamp check.

    Raises :class:`WebhookSignatureVerificationError` on ANY failure —
    missing header, signature mismatch, stale timestamp, or a non-JSON body.
    Never returns a partially-parsed event.
    """
    if format == "custom":
        if not header_name:
            raise WebhookSignatureVerificationError(
                'header_name is required when format="custom"'
            )
        wanted = header_name.lower()
    elif format in _FORMAT_HEADERS:
        wanted = _FORMAT_HEADERS[format]
    else:
        raise WebhookSignatureVerificationError(
            f"unknown webhook signature format: {format!r}"
        )

    body = raw_body.encode() if isinstance(raw_body, str) else bytes(raw_body)
    hmap = {str(k).lower(): v for k, v in headers.items()}
    sig_header = hmap.get(wanted)
    if not sig_header:
        raise WebhookSignatureVerificationError(
            f"missing webhook signature header ({wanted})"
        )

    def _mac(data: bytes) -> "hmac.HMAC":
        return hmac.new(secret.encode(), data, hashlib.sha256)

    now = int(time.time())
    check_envelope_timestamp = False

    if format == "stripe":
        # Stripe-Signature: t=<ts>,v1=<hex>[,v1=<hex>...] — any matching v1
        # passes (mirrors Stripe's own tolerance for rotated secrets).
        header_ts: str | None = None
        candidates: list[str] = []
        for pair in sig_header.split(","):
            key, _, value = pair.strip().partition("=")
            if key == "t":
                header_ts = value
            elif key == "v1":
                candidates.append(value)
        if header_ts is None or not candidates:
            raise WebhookSignatureVerificationError("malformed Stripe-Signature header")
        expected = _mac(f"{header_ts}.".encode() + body).hexdigest()
        matched = False
        for candidate in candidates:
            if hmac.compare_digest(expected, candidate):
                matched = True
        if not matched:
            raise WebhookSignatureVerificationError("webhook signature verification failed")
        if tolerance_seconds:
            try:
                ts_val = int(header_ts)
            except ValueError:
                raise WebhookSignatureVerificationError(
                    "malformed Stripe-Signature timestamp"
                ) from None
            if abs(now - ts_val) > tolerance_seconds:
                raise WebhookSignatureVerificationError(
                    "webhook timestamp outside the tolerance window"
                )
    elif format == "slack":
        header_ts = hmap.get("x-slack-request-timestamp")
        if not header_ts:
            raise WebhookSignatureVerificationError(
                "missing webhook signature header (x-slack-request-timestamp)"
            )
        candidate = sig_header[3:] if sig_header.startswith("v0=") else sig_header
        expected = _mac(f"v0:{header_ts}:".encode() + body).hexdigest()
        if not hmac.compare_digest(expected, candidate):
            raise WebhookSignatureVerificationError("webhook signature verification failed")
        if tolerance_seconds:
            try:
                ts_val = int(header_ts)
            except ValueError:
                raise WebhookSignatureVerificationError(
                    "malformed X-Slack-Request-Timestamp header"
                ) from None
            if abs(now - ts_val) > tolerance_seconds:
                raise WebhookSignatureVerificationError(
                    "webhook timestamp outside the tolerance window"
                )
    elif format == "aws-sns":
        expected = base64.b64encode(_mac(body).digest()).decode()
        if not hmac.compare_digest(expected, sig_header):
            raise WebhookSignatureVerificationError("webhook signature verification failed")
        check_envelope_timestamp = True
    else:  # legacy | github | custom — sha256=<hex> over the body
        candidate = _strip_sha256_prefix(sig_header)
        expected = _mac(body).hexdigest()
        if not hmac.compare_digest(expected, candidate):
            raise WebhookSignatureVerificationError("webhook signature verification failed")
        check_envelope_timestamp = True

    try:
        event = json.loads(body)
    except ValueError:
        raise WebhookSignatureVerificationError("webhook body is not valid JSON") from None
    if not isinstance(event, dict):
        raise WebhookSignatureVerificationError("webhook body is not a JSON object")

    # Formats without a signed timestamp bound replay via the envelope's
    # own timestamp field (skipped when tolerance is explicitly disabled).
    if check_envelope_timestamp and tolerance_seconds:
        raw_ts = event.get("timestamp")
        try:
            parsed = _dt.datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            raise WebhookSignatureVerificationError(
                "webhook envelope timestamp is missing or invalid"
            ) from None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=_dt.timezone.utc)
        if abs(now - parsed.timestamp()) > tolerance_seconds:
            raise WebhookSignatureVerificationError(
                "webhook timestamp outside the tolerance window"
            )

    return event  # type: ignore[return-value]
