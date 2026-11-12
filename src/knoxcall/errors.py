"""Error hierarchy mirroring the JS SDK + Anthropic/Stripe pattern."""

from __future__ import annotations
from typing import Any


class KnoxCallError(Exception):
    """Base for all SDK errors."""

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        code: str | None = None,
        request_id: str | None = None,
        headers: dict[str, str] | None = None,
        body: Any = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.request_id = request_id
        self.headers = headers or {}
        self.body = body


class APIConnectionError(KnoxCallError):
    pass


class APIConnectionTimeoutError(APIConnectionError):
    pass


class APIUserAbortError(KnoxCallError):
    pass


class AuthenticationError(KnoxCallError):
    pass


class PermissionDeniedError(KnoxCallError):
    pass


# Deprecated alias — shadowed Python's builtin PermissionError, which made
# ``except PermissionError`` around file I/O silently match API errors.
PermissionError = PermissionDeniedError


class PaymentRequiredError(KnoxCallError):
    """HTTP 402 — a plan/billing limit. Two error types share this status:
    ``plan_limit`` (a counted quota was reached) and ``plan_feature`` (the
    capability itself is not on the tier). The mapping is on STATUS, so both
    land here. Distinct from :class:`PermissionDeniedError` (403) so callers can
    prompt to upgrade rather than showing an access denial."""

    pass


class NotFoundError(KnoxCallError):
    pass


class ConflictError(KnoxCallError):
    pass


class ValidationError(KnoxCallError):
    def __init__(
        self,
        message: str,
        *,
        fields: dict[str, list[str]] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.fields = fields or {}


class RateLimitError(KnoxCallError):
    def __init__(
        self,
        message: str,
        *,
        retry_after: int | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.retry_after = retry_after


class ServerError(KnoxCallError):
    """5xx.

    ``retry_after`` is whole seconds from ``Retry-After`` when the server sent
    one: a ``503 dependency_unavailable`` — KnoxCall could not reach one of its
    own dependencies in time and did not serve the request — does, and the
    retry loop honours it exactly as a 429's (PARITY §4). ``None`` when absent:
    a plain 5xx keeps the jittered backoff.
    """

    def __init__(
        self,
        message: str,
        *,
        retry_after: int | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.retry_after = retry_after


class BootstrapError(KnoxCallError):
    pass


class NotAuthenticatedError(BootstrapError):
    """No usable credential was found by auto-detection (no explicit creds, env
    token/keys, credentials file, or cloud OIDC).

    Subclass of :class:`BootstrapError` so existing ``except BootstrapError``
    keeps working, but distinctly typed so callers can branch on "not logged
    in — should I run ``login()``?" vs a genuine misconfiguration. See
    :func:`knoxcall.login` / :func:`knoxcall.ensure_login`.
    """

    pass


class WebhookSignatureVerificationError(KnoxCallError):
    """Raised by ``construct_webhook_event`` when a webhook delivery fails
    verification (missing header, bad signature, stale timestamp, or a body
    that is not valid JSON). The message never echoes the signature or secret."""

    pass


class AIGatewayError(KnoxCallError):
    """A refusal from the AI **data plane** (``POST {agent_url}/…``), typed.

    WHY IT IS ITS OWN CLASS. The data plane is not the Management API: it
    answers ``{error, error_description, code}`` with the machine-readable code
    in ``error`` AND ``code`` (AIGW-163), while the management plane answers the
    nested ``{"error": {"type", "message", "request_id"}}``. A ``code`` of
    ``budget_exceeded`` and a ``code`` of ``not_found`` come from different
    contracts, and status alone cannot tell them apart.

    The SDK does not make the data-plane call for you — that is the design: you
    point an existing Anthropic or OpenAI client at the agent's ``agent_url``
    and it works unchanged. So this class is paired with
    :func:`ai_gateway_error_from`, which types whatever your provider client
    hands back.

    A subclass of :class:`KnoxCallError`, so ``except KnoxCallError`` still
    catches it (sdk/PARITY.md §1).
    """

    def __init__(
        self,
        message: str,
        *,
        code: str,
        error_description: str,
        status: int | None = None,
        request_id: str | None = None,
        retry_after: int | None = None,
        headers: dict[str, str] | None = None,
        body: Any = None,
    ) -> None:
        super().__init__(
            message, status=status, code=code, request_id=request_id, headers=headers, body=body
        )
        self.error_description = error_description
        #: Seconds to wait before retrying, from ``Retry-After``. Present on a
        #: 429 whose reset the gateway knows exactly (a spend cap's UTC
        #: rollover, a rate-limit window) and ``None`` rather than guessed
        #: otherwise — so ``None`` means "back off on your own schedule".
        self.retry_after = retry_after


def is_ai_gateway_error_body(body: Any) -> bool:
    """Does this body look like the AI data plane's envelope?"""
    if not isinstance(body, dict):
        return False
    return (
        isinstance(body.get("error"), str)
        and isinstance(body.get("code"), str)
        and isinstance(body.get("error_description"), str)
        and body["error"] == body["code"]
    )


def ai_gateway_error_from(
    status: int,
    body: Any,
    headers: Any = None,
) -> AIGatewayError | None:
    """Type a refusal a provider client received from an agent's data-plane URL.

    Returns ``None`` when the body is not the data plane's envelope, so a caller
    falls through to its own handling rather than being handed a mislabelled
    error::

        resp = httpx.post(f"{agent['agent_url']}/v1/messages", json=payload)
        if resp.is_error:
            err = ai_gateway_error_from(resp.status_code, resp.json(), resp.headers)
            if err and err.code == "budget_exceeded":
                time.sleep(err.retry_after or 60)
            raise err or RuntimeError(f"HTTP {resp.status_code}")

    ``headers`` accepts any case-insensitive or plain mapping, or ``None``.
    """
    if not is_ai_gateway_error_body(body):
        return None

    def read(name: str) -> str | None:
        if headers is None:
            return None
        try:
            value = headers.get(name)
        except AttributeError:
            return None
        if value is None:
            try:
                value = headers.get(name.lower())
            except AttributeError:
                return None
        return value if isinstance(value, str) else None

    raw_retry = (read("Retry-After") or "").strip()
    retry_after = int(raw_retry) if raw_retry.isdigit() else None
    request_id = read("X-Request-Id")
    if request_id is None and isinstance(body.get("request_id"), str):
        request_id = body["request_id"]
    return AIGatewayError(
        body["error_description"],
        code=body["code"],
        error_description=body["error_description"],
        status=status,
        request_id=request_id,
        retry_after=retry_after,
        body=body,
    )


def error_from_response(
    status: int,
    body: Any,
    headers: dict[str, str],
) -> KnoxCallError:
    """Map an HTTP status + body to a typed KnoxCallError."""
    body_dict: dict[str, Any] = body if isinstance(body, dict) else {}
    err_field = body_dict.get("error")

    # The KnoxCall /v1 API returns errors as ``{"error": {"type", "message",
    # "request_id"}}`` — ``error`` is a DICT. Treating it as a string (the
    # previous bug) rendered a dict-repr and set ``code`` to the dict. Stay
    # tolerant of the flat shapes some non-/v1 surfaces still use:
    #   B: {"error": "<message>", "statusCode", "errorId"}
    #   C: {"error": "<code>", "message"}
    if isinstance(err_field, dict):
        message = err_field.get("message") or err_field.get("type") or f"HTTP {status}"
        code = err_field.get("type")
        body_request_id = err_field.get("request_id")
    else:
        message = (
            body_dict.get("error_description")
            or body_dict.get("message")
            or err_field
            or f"HTTP {status}"
        )
        # AIGW-163: the AI data plane sends the code in BOTH `error` and
        # `code`. Prefer the explicit `code` — a future surface could carry one
        # that is not mirrored, and reading the mirror would lose it.
        code = body_dict.get("code") if isinstance(body_dict.get("code"), str) else (
            err_field if isinstance(err_field, str) else None
        )
        body_request_id = body_dict.get("request_id") or body_dict.get("errorId")

    # Correlation id: the X-Request-Id response header (now emitted by the API)
    # or, failing that, the id carried in the body.
    request_id = headers.get("x-request-id") or body_request_id
    init = dict(status=status, code=code, request_id=request_id, headers=headers, body=body)

    if status == 401:
        return AuthenticationError(message, **init)
    if status == 402:
        return PaymentRequiredError(message, **init)
    if status == 403:
        return PermissionDeniedError(message, **init)
    if status == 404:
        return NotFoundError(message, **init)
    if status == 409:
        return ConflictError(message, **init)
    if status == 422:
        return ValidationError(message, fields=body_dict.get("fields"), **init)
    if status == 429:
        ra = headers.get("retry-after")
        return RateLimitError(message, retry_after=int(ra) if ra and ra.isdigit() else None, **init)
    if status >= 500:
        # A 503 `dependency_unavailable` carries Retry-After; a plain 5xx does
        # not. Digits only — an HTTP-date is legal but is not delta-seconds.
        ra = (headers.get("retry-after") or "").strip()
        return ServerError(message, retry_after=int(ra) if ra.isdigit() else None, **init)
    return KnoxCallError(message, **init)
