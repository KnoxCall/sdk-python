"""OIDC workload federation — mirrors token-exchange.ts.

RFC 8693 token exchange against ``POST /v1/oauth/token``: trade the OIDC
id_token your CI provider already mints for a short-lived AI-gateway
capability token::

    from knoxcall import exchange_token

    res = await exchange_token(subject_token=ci_id_token, tenant="acme")
    # res["access_token"] is an agent-kind token for POST /v1/ai/...

Like :func:`knoxcall.signup` this is a standalone function and NOT a method on
the authenticated client, and for a stronger reason: the whole point is that CI
holds no KnoxCall credential. Constructing a client to reach this endpoint
would require the very secret the flow exists to remove.

Supply ``resource`` — the ``resource`` field of an MCP server's create/get
response — to narrow the minted token to ``tool`` kind, confined to exactly
that one ``/v1/mcp/<slug>`` and refused on ``/v1/ai``.

THE HOST MATTERS, and getting it wrong looks like a credential failure.
``/v1/oauth/token`` is part of the DATA plane: ``src/server.ts`` hands
``/v1/ai/``, ``/v1/mcp/`` and ``/v1/oauth/`` to the proxy router only when the
request lands on a tenant data-plane host (``{slug}.knoxcall.com``,
``sandbox-{slug}...``). Verified against a running server on 2026-08-25: the
same request answers 400 ``invalid_grant`` on ``acme.knoxcall.com`` and **401**
on ``api.knoxcall.com`` — a caller who points this at the management host reads
that 401 as "my CI token was rejected" when the endpoint is simply not served
there. So ``tenant`` (or an explicit ``base_url``) is REQUIRED: there is no safe
default to guess.

NOT the tenant OAuth 2.1 token endpoint at ``https://api.knoxcall.com/oauth/token``
(root host, no ``/v1``), which mints ``kc_`` MANAGEMENT tokens from
``client_credentials`` and friends. Sending a token-exchange grant there is
``unsupported_grant_type``, and vice versa.

Synchronous callers use :func:`exchange_token_sync` (same parameters and result).
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

import httpx

from .._warn import is_insecure_remote_url, warn_security
from ..errors import BootstrapError, KnoxCallError, ai_gateway_error_from

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token"
KNOXCALL_AUDIENCE = "knoxcall:gateway"

# A tenant slug becomes a hostname, so it must be a bare DNS label. This
# mirrors the client's own slug assertion and exists for the same reason: a
# slug adopted from config or an environment variable that is not one
# ("evil.com#") would send the workload's OIDC token to an attacker host.
_TENANT_SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


def _resolve_base_url(tenant: str | None, sandbox: bool, base_url: str | None) -> str:
    """The data-plane origin. There is no default — see the module docstring."""
    if base_url:
        return base_url.rstrip("/")
    if not tenant:
        raise BootstrapError(
            "exchange_token needs a tenant slug or a base_url: POST /v1/oauth/token is "
            "served only on the tenant data-plane host (https://{tenant}.knoxcall.com). "
            "Pointing it at api.knoxcall.com answers 401, which reads like a rejected "
            "subject_token but means the endpoint is not there."
        )
    if not _TENANT_SLUG_RE.match(tenant):
        raise BootstrapError(
            f"invalid tenant slug {tenant!r} — expected a DNS label; refusing to send a "
            "subject token to a host derived from it"
        )
    host = f"sandbox-{tenant}" if sandbox else tenant
    return f"https://{host}.knoxcall.com"


# Sentinel distinguishing "caller did not ask for a resource" from
# ``resource=""``. An empty string must reach the server and be refused
# ``invalid_target``: treating it as absent would hand back an UNCONFINED agent
# token to a caller who asked for a confined one.
_UNSET = object()


class TokenExchangeError(KnoxCallError):
    """Raised when ``POST /v1/oauth/token`` returns a non-2xx response.

    Part of the SDK error hierarchy (``except KnoxCallError`` catches it).
    ``.type`` is the RFC 6749 §5.2 code: ``invalid_grant``, ``invalid_target``,
    ``unsupported_grant_type``, ``invalid_request`` or ``server_error``.
    """

    def __init__(self, message: str, *, status: int, type: str | None = None) -> None:
        super().__init__(message, status=status, code=type)
        self.type = type


async def exchange_token(
    *,
    subject_token: str,
    resource: Any = _UNSET,
    audience: str = KNOXCALL_AUDIENCE,
    tenant: str | None = None,
    sandbox: bool = False,
    base_url: str | None = None,
    http: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Exchange a CI OIDC token for an AI-gateway capability token.

    Requires no constructed client and no KnoxCall credential: ``subject_token``
    IS the credential, verified against the issuer's published JWKS.

    Returns the RFC 8693 §2.2.1 body — ``{access_token, issued_token_type,
    token_type, expires_in, scope}``. This is a BARE OAuth body, not the
    ``{data, meta}`` envelope the rest of ``/v1`` returns.
    """
    origin = _resolve_base_url(tenant, sandbox, base_url)
    # the request carries the workload OIDC id_token, which IS a credential -- the
    # whole point of the flow. PARITY 15 already warns when a CLIENT is constructed
    # against plaintext http to a non-loopback host, and this function deliberately
    # constructs no client, so without this the control exists on one path and is
    # simply absent on the parallel one. A warning rather than a refusal because the
    # acceptance harness and local dev legitimately use http://127.0.0.1.
    if is_insecure_remote_url(origin):
        warn_security(
            f"KnoxCall: exchanging a workload OIDC token over plaintext HTTP to {origin} "
            "— the subject token is a credential and is readable on the wire. Use https://."
        )
    url = f"{origin}/v1/oauth/token"
    payload: dict[str, Any] = {
        "grant_type": TOKEN_EXCHANGE_GRANT,
        "subject_token": subject_token,
        "subject_token_type": ID_TOKEN_TYPE,
        "audience": audience,
    }
    if resource is not _UNSET:
        payload["resource"] = resource

    if http is not None:
        res = await http.post(url, json=payload)
    else:
        async with httpx.AsyncClient() as owned:
            res = await owned.post(url, json=payload)

    try:
        body = res.json()
    except ValueError:
        # A non-JSON error page (a proxy 502). Fall through to the status check
        # rather than masking it as a parse failure.
        body = {}
    if not isinstance(body, dict):
        body = {}

    if res.status_code >= 400 or not body.get("access_token"):
        # AIGW-163: this endpoint is on the TENANT DATA PLANE, so when the AI
        # gateway has failed to boot it is answered by the plane's 503 sentinel
        # — the data-plane envelope with ``code: "ai_gateway_unavailable"`` and
        # a ``Retry-After`` — not by an RFC 6749 error. Typing it means a CI job
        # is told to wait rather than being handed a generic failure. The
        # discriminator is exact: an RFC 6749 body carries no ``code`` at all.
        ai_err = ai_gateway_error_from(res.status_code, body, res.headers)
        if ai_err is not None:
            raise ai_err
        raise TokenExchangeError(
            body.get(
                "error_description",
                f"Token exchange failed with status {res.status_code}",
            ),
            status=res.status_code,
            type=body.get("error", "token_exchange_failed"),
        )
    return body


def exchange_token_sync(
    *,
    subject_token: str,
    resource: Any = _UNSET,
    audience: str = KNOXCALL_AUDIENCE,
    tenant: str | None = None,
    sandbox: bool = False,
    base_url: str | None = None,
    http: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Synchronous :func:`exchange_token`. Runs the request on a private event
    loop — call the async :func:`exchange_token` instead when already inside a
    running loop."""
    return asyncio.run(
        exchange_token(
            subject_token=subject_token,
            resource=resource,
            audience=audience,
            tenant=tenant,
            sandbox=sandbox,
            base_url=base_url,
            http=http,
        )
    )
