"""Headless signup — mirrors signup.ts.

The one /v1 surface that needs no credentials, so these are standalone
functions rather than resources on the authenticated client. TWO steps since
2026-08-28 (founder decision F-25): :func:`signup` never returns a credential,
it returns a claim handle and emails a sign-in link; the starter key is minted
when that link has been clicked and the claim is collected::

    import asyncio
    from knoxcall import signup, claim_signup

    accepted = await signup(email="dev@example.com", tenant_name="Acme Inc")
    handle = accepted["claim_handle"]

    # …the account owner clicks the emailed sign-in link…
    claim = await claim_signup(claim_handle=handle)
    while claim["status"] == "pending":
        await asyncio.sleep(accepted["poll_after_seconds"])
        claim = await claim_signup(claim_handle=handle)

    # claim["starter"]["api_key"]["api_key"] is shown exactly once — store it
    # now. It is a one-time *test* API key for raw proxy calls
    # (x-knoxcall-key header against sandbox.knoxcall.com); the SDK itself
    # authenticates via OAuth — create an OAuth client (client_credentials)
    # in the dashboard, then:
    #
    #     from knoxcall import KnoxCall, ClientCredentials
    #     client = KnoxCall(
    #         tenant=claim["tenant"]["slug"],
    #         bootstrap=ClientCredentials(
    #             client_id="tk_...", client_secret="..."
    #         ),
    #     )

Synchronous callers use :func:`signup_sync` / :func:`claim_signup_sync` (same
parameters and result).
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from ..errors import KnoxCallError
from ..types import SignupClaimResult, SignupResult

DEFAULT_BASE_URL = "https://api.knoxcall.com"


class SignupError(KnoxCallError):
    """Raised when /v1/signup returns a non-2xx response.

    Part of the SDK error hierarchy (``except KnoxCallError`` catches it);
    keeps the original ``.status`` / ``.type`` attributes.
    """

    def __init__(self, message: str, *, status: int, type: str | None = None) -> None:
        super().__init__(message, status=status, code=type)
        self.type = type


async def _post(
    url: str,
    payload: dict[str, Any],
    what: str,
    http: httpx.AsyncClient | None = None,
) -> Any:
    """POST the envelope and unwrap ``data``, raising SignupError otherwise.

    Note what is NOT an error here: a 202. Both endpoints use it for a normal,
    credential-less success (``signup`` always, ``claim_signup`` while the
    sign-in link is unused), so anything below 400 with a ``data`` object is
    returned to the caller unchanged.
    """
    if http is not None:
        # Caller-supplied transport (tests, proxies, custom TLS). Not closed
        # here — the caller owns its lifetime.
        res = await http.post(url, json=payload)
    else:
        async with httpx.AsyncClient() as client:
            res = await client.post(url, json=payload)

    try:
        body = res.json()
    except ValueError:
        body = {}

    data = body.get("data")
    if res.status_code >= 400 or not data:
        err = body.get("error") or {}
        raise SignupError(
            err.get("message", f"{what} failed with status {res.status_code}"),
            status=res.status_code,
            type=err.get("type"),
        )
    return data


async def signup(
    *,
    email: str,
    tenant_name: str,
    full_name: str | None = None,
    tenant_slug: str | None = None,
    country: str | None = None,
    region: str | None = None,
    base_url: str | None = None,
    http: httpx.AsyncClient | None = None,
) -> SignupResult:
    """Start creating a KnoxCall account.

    Always answers 202 with an opaque ``claim_handle`` and emails a sign-in
    link — no account, tenant or credential exists until that link is clicked.
    Collect the starter kit afterwards with :func:`claim_signup`. Rate limited
    to 3 signups/hour/IP.

    Enumeration-safe: the reply is identical for an address that already has an
    account (it receives a sign-in link and a handle that stays ``pending``).

    Omit ``tenant_slug`` to have the server derive an available one from
    ``tenant_name`` (recommended for headless callers).
    """
    url = f"{base_url.rstrip('/')}/v1/signup" if base_url else f"{DEFAULT_BASE_URL}/v1/signup"
    payload: dict[str, Any] = {"email": email, "tenant_name": tenant_name}
    if full_name is not None:
        payload["full_name"] = full_name
    if tenant_slug is not None:
        payload["tenant_slug"] = tenant_slug
    if country is not None:
        payload["country"] = country
    if region is not None:
        payload["region"] = region

    return await _post(url, payload, "Signup", http)


def signup_sync(
    *,
    email: str,
    tenant_name: str,
    full_name: str | None = None,
    tenant_slug: str | None = None,
    country: str | None = None,
    region: str | None = None,
    base_url: str | None = None,
) -> SignupResult:
    """Synchronous :func:`signup`. Runs the request on a private event loop —
    call the async :func:`signup` instead when already inside a running loop."""
    return asyncio.run(signup(
        email=email,
        tenant_name=tenant_name,
        full_name=full_name,
        tenant_slug=tenant_slug,
        country=country,
        region=region,
        base_url=base_url,
    ))


async def claim_signup(
    *,
    claim_handle: str,
    base_url: str | None = None,
    http: httpx.AsyncClient | None = None,
) -> SignupClaimResult:
    """Poll a claim handle returned by :func:`signup`.

    Returns ``{"status": "pending", ...}`` — a 202, and a normal SUCCESS —
    until the emailed sign-in link has been clicked, then once returns
    ``{"status": "ready", ...}`` with the tenant and a one-time Test-mode API
    key. Polling again after that raises :class:`SignupError` (409); an unknown
    or expired handle raises it with 404.

    Do not poll faster than the ``poll_after_seconds`` :func:`signup` returned.
    """
    url = (
        f"{base_url.rstrip('/')}/v1/signup/claim"
        if base_url
        else f"{DEFAULT_BASE_URL}/v1/signup/claim"
    )
    return await _post(url, {"claim_handle": claim_handle}, "Signup claim", http)


def claim_signup_sync(
    *,
    claim_handle: str,
    base_url: str | None = None,
) -> SignupClaimResult:
    """Synchronous :func:`claim_signup` (same parameters and result)."""
    return asyncio.run(claim_signup(claim_handle=claim_handle, base_url=base_url))
