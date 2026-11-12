"""Wrap-credential escrow resource — mirrors wrap.ts."""

from __future__ import annotations
from typing import Any, Literal, TYPE_CHECKING, overload
from urllib.parse import quote

import httpx

from .._envelope import unwrap
from ..core import NOT_MODIFIED, _SDK_VERSION
from ..types import (
    EgressObservation,
    EgressObservationsReport,
    WrapEscrowResult,
    InterceptManifest,
    WrapGatewayToken,
    WrapGatewayTokenRevokeResult,
    WrapGatewayUrlResult,
)
from ..wrap_transport import KnoxWrapAsyncTransport
from .._intercept_patch import InterceptHandle


def manifest_etag(version: str) -> str:
    """The weak ETag the manifest endpoint sets for a ``version`` (``src/client-api/wrap.ts``)."""
    return f'W/"{version}"'


if TYPE_CHECKING:
    from ..core import APIClient


class WrapResource:
    def __init__(self, client: "APIClient") -> None:
        self._client = client

    async def escrow(
        self,
        *,
        provider: str,
        name: str,
        value: str,
        hosts: list[str],
        idempotency_key: str | None = None,
    ) -> WrapEscrowResult:
        """Escrow a raw provider credential under KnoxCall custody.

        The ``value`` is sent once and never returned. ``hosts`` is the
        load-bearing pin — the allowed upstream hostnames the escrowed key may
        be used against. The result carries only the stored secret's metadata
        (``secret_id``, ``name``, ``provider``, ``allowed_hosts``, ``sandbox``).
        """
        body: dict[str, Any] = {
            "provider": provider,
            "name": name,
            "value": value,
            "hosts": hosts,
        }
        return unwrap(await self._client.request(
            method="POST",
            path="/v1/wrap/credentials",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def gateway_url(
        self,
        *,
        secret: str,
        host: str | None = None,
        ttl_seconds: int | None = None,
        label: str | None = None,
        style: Literal["path", "subdomain"] | None = None,
        idempotency_key: str | None = None,
    ) -> WrapGatewayUrlResult:
        """Mint a base-URL gateway token bound to an already-escrowed credential.

        For SDKs that expose ONLY a base-URL override and no ``fetch``/transport
        hook (Resend, Mailgun, Airtable, …). Set the returned ``base_url`` as the
        wrapped SDK's base URL; the SDK's own key becomes a placeholder because
        KnoxCall injects the escrowed secret server-side, so the real key never
        enters your process.

        ESCROW-ONLY — ``secret`` must already be escrowed (:meth:`escrow`). The
        returned ``token`` is a bearer credential embedded in ``base_url``: treat
        it as a secret, never store or log it. Use the returned ``id`` with
        :meth:`revoke_gateway_token` to revoke it.

        ``style`` selects which ``base_url`` form to return. ``"path"``
        (``…/wg/<token>/<host>``) is always available; ``"subdomain"``
        (``<label>.wrap.<domain>``) is only available when the operator has
        enabled the wildcard-subdomain gateway (else the call 400s). Omit it to
        let the server choose (subdomain when enabled, else path). The result's
        ``base_url_style`` reports which form was returned. NOTE: the subdomain
        form carries the token in the TLS SNI (plaintext on the wire) — weaker
        token confidentiality than the path form; prefer a short ``ttl_seconds``.
        """
        body: dict[str, Any] = {"secret": secret}
        if host is not None:
            body["host"] = host
        if ttl_seconds is not None:
            body["ttl_seconds"] = ttl_seconds
        if label is not None:
            body["label"] = label
        if style is not None:
            body["style"] = style
        return unwrap(await self._client.request(
            method="POST",
            path="/v1/wrap/tokens",
            body=body,
            idempotency_key=idempotency_key,
        ))

    @overload
    async def intercept_manifest(self, *, environment: str | None = None) -> InterceptManifest: ...

    @overload
    async def intercept_manifest(self, *, environment: str | None = None, if_none_match: str | None) -> InterceptManifest | None: ...

    async def intercept_manifest(self, *, environment: str | None = None, if_none_match: str | None = None) -> InterceptManifest | None:
        """The intercept manifest (GET /v1/wrap/intercept-manifest): which upstream
        hosts an intercept-enabled Route covers in this space, for one
        environment (default: the tenant's default), and the slug to send them
        under. What a route-aware interceptor polls; ``version`` is the ETag.
        Scope: ``routes:read``.

        Conditional form: pass ``if_none_match`` (the ``version`` you hold) and
        the SDK sends ``If-None-Match: W/"<version>"``; a ``304`` returns ``None``
        — keep what you hold. Everything else (auth, the one re-auth on 401,
        retries, a 200 with a newer manifest) is exactly the unconditional call."""
        query = {"environment": environment} if environment is not None else None
        if if_none_match is None:
            return unwrap(await self._client.request(
                method="GET",
                path="/v1/wrap/intercept-manifest",
                query=query,
            ))
        res = await self._client.request(
            method="GET",
            path="/v1/wrap/intercept-manifest",
            query=query,
            headers={"If-None-Match": manifest_etag(if_none_match)},
            allow_not_modified=True,
        )
        return None if res is NOT_MODIFIED else unwrap(res)

    async def report_egress_observations(
        self, observations: list[EgressObservation], *, sdk: str | None = None
    ) -> EgressObservationsReport:
        """Report uncovered-egress observations (POST /v1/wrap/egress-observations;
        PARITY §21.3) — the thin typed wrapper the interceptor's reporter uses,
        exported so an integrator can report by hand. At most 200 observations
        per call. The body carries names, never values: a credential header's
        NAME, the host, the first path segment, the method and counts. Scope:
        ``routes:read``."""
        return unwrap(await self._client.request(
            method="POST",
            path="/v1/wrap/egress-observations",
            body={"sdk": sdk or f"python/{_SDK_VERSION}", "observations": list(observations)},
        ))

    async def list_gateway_tokens(self) -> list[WrapGatewayToken]:
        """List this space's gateway tokens (metadata only — the token itself is
        never returned)."""
        res = unwrap(await self._client.request(
            method="GET",
            path="/v1/wrap/tokens",
        ))
        return res["tokens"]

    async def revoke_gateway_token(self, id: str) -> WrapGatewayTokenRevokeResult:
        """Revoke a single gateway token by id — immediately invalidates it for all
        future ``/wg`` requests."""
        return unwrap(await self._client.request(
            method="DELETE",
            path=f"/v1/wrap/tokens/{quote(id, safe='')}",
        ))

    # ── Data-plane wrap transport (mirrors Node ``knox.wrap.fetch()``) ──────────

    def transport(self, **opts: Any) -> KnoxWrapAsyncTransport:
        """An :class:`httpx.AsyncBaseTransport` that routes a wrapped third-party
        SDK's HTTP calls through KnoxCall's ephemeral proxy (transparent mode).

        Swap ONLY the wrapped SDK's httpx transport — it keeps its own
        serialization, retries and error types::

            # OpenAI, Anthropic, … (any SDK taking http_client):
            oai = AsyncOpenAI(http_client=httpx.AsyncClient(transport=knox.wrap.transport()))

            # Or let KnoxCall build the AsyncClient for you:
            oai = AsyncOpenAI(http_client=knox.wrap.client())

        Transit mode (default): the wrapped SDK's own ``Authorization`` header is
        lifted out-of-band and delivered to the upstream by the server — it never
        transits as a raw header and is never logged. Its Test/Live prefix must
        match the client's ``sandbox`` flag (both-must-agree). Escrow mode
        (``credential={"secret": "wrap-stripe-live"}``): the raw key stays in
        KnoxCall custody. Requests matching a route-around rule (raw-card
        endpoints by default) are sent to the provider DIRECTLY, untouched.

        Options (keyword-only) mirror the Node wrapper: ``credential``,
        ``route_around``, ``disable_default_route_around``, ``route``,
        ``auto_switch``, ``on_route_around``, ``on_promoted`` and (for tests /
        pinning the direct path) ``direct_transport``.
        """
        return KnoxWrapAsyncTransport(self._client, **opts)

    def client(self, **opts: Any) -> httpx.AsyncClient:
        """An :class:`httpx.AsyncClient` pre-wired with :meth:`transport` — hand
        it straight to a wrapped async SDK's ``http_client=`` parameter."""
        return httpx.AsyncClient(transport=self.transport(**opts))

    # ── Process-wide interceptor (route-aware-interception-plan.md PR3) ───────

    def intercept(
        self,
        *,
        hosts: Any = (),
        stacks: list[str] | None = None,
        require_context: bool = False,
        **opts: Any,
    ) -> InterceptHandle:
        """Reroute outbound egress for the hosts a Route covers — and for
        ``hosts`` you list — through KnoxCall, with NO per-SDK wiring.

        On the ASYNC client the async stacks are patched: ``httpx`` (default) and,
        opt-in, ``stacks=["aiohttp"]`` — ``aiohttp.ClientSession._request``, for
        aiobotocore, slack_sdk's async client, azure-core's aiohttp transport and
        any other session (aiohttp >= 3.13, installed separately; a real
        ``aiohttp.ClientResponse`` comes back; see ``_intercept_aiohttp.py``).
        ``urllib3`` needs the sync facade (there is no runner to drive the SDK's
        async I/O from a synchronous ``requests`` / ``httpx.Client`` call), and
        the aiohttp stack needs THIS facade (it awaits the pipeline on your event
        loop). Route-aware by default (``routes="auto"``); ``hosts`` may be a
        list or a ``{host: {"credential": …, "unavailable": …}}`` map. Returns
        an :class:`InterceptHandle` (``uninstall()``, ``aready()``,
        ``arefresh()``, ``manifest()``). ``KNOXCALL_INTERCEPT=off`` passes
        everything through. A convenience, not a security boundary — see
        ``_intercept_patch.py``.
        """
        from .._intercept_patch import install_intercept

        host_list, host_options = _split_hosts(hosts)
        opts.setdefault("routes", "auto")
        return install_intercept(
            client=self._client,
            runner=None,
            stacks=stacks or ["httpx"],
            hosts=host_list,
            host_options=host_options,
            require_context=require_context,
            transport_opts=opts,
        )


def _split_hosts(hosts: Any) -> tuple[list[str], dict[str, Any]]:
    """``["a", "b"]`` or ``{"a": {...}, "b": {}}`` → (list, per-host options)."""
    if isinstance(hosts, str):
        raise TypeError("hosts must be a list of hostnames or a {host: options} mapping")
    if isinstance(hosts, dict):
        return list(hosts.keys()), {h: (o or {}) for h, o in hosts.items()}
    return list(hosts), {}
