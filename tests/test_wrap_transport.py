"""Wrap-transport tests — the Python mirror of
``sdk/knoxcall-node/test/wrap-transport.test.ts``.

Asserts the wrapped-SDK httpx transport re-targets to ``ephemeral()`` in
transparent mode, lifts the provider credential out-of-band, preserves the
request bytes/Content-Type, enforces both-must-agree, and routes raw-card /
opted-in requests directly to the provider.

Capture is via a FAKE ephemeral hook (a stand-in ``client`` recording each
``ephemeral()`` / ``call()`` invocation), never by mocking the transport — the
same discipline the Node tests use at the fetch boundary.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from knoxcall import (
    KnoxCall,
    KnoxCallAsync,
    KnoxWrapAsyncTransport,
    KnoxWrapTransport,
    RouteAroundRule,
    WrapSandboxMismatchError,
)
from knoxcall.auth.bootstrap import AccessToken

STRIPE_FORM = "amount=2000&currency=usd&source=tok_visa"


class FakeClient:
    """A stand-in for ``APIClient`` that records ``ephemeral()`` / ``call()``
    invocations instead of performing HTTP. ``promoted`` optionally stamps the
    ``X-Knox-Promoted-Route`` hint on every ephemeral response."""

    def __init__(self, *, sandbox: bool = False, promoted: str | None = None) -> None:
        self.sandbox = sandbox
        self._promoted = promoted
        self.ephemeral_calls: list[dict[str, Any]] = []
        self.route_calls: list[dict[str, Any]] = []

    async def ephemeral(
        self,
        upstream_url: str,
        *,
        method: str = "GET",
        body: Any = None,
        headers: dict[str, str] | None = None,
        mode: str | None = None,
        upstream_authorization: str | None = None,
        upstream_auth_secret: str | None = None,
        upstream_auth_scheme: str | None = None,
        timeout: float | None = None,
        **extra: Any,
    ) -> httpx.Response:
        self.ephemeral_calls.append(
            {
                "url": upstream_url,
                "method": method,
                "body": body,
                "headers": headers or {},
                "mode": mode,
                "upstream_authorization": upstream_authorization,
                "upstream_auth_secret": upstream_auth_secret,
                "upstream_auth_scheme": upstream_auth_scheme,
                "timeout": timeout,
            }
        )
        resp_headers = {"content-type": "application/json"}
        if self._promoted:
            resp_headers["x-knox-promoted-route"] = self._promoted
        return httpx.Response(200, headers=resp_headers, json={"ok": True})

    async def call(
        self,
        route: str,
        *,
        method: str = "GET",
        path: str = "/",
        body: Any = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        **extra: Any,
    ) -> httpx.Response:
        self.route_calls.append(
            {
                "route": route,
                "method": method,
                "path": path,
                "body": body,
                "headers": headers or {},
                "timeout": timeout,
            }
        )
        return httpx.Response(200, json={"ok": True})


def _async_wrapped(fake: FakeClient, **opts: Any) -> httpx.AsyncClient:
    """A wrapped-SDK-style AsyncClient whose transport routes through ``fake``."""
    return httpx.AsyncClient(transport=KnoxWrapAsyncTransport(fake, **opts))


# ── Transit mode (lift the SDK Authorization) ──────────────────────────────────


@pytest.mark.asyncio
async def test_transit_retargets_lifts_auth_and_preserves_body():
    fake = FakeClient(sandbox=False)
    async with _async_wrapped(fake) as http:
        await http.post(
            "https://api.stripe.com/v1/charges",
            headers={
                "authorization": "Bearer sk_live_provider",
                "content-type": "application/x-www-form-urlencoded",
                "idempotency-key": "idem-1",
            },
            content=STRIPE_FORM,
        )

    assert len(fake.ephemeral_calls) == 1
    r = fake.ephemeral_calls[0]
    # Re-targeted to the ephemeral proxy in transparent mode.
    assert r["url"] == "https://api.stripe.com/v1/charges"
    assert r["mode"] == "transparent"
    # Provider credential lifted out-of-band; NOT forwarded as a raw header.
    assert r["upstream_authorization"] == "Bearer sk_live_provider"
    assert "authorization" not in r["headers"]
    # SDK headers + Content-Type preserved verbatim; body byte-identical.
    assert r["headers"]["idempotency-key"] == "idem-1"
    assert r["headers"]["content-type"] == "application/x-www-form-urlencoded"
    assert r["body"] == STRIPE_FORM.encode()


@pytest.mark.asyncio
async def test_transit_test_key_on_live_client_raises():
    fake = FakeClient(sandbox=False)
    async with _async_wrapped(fake) as http:
        with pytest.raises(WrapSandboxMismatchError):
            await http.post(
                "https://api.stripe.com/v1/charges",
                headers={"authorization": "Bearer sk_test_x"},
                content="",
            )
    assert fake.ephemeral_calls == []


@pytest.mark.asyncio
async def test_transit_live_key_on_sandbox_client_raises():
    fake = FakeClient(sandbox=True)
    async with _async_wrapped(fake) as http:
        with pytest.raises(WrapSandboxMismatchError):
            await http.post(
                "https://api.stripe.com/v1/charges",
                headers={"authorization": "Bearer sk_live_x"},
                content="",
            )


@pytest.mark.asyncio
async def test_transit_accepts_restricted_key_matching_sandbox():
    fake = FakeClient(sandbox=False)
    async with _async_wrapped(fake) as http:
        await http.post(
            "https://api.stripe.com/v1/charges",
            headers={"authorization": "Bearer rk_live_restricted"},
            content="",
        )
    assert fake.ephemeral_calls[0]["upstream_authorization"] == "Bearer rk_live_restricted"


@pytest.mark.asyncio
async def test_transit_rejects_publishable_key():
    fake = FakeClient(sandbox=False)
    async with _async_wrapped(fake) as http:
        with pytest.raises(WrapSandboxMismatchError):
            await http.post(
                "https://api.stripe.com/v1/charges",
                headers={"authorization": "Bearer pk_live_x"},
                content="",
            )


@pytest.mark.asyncio
async def test_transit_leading_space_before_bearer_still_checked():
    # Regression (#1): a leading space must not let the classifier skip the check.
    fake = FakeClient(sandbox=True)
    async with _async_wrapped(fake) as http:
        with pytest.raises(WrapSandboxMismatchError):
            await http.post(
                "https://api.stripe.com/v1/charges",
                headers={"authorization": " Bearer sk_live_x"},
                content="",
            )


@pytest.mark.asyncio
async def test_transit_does_not_forward_or_lift_when_no_auth():
    fake = FakeClient(sandbox=False)
    async with _async_wrapped(fake) as http:
        await http.post("https://api.example.com/x", content="raw-bytes")
    r = fake.ephemeral_calls[0]
    assert r["upstream_authorization"] is None
    # No Content-Type was set by the caller; the transport must not invent one.
    assert "content-type" not in {k.lower() for k in r["headers"]}


# ── Escrow mode ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_escrow_sends_secret_ref_and_never_a_raw_key():
    fake = FakeClient(sandbox=False)
    async with _async_wrapped(fake, credential={"secret": "wrap-stripe-live"}) as http:
        await http.post(
            "https://api.stripe.com/v1/charges",
            headers={
                "authorization": "Bearer sk_managed_by_knoxcall",
                "content-type": "application/x-www-form-urlencoded",
            },
            content=STRIPE_FORM,
        )
    r = fake.ephemeral_calls[0]
    assert r["upstream_auth_secret"] == "wrap-stripe-live"
    # The placeholder key the SDK set is NOT lifted out-of-band.
    assert r["upstream_authorization"] is None
    assert "authorization" not in r["headers"]
    assert r["body"] == STRIPE_FORM.encode()


@pytest.mark.asyncio
async def test_escrow_passes_custom_scheme():
    fake = FakeClient(sandbox=False)
    async with _async_wrapped(
        fake, credential={"secret": "wrap-x", "scheme": "none"}
    ) as http:
        await http.post("https://api.example.com/x", content="")
    assert fake.ephemeral_calls[0]["upstream_auth_scheme"] == "none"


def test_escrow_malformed_credential_raises_typeerror():
    # Regression (#7): a malformed escrow credential must fail loud, never fall
    # through to transit mode and leak the SDK's raw key.
    with pytest.raises(TypeError):
        KnoxWrapAsyncTransport(FakeClient(), credential={})
    with pytest.raises(TypeError):
        KnoxWrapAsyncTransport(FakeClient(), credential={"secret": ""})


# ── Client-side route-around ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_route_around_raw_card_goes_direct():
    fake = FakeClient(sandbox=False)
    seen_direct: list[str] = []
    around_hook: list[dict[str, str]] = []

    def direct_handler(req: httpx.Request) -> httpx.Response:
        seen_direct.append(str(req.url))
        return httpx.Response(200, json={"id": "tok_1"})

    transport = KnoxWrapAsyncTransport(
        fake,
        direct_transport=httpx.MockTransport(direct_handler),
        on_route_around=around_hook.append,
    )
    async with httpx.AsyncClient(transport=transport) as http:
        await http.post(
            "https://api.stripe.com/v1/tokens",
            headers={"authorization": "Bearer sk_live_x"},
            content="card[number]=4242424242424242",
        )

    # Went direct — the ephemeral hook was never touched.
    assert fake.ephemeral_calls == []
    assert seen_direct == ["https://api.stripe.com/v1/tokens"]
    assert around_hook and around_hook[0]["host"] == "api.stripe.com"


@pytest.mark.asyncio
async def test_route_around_trailing_dot_host_still_matches():
    # Regression (#2): a trailing-dot FQDN must still route around.
    fake = FakeClient(sandbox=False)
    seen_direct: list[str] = []
    transport = KnoxWrapAsyncTransport(
        fake,
        direct_transport=httpx.MockTransport(
            lambda req: seen_direct.append(str(req.url)) or httpx.Response(200)
        ),
    )
    async with httpx.AsyncClient(transport=transport) as http:
        await http.post(
            "https://api.stripe.com./v1/tokens",
            headers={"authorization": "Bearer sk_live_x"},
            content="card[number]=4242",
        )
    assert len(seen_direct) == 1
    assert fake.ephemeral_calls == []


@pytest.mark.asyncio
async def test_route_around_does_not_trigger_on_normal_endpoint():
    fake = FakeClient(sandbox=False)
    direct_hit = False

    def direct_handler(req: httpx.Request) -> httpx.Response:
        nonlocal direct_hit
        direct_hit = True
        return httpx.Response(200)

    transport = KnoxWrapAsyncTransport(
        fake, direct_transport=httpx.MockTransport(direct_handler)
    )
    async with httpx.AsyncClient(transport=transport) as http:
        await http.post(
            "https://api.stripe.com/v1/charges",
            headers={"authorization": "Bearer sk_live_x"},
            content=STRIPE_FORM,
        )
    assert direct_hit is False
    assert len(fake.ephemeral_calls) == 1
    assert fake.ephemeral_calls[0]["url"] == "https://api.stripe.com/v1/charges"


@pytest.mark.asyncio
async def test_route_around_honours_extra_rule():
    fake = FakeClient(sandbox=False)
    seen_direct: list[str] = []
    transport = KnoxWrapAsyncTransport(
        fake,
        direct_transport=httpx.MockTransport(
            lambda req: seen_direct.append(str(req.url)) or httpx.Response(200)
        ),
        route_around=[RouteAroundRule(host="files.stripe.com", reason="multipart upload")],
    )
    async with httpx.AsyncClient(transport=transport) as http:
        await http.post(
            "https://files.stripe.com/v1/files",
            headers={"authorization": "Bearer sk_live_x"},
            content="x",
        )
    assert len(seen_direct) == 1
    assert fake.ephemeral_calls == []


def test_route_around_non_bare_host_raises():
    # Regression (#10): a host with a scheme can never match — fail loud.
    with pytest.raises(WrapSandboxMismatchError):
        KnoxWrapAsyncTransport(
            FakeClient(), route_around=[{"host": "https://api.stripe.com", "reason": "x"}]
        )


# ── Route mode + promoted-route hint (PR6 parity) ──────────────────────────────


@pytest.mark.asyncio
async def test_route_mode_sends_via_durable_route_no_upstream_credential():
    fake = FakeClient(sandbox=False)
    async with _async_wrapped(fake, route="stripe-api") as http:
        await http.post(
            "https://api.stripe.com/v1/charges?limit=3",
            headers={
                "authorization": "Bearer sk_live_x",
                "content-type": "application/x-www-form-urlencoded",
            },
            content=STRIPE_FORM,
        )
    assert fake.ephemeral_calls == []
    assert len(fake.route_calls) == 1
    c = fake.route_calls[0]
    assert c["route"] == "stripe-api"
    assert c["method"] == "POST"
    assert c["path"] == "/v1/charges?limit=3"
    # The route injects the stored secret: no provider credential travels.
    assert "authorization" not in c["headers"]
    assert c["body"] == STRIPE_FORM.encode()


@pytest.mark.asyncio
async def test_promoted_hint_fires_but_does_not_auto_switch_by_default():
    fake = FakeClient(sandbox=False, promoted="stripe-api")
    promoted: list[dict[str, str]] = []
    async with _async_wrapped(fake, on_promoted=promoted.append) as http:
        await http.post(
            "https://api.stripe.com/v1/charges",
            headers={"authorization": "Bearer sk_live_x"},
            content="",
        )
        await http.post(
            "https://api.stripe.com/v1/charges",
            headers={"authorization": "Bearer sk_live_x"},
            content="",
        )
    # Both calls stayed on the ephemeral path.
    assert len(fake.ephemeral_calls) == 2
    assert fake.route_calls == []
    assert promoted[0] == {"host": "api.stripe.com", "slug": "stripe-api"}


@pytest.mark.asyncio
async def test_auto_switch_moves_subsequent_calls_to_the_route():
    fake = FakeClient(sandbox=False, promoted="stripe-api")
    async with _async_wrapped(fake, auto_switch=True) as http:
        await http.post(
            "https://api.stripe.com/v1/charges",
            headers={"authorization": "Bearer sk_live_x"},
            content="",
        )
        await http.post(
            "https://api.stripe.com/v1/charges",
            headers={"authorization": "Bearer sk_live_x"},
            content="",
        )
    # First call ephemeral (learns the hint); second switched to the route.
    assert len(fake.ephemeral_calls) == 1
    assert len(fake.route_calls) == 1
    assert fake.route_calls[0]["route"] == "stripe-api"


# ── Timeout / cancellation preservation ────────────────────────────────────────


@pytest.mark.asyncio
async def test_caller_timeout_is_preserved_on_the_proxy_call():
    fake = FakeClient(sandbox=False)
    transport = KnoxWrapAsyncTransport(fake)
    async with httpx.AsyncClient(transport=transport, timeout=httpx.Timeout(12.5)) as http:
        await http.post(
            "https://api.stripe.com/v1/charges",
            headers={"authorization": "Bearer sk_live_x"},
            content="",
        )
    assert fake.ephemeral_calls[0]["timeout"] == 12.5


# ── Sync transport ─────────────────────────────────────────────────────────────


def _sync_runner(coro: Any) -> Any:
    """Drive a coroutine to completion synchronously (test stand-in for the sync
    client's background-loop runner)."""
    return asyncio.run(coro)


def test_sync_transport_transit_lifts_auth_and_preserves_body():
    fake = FakeClient(sandbox=False)
    transport = KnoxWrapTransport(fake, _sync_runner)
    with httpx.Client(transport=transport) as http:
        http.post(
            "https://api.stripe.com/v1/charges",
            headers={
                "authorization": "Bearer sk_live_provider",
                "content-type": "application/x-www-form-urlencoded",
            },
            content=STRIPE_FORM,
        )
    r = fake.ephemeral_calls[0]
    assert r["url"] == "https://api.stripe.com/v1/charges"
    assert r["mode"] == "transparent"
    assert r["upstream_authorization"] == "Bearer sk_live_provider"
    assert r["body"] == STRIPE_FORM.encode()


def test_sync_transport_route_around_goes_direct():
    fake = FakeClient(sandbox=False)
    seen_direct: list[str] = []
    transport = KnoxWrapTransport(
        fake,
        _sync_runner,
        direct_transport=httpx.MockTransport(
            lambda req: seen_direct.append(str(req.url)) or httpx.Response(200, json={"id": "tok_1"})
        ),
    )
    with httpx.Client(transport=transport) as http:
        http.post(
            "https://api.stripe.com/v1/tokens",
            headers={"authorization": "Bearer sk_live_x"},
            content="card[number]=4242",
        )
    assert seen_direct == ["https://api.stripe.com/v1/tokens"]
    assert fake.ephemeral_calls == []


def test_sync_transport_sandbox_mismatch_raises():
    fake = FakeClient(sandbox=False)
    transport = KnoxWrapTransport(fake, _sync_runner)
    with httpx.Client(transport=transport) as http:
        with pytest.raises(WrapSandboxMismatchError):
            http.post(
                "https://api.stripe.com/v1/charges",
                headers={"authorization": "Bearer sk_test_x"},
                content="",
            )


# ── Accessor wiring: knox.wrap.transport() / knox.wrap.client() ────────────────


@pytest.mark.asyncio
async def test_async_accessor_returns_working_transport(monkeypatch):
    calls: list[dict[str, Any]] = []

    async def fake_ephemeral(upstream_url, **kw):
        calls.append({"url": upstream_url, **kw})
        return httpx.Response(200, json={"ok": True})

    client = KnoxCallAsync(tenant="acme", base_url="https://api.test", bootstrap=AccessToken(access_token="kc_live_x"))
    monkeypatch.setattr(client, "ephemeral", fake_ephemeral)

    transport = client.wrap.transport()
    assert isinstance(transport, KnoxWrapAsyncTransport)
    async with httpx.AsyncClient(transport=transport) as http:
        await http.post(
            "https://api.stripe.com/v1/charges",
            headers={"authorization": "Bearer sk_live_x"},
            content=STRIPE_FORM,
        )
    await client.__aexit__(None, None, None)

    assert calls and calls[0]["url"] == "https://api.stripe.com/v1/charges"
    assert calls[0]["upstream_authorization"] == "Bearer sk_live_x"
    assert calls[0]["mode"] == "transparent"


def test_sync_accessor_returns_working_transport():
    calls: list[dict[str, Any]] = []

    async def fake_ephemeral(upstream_url, **kw):
        calls.append({"url": upstream_url, **kw})
        return httpx.Response(200, json={"ok": True})

    with KnoxCall(
        tenant="acme",
        base_url="https://api.test",
        bootstrap=AccessToken(access_token="kc_live_x"),
    ) as client:
        client._async.ephemeral = fake_ephemeral  # type: ignore[method-assign]
        transport = client.wrap.transport()
        assert isinstance(transport, KnoxWrapTransport)
        with httpx.Client(transport=transport) as http:
            http.post(
                "https://api.stripe.com/v1/charges",
                headers={"authorization": "Bearer sk_live_x"},
                content=STRIPE_FORM,
            )

    assert calls and calls[0]["url"] == "https://api.stripe.com/v1/charges"
    assert calls[0]["upstream_authorization"] == "Bearer sk_live_x"
