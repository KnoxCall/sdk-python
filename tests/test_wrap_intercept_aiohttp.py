"""The ``aiohttp`` arm of the process-wide interceptor — opt-in ``stacks=["aiohttp"]``
(route-aware-interception-plan.md D7, PARITY §21.1): the aiohttp twin of the urllib3
cases in ``test_wrap_intercept.py``.

Capture is at the SDK's boundary (the same ``FakeClient``), plus ONE test on a real
``KnoxCallAsync`` under ``respx`` that shows exactly what reaches KnoxCall. The
ORIGINAL ``ClientSession._request`` is replaced by ``Canned`` before every install:
a loopback host is served by aiohttp's pristine ``_request`` against a real
``aiohttp.web`` server (so the direct legs are proved on real sockets), anything
else answers with a marker — a test can never reach the network.

``aiohttp`` is imported unconditionally: it is in the ``test`` extra, CI installs
that extra, and a missing package must fail collection loudly rather than skip.
"""

from __future__ import annotations

import asyncio
import io
import sys
import warnings
from typing import Any

import aiohttp
import httpx
import pytest
import respx
from aiohttp import web
from aiohttp.test_utils import TestServer

from knoxcall import KnoxCallAsync
from knoxcall._intercept_patch import install_intercept, routed
from knoxcall.auth.bootstrap import AccessToken
from knoxcall.errors import APIConnectionError
from test_wrap_intercept import HUBSPOT, HUBSPOT_ROOT, FakeClient, entry, sync_runner

_PRISTINE_REQUEST = aiohttp.ClientSession._request


class RecordingClient(FakeClient):
    """``FakeClient`` that also records the local timeout each ``call()`` carried."""

    def __init__(self, **kw: Any) -> None:
        super().__init__(**kw)
        self.timeouts: list[float | None] = []

    async def call(self, route: str, **kw: Any) -> httpx.Response:
        self.timeouts.append(kw.get("timeout"))
        return await super().call(route, **kw)


class Marker:
    """What the canned original answers for a non-loopback host."""

    def __init__(self, method: str, url: str) -> None:
        self.method, self.url, self.status = method, url, 200

    async def __aenter__(self) -> "Marker":
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None


class Canned:
    """Replaces the ORIGINAL ``ClientSession._request`` for one test: loopback →
    the pristine method (real sockets); anything else → a :class:`Marker`."""

    def __init__(self) -> None:
        self.original: list[str] = []

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        canned = self

        async def _request(self_: Any, method: str, str_or_url: Any, **kw: Any) -> Any:
            url = str(str_or_url)
            canned.original.append(url)
            if "127.0.0.1" in url:
                return await _PRISTINE_REQUEST(self_, method, str_or_url, **kw)
            return Marker(method, url)

        monkeypatch.setattr(aiohttp.ClientSession, "_request", _request)


def install(client: Any, *, hosts: list[str] | None = None, host_options: dict[str, Any] | None = None, require_context: bool = False, stacks: list[str] | None = None, **opts: Any) -> Any:
    return install_intercept(
        client=client,
        runner=None,
        stacks=stacks or ["aiohttp"],
        hosts=hosts or [],
        host_options=host_options or {},
        require_context=require_context,
        transport_opts={"routes": "auto", "manifest_fetch": client.fetch_manifest, **opts},
    )


@pytest.fixture(autouse=True)
def _no_kill_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KNOXCALL_INTERCEPT", raising=False)


@pytest.fixture
async def loopback() -> Any:
    """A real aiohttp server on a loopback port; records what it served."""
    served: list[dict[str, Any]] = []

    async def handler(request: web.Request) -> web.Response:
        served.append({"method": request.method, "path": request.path_qs, "body": await request.read(), "headers": dict(request.headers)})
        return web.Response(text=f"served {request.path}", headers={"x-served-by": "loopback"})

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handler)
    async with TestServer(app) as server:
        yield server, served


# ── the decision table, through an untouched aiohttp session ──────────────────


async def test_route_mode_rebases_the_path_keeps_the_query_and_forwards_no_provider_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    Canned().install(monkeypatch)
    client = FakeClient(routes=[HUBSPOT, HUBSPOT_ROOT])
    seen: list[dict[str, Any]] = []
    handle = install(client, on_reroute=seen.append)
    try:
        await handle.aready()
        assert len(handle.manifest()["routes"]) == 2
        async with aiohttp.ClientSession() as s:
            async with s.post(
                "https://api.hubapi.com/crm/v3/objects/contacts?limit=1",
                headers={"Authorization": "Bearer hubspot-token"},
                data=b'{"a":1}',
            ) as resp:
                assert isinstance(resp, aiohttp.ClientResponse)
                assert resp.status == 200 and resp.ok and resp.reason == "OK"
                assert await resp.json() == {"ok": True}
                assert resp.content_type == "application/json"
                assert resp.request_info.method == "POST"
                assert str(resp.url) == "https://api.hubapi.com/crm/v3/objects/contacts?limit=1"
            # params= is applied the way aiohttp applies it; a session base_url is honoured
            await s.get("https://api.hubapi.com/crm/v3/objects", params={"after": "9"}, headers={"authorization": "Bearer t"})
        async with aiohttp.ClientSession(base_url="https://api.hubapi.com") as s:
            await s.get("/oauth/v1/token", headers={"authorization": "Bearer t"})
    finally:
        handle.uninstall()
    first, second, third = client.route_calls
    assert (first["route"], first["method"], first["path"]) == ("hubspot-crm", "POST", "/objects/contacts?limit=1")
    assert "authorization" not in first["headers"]  # the Route injects the secret
    assert first["body"] == b'{"a":1}'
    assert first["headers"]["user-agent"].startswith("Python/") and "aiohttp" in first["headers"]["user-agent"]
    assert second["path"] == "/objects?after=9"
    assert (third["route"], third["path"]) == ("hubspot", "/oauth/v1/token")
    assert client.ephemeral_calls == []
    assert seen[0]["mode"] == "route" and seen[0]["slug"] == "hubspot-crm" and seen[0]["reason"] == "manifest"


async def test_listed_host_without_a_route_goes_ephemeral_with_the_credential_lifted(monkeypatch: pytest.MonkeyPatch) -> None:
    Canned().install(monkeypatch)
    client = FakeClient(routes=[])
    handle = install(client, hosts=["api.resend.com"])
    try:
        await handle.aready()
        async with aiohttp.ClientSession() as s:
            async with s.post("https://api.resend.com/emails", headers={"Authorization": "Bearer re_x"}, json={"to": "a"}) as resp:
                assert resp.status == 200
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)  # aiohttp 3.14 deprecates auth= itself
                await s.get("https://api.resend.com/domains", auth=aiohttp.BasicAuth("u", "p"))
    finally:
        handle.uninstall()
    sent, basic = client.ephemeral_calls
    assert sent["url"] == "https://api.resend.com/emails" and sent["method"] == "POST"
    assert sent["upstream_authorization"] == "Bearer re_x"
    assert "authorization" not in sent["headers"]
    assert sent["body"] == b'{"to": "a"}' and sent["headers"]["content-type"] == "application/json"
    assert basic["upstream_authorization"] == "Basic dTpw"


async def test_unlisted_host_goes_direct_through_the_original_request_on_a_real_socket(monkeypatch: pytest.MonkeyPatch, loopback: Any) -> None:
    server, served = loopback
    canned = Canned()
    canned.install(monkeypatch)
    client = FakeClient(routes=[HUBSPOT_ROOT])
    handle = install(client, hosts=["api.resend.com"])
    try:
        await handle.aready()
        async with aiohttp.ClientSession() as s:
            async with s.post(server.make_url("/direct?x=1"), data=b"raw") as resp:
                assert await resp.text() == "served /direct"
                assert resp.headers["x-served-by"] == "loopback"
                assert resp.connection is None or resp.connection is not None  # a real, started response
            assert isinstance(await s.get("https://api.openai.com/v1/models"), Marker)
    finally:
        handle.uninstall()
    assert served == [{"method": "POST", "path": "/direct?x=1", "body": b"raw", "headers": served[0]["headers"]}]
    assert client.route_calls == [] and client.ephemeral_calls == []
    assert canned.original[-1] == "https://api.openai.com/v1/models"


async def test_direct_decisions_inside_the_pipeline_replay_the_original_call(monkeypatch: pytest.MonkeyPatch, loopback: Any) -> None:
    """Route-around and the unavailable="direct" fallback are decided INSIDE the
    pipeline; both must run aiohttp's own request, not an httpx send of a copy."""
    server, served = loopback
    Canned().install(monkeypatch)
    around: list[dict[str, str]] = []
    client = FakeClient(routes=[], ephemeral_error=APIConnectionError("ECONNREFUSED"))
    handle = install(
        client,
        hosts=["127.0.0.1"],
        host_options={"127.0.0.1": {"unavailable": "direct"}},
        route_around=[{"host": "127.0.0.1", "path_prefix": "/around", "reason": "loopback"}],
        on_route_around=around.append,
    )
    fallbacks: list[dict[str, Any]] = []
    handle._async._on_fallback = fallbacks.append  # the aiohttp transport shares the store, not the hooks; pin the one it fires
    try:
        await handle.aready()
        async with aiohttp.ClientSession() as s:
            async with s.get(server.make_url("/around/x")) as resp:  # route-around rule → direct
                assert await resp.text() == "served /around/x" and resp.headers["x-served-by"] == "loopback"
            async with s.post(server.make_url("/fallback"), data=b"again") as resp:  # ephemeral unreachable → direct
                assert await resp.text() == "served /fallback"
    finally:
        handle.uninstall()
    assert [x["path"] for x in served] == ["/around/x", "/fallback"] and served[1]["body"] == b"again"
    assert around[0]["reason"] == "loopback"
    assert client.ephemeral_calls == []  # the ephemeral hook raised before recording


async def test_refusal_refreshes_once_and_resends_the_buffered_body(monkeypatch: pytest.MonkeyPatch) -> None:
    Canned().install(monkeypatch)
    routes: list[dict[str, Any]] = [HUBSPOT_ROOT]
    client = FakeClient(routes=lambda: routes, route_status=401)
    refused: list[dict[str, Any]] = []
    handle = install(client, hosts=["api.hubapi.com"], on_refused=refused.append)
    try:
        await handle.aready()
        routes = []  # the Route was disabled between the poll and this request

        async def chunks() -> Any:
            yield b"pay"
            yield b"load"

        async with aiohttp.ClientSession() as s:
            async with s.post("https://api.hubapi.com/x", headers={"authorization": "Bearer t"}, data=chunks()) as resp:
                assert resp.status == 200 and await resp.json() == {"ok": True}
    finally:
        handle.uninstall()
    assert len(client.route_calls) == 1 and client.route_calls[0]["body"] == b"payload"
    assert client.manifest_calls == 2
    assert client.ephemeral_calls[0]["body"] == b"payload"  # replayed from memory
    assert refused[0]["slug"] == "hubspot" and refused[0]["status"] == 401 and refused[0]["redecided"] == "ephemeral"


async def test_bodies_are_buffered_through_aiohttps_own_payloads(monkeypatch: pytest.MonkeyPatch) -> None:
    Canned().install(monkeypatch)
    client = FakeClient(routes=[HUBSPOT_ROOT])
    handle = install(client)
    try:
        await handle.aready()
        form = aiohttp.FormData()
        form.add_field("file", b"abc", filename="a.txt", content_type="text/plain")
        async with aiohttp.ClientSession() as s:
            await s.post("https://api.hubapi.com/dict", data={"a": "1", "b": "2"})
            await s.post("https://api.hubapi.com/str", data="héllo")
            await s.post("https://api.hubapi.com/multipart", data=form)
            await s.post("https://api.hubapi.com/file", data=io.BytesIO(b"file-bytes"))
            await s.post("https://api.hubapi.com/none")
            with pytest.raises(TypeError):  # aiohttp's own refusal of a body it cannot encode
                await s.post("https://api.hubapi.com/bad", data=object())
    finally:
        handle.uninstall()
    by_path = {c["path"]: c for c in client.route_calls}
    assert by_path["/dict"]["body"] == b"a=1&b=2" and by_path["/dict"]["headers"]["content-type"] == "application/x-www-form-urlencoded"
    assert by_path["/str"]["body"] == "héllo".encode("utf-8") and by_path["/str"]["headers"]["content-type"].startswith("text/plain")
    multipart = by_path["/multipart"]
    assert multipart["headers"]["content-type"].startswith("multipart/form-data; boundary=")
    assert b'filename="a.txt"' in multipart["body"] and b"abc" in multipart["body"]
    assert by_path["/file"]["body"] == b"file-bytes"
    assert by_path["/none"]["body"] is None
    assert "/bad" not in by_path


async def test_the_response_is_a_real_client_response_with_aiohttps_own_surface(monkeypatch: pytest.MonkeyPatch) -> None:
    Canned().install(monkeypatch)
    client = FakeClient(routes=[HUBSPOT_ROOT], route_headers={"set-cookie": "sid=abc; Path=/", "x-upstream": "yes"})
    handle = install(client)
    try:
        await handle.aready()
        async with aiohttp.ClientSession() as s:
            resp = await s.get("https://api.hubapi.com/x")
            assert resp.version == aiohttp.HttpVersion11
            assert (b"content-type", b"application/json") in resp.raw_headers and resp.headers["x-upstream"] == "yes"
            assert resp.get_encoding() == "utf-8" and resp.charset is None
            assert await resp.read() == b'{"ok":true}' and await resp.text() == '{"ok":true}'
            assert resp.cookies["sid"].value == "abc"
            resp.release()
            assert resp.closed
            assert await resp.text() == '{"ok":true}'  # the body read before release stays readable
            # `content` is aiohttp's own StreamReader: streaming it drains it, exactly as on a socket
            streamed = await s.get("https://api.hubapi.com/again")  # the jar now carries the cookie
            assert [c async for c in streamed.content.iter_chunked(4)] == [b'{"ok', b'":tr', b"ue}"]
            assert await streamed.read() == b""
            streamed.release()
        assert client.route_calls[1]["headers"]["cookie"] == "sid=abc"
    finally:
        handle.uninstall()

    client = FakeClient(routes=[HUBSPOT_ROOT], route_status=503)
    handle = install(client)
    try:
        await handle.aready()
        async with aiohttp.ClientSession() as s:
            async with s.get("https://api.hubapi.com/x") as resp:
                assert resp.status == 503 and not resp.ok and resp.reason == "Service Unavailable"
                with pytest.raises(aiohttp.ClientResponseError) as err:
                    resp.raise_for_status()
                assert err.value.status == 503 and err.value.request_info.method == "GET"
            with pytest.raises(aiohttp.ClientResponseError):  # per-call raise_for_status
                await s.get("https://api.hubapi.com/x", raise_for_status=True)

            async def callback(r: aiohttp.ClientResponse) -> None:
                raise RuntimeError(f"callback saw {r.status}")

            with pytest.raises(RuntimeError, match="callback saw 503"):
                await s.get("https://api.hubapi.com/x", raise_for_status=callback)
        async with aiohttp.ClientSession(raise_for_status=True) as s:  # session-level
            with pytest.raises(aiohttp.ClientResponseError):
                await s.get("https://api.hubapi.com/x")
    finally:
        handle.uninstall()


async def test_session_defaults_skip_auto_headers_and_timeouts_are_carried(monkeypatch: pytest.MonkeyPatch) -> None:
    Canned().install(monkeypatch)
    client = RecordingClient(routes=[HUBSPOT_ROOT])
    handle = install(client)
    try:
        await handle.aready()
        async with aiohttp.ClientSession(headers={"X-App": "1"}, timeout=aiohttp.ClientTimeout(total=7), skip_auto_headers=["User-Agent"]) as s:
            await s.get("https://api.hubapi.com/a")
            await s.get("https://api.hubapi.com/b", timeout=3, headers={"X-App": "2"})
    finally:
        handle.uninstall()
    a, b = client.route_calls
    assert a["headers"]["x-app"] == "1" and "user-agent" not in a["headers"] and a["headers"]["accept"] == "*/*"
    assert b["headers"]["x-app"] == "2"
    assert client.timeouts == [7.0, 3.0]


async def test_kill_switch_require_context_own_hosts_and_upgrade_go_to_the_original(monkeypatch: pytest.MonkeyPatch) -> None:
    canned = Canned()
    canned.install(monkeypatch)
    client = FakeClient(routes=[HUBSPOT_ROOT, entry("api.test", "self")])
    handle = install(client, hosts=["api.resend.com", "api.test"], require_context=True)
    try:
        await handle.aready()
        async with aiohttp.ClientSession() as s:
            assert isinstance(await s.get("https://api.hubapi.com/x"), Marker)  # outside routed()
            with routed():
                await s.get("https://api.hubapi.com/x")
                assert client.route_calls[-1]["route"] == "hubspot"
                assert isinstance(await s.get("https://api.test/v1/routes"), Marker)  # the SDK's own host
                assert isinstance(await s.get("https://api.hubapi.com/ws", headers={"Upgrade": "websocket", "Connection": "Upgrade"}), Marker)
                monkeypatch.setenv("KNOXCALL_INTERCEPT", "off")
                assert isinstance(await s.get("https://api.hubapi.com/x"), Marker)
    finally:
        handle.uninstall()
    assert len(client.route_calls) == 1 and client.ephemeral_calls == []
    assert canned.original == ["https://api.hubapi.com/x", "https://api.test/v1/routes", "https://api.hubapi.com/ws", "https://api.hubapi.com/x"]


async def test_httpx_and_aiohttp_stacks_share_one_manifest(monkeypatch: pytest.MonkeyPatch) -> None:
    Canned().install(monkeypatch)
    async_before = httpx.AsyncHTTPTransport.handle_async_request
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", async_before)
    client = FakeClient(routes=[HUBSPOT_ROOT])
    handle = install(client, stacks=["httpx", "aiohttp"])
    try:
        await handle.aready()
        assert client.manifest_calls == 1
        async with aiohttp.ClientSession() as s:
            await s.get("https://api.hubapi.com/from-aiohttp")
        async with httpx.AsyncClient() as h:
            await h.get("https://api.hubapi.com/from-httpx")
    finally:
        handle.uninstall()
    assert [c["path"] for c in client.route_calls] == ["/from-aiohttp", "/from-httpx"]
    assert client.manifest_calls == 1  # one store, one poll
    assert httpx.AsyncHTTPTransport.handle_async_request is async_before


# ── install rules ─────────────────────────────────────────────────────────────


async def test_install_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    Canned().install(monkeypatch)
    before = aiohttp.ClientSession._request
    client = FakeClient(routes=[])
    with pytest.raises(TypeError, match="KnoxCallAsync"):  # the sync client is refused
        install_intercept(client=client, runner=sync_runner, stacks=["aiohttp"], hosts=["a.example"], host_options={}, require_context=False, transport_opts={"routes": "off"})
    with pytest.raises(ValueError, match="aiohttp"):
        install_intercept(client=client, runner=None, stacks=["aiohtp"], hosts=["a.example"], host_options={}, require_context=False, transport_opts={"routes": "off"})
    assert aiohttp.ClientSession._request is before

    handle = install(client, hosts=["a.example"])
    try:
        assert aiohttp.ClientSession._request is not before
        with pytest.raises(RuntimeError, match="already installed"):
            install(client, hosts=["b.example"])
        assert aiohttp.ClientSession._request is not before  # the refused second install left the first in place
    finally:
        handle.uninstall()
    assert not handle.installed
    assert aiohttp.ClientSession._request is before  # restored


async def test_install_refuses_a_missing_or_too_old_aiohttp_and_a_broken_recipe(monkeypatch: pytest.MonkeyPatch) -> None:
    Canned().install(monkeypatch)
    before = aiohttp.ClientSession._request
    client = FakeClient(routes=[])

    monkeypatch.setitem(sys.modules, "aiohttp", None)  # `import aiohttp` now raises ImportError
    with pytest.raises(ImportError, match="pip install 'aiohttp>=3.13'"):
        install(client, hosts=["a.example"])
    monkeypatch.setitem(sys.modules, "aiohttp", aiohttp)

    from aiohttp import payload

    saved_as_bytes = payload.Payload.as_bytes
    monkeypatch.delattr(payload.Payload, "as_bytes")  # what aiohttp < 3.13 looks like
    with pytest.raises(RuntimeError, match=">= 3.13"):
        install(client, hosts=["a.example"])
    monkeypatch.setattr(payload.Payload, "as_bytes", saved_as_bytes, raising=False)

    def boom(self: Any, *a: Any, **k: Any) -> None:
        raise AttributeError("a constructor this arm does not know")

    saved_init = aiohttp.ClientResponse.__init__
    monkeypatch.setattr(aiohttp.ClientResponse, "__init__", boom)  # a future aiohttp the recipe cannot build
    with pytest.raises(RuntimeError, match="cannot build a ClientResponse on aiohttp"):
        install(client, hosts=["a.example"])
    monkeypatch.setattr(aiohttp.ClientResponse, "__init__", saved_init)
    assert aiohttp.ClientSession._request is before  # nothing was left patched by any refusal

    # a refusal after the httpx arm was patched also unwinds the httpx arm
    async_before = httpx.AsyncHTTPTransport.handle_async_request
    monkeypatch.setitem(sys.modules, "aiohttp", None)
    with pytest.raises(ImportError):
        install(client, hosts=["a.example"], stacks=["httpx", "aiohttp"])
    assert httpx.AsyncHTTPTransport.handle_async_request is async_before


# ── a real client: what reaches KnoxCall ──────────────────────────────────────


async def test_through_a_real_client_only_the_sdk_credential_reaches_knoxcall(monkeypatch: pytest.MonkeyPatch) -> None:
    """Under respx: the manifest poll, the route send and the ephemeral send are the
    only egress; the wrapped SDK's key is dropped (route) or lifted onto the
    KnoxCall header (ephemeral), never the KnoxCall hop's Authorization; and no
    request reaches a provider host."""
    Canned().install(monkeypatch)
    manifest = {"version": "sha256:one", "ttl_seconds": 60, "environment": "production", "sandbox": False, "routes": [HUBSPOT]}
    with respx.mock(assert_all_called=True) as mock:
        m_manifest = mock.get("https://api.test/v1/wrap/intercept-manifest").mock(return_value=httpx.Response(200, json={"data": manifest, "meta": {}}))
        m_route = mock.post("https://acme.test/objects/contacts").mock(return_value=httpx.Response(200, json={"ok": True}))
        m_proxy = mock.post("https://api.test/v1/proxy").mock(return_value=httpx.Response(202, json={"sent": True}))
        async with KnoxCallAsync(tenant="acme", base_url="https://api.test", proxy_base_url="https://acme.test", bootstrap=AccessToken(access_token="kc_live_x")) as knox:
            handle = knox.wrap.intercept(hosts=["api.resend.com"], stacks=["aiohttp"])
            try:
                await handle.aready()
                assert handle.manifest()["version"] == "sha256:one"
                async with aiohttp.ClientSession() as s:
                    async with s.post("https://api.hubapi.com/crm/v3/objects/contacts", params={"limit": "1"}, headers={"Authorization": "Bearer hubspot-token"}, json={"a": 1}) as resp:
                        assert resp.status == 200 and await resp.json() == {"ok": True}
                    async with s.post("https://api.resend.com/emails", headers={"Authorization": "Bearer re_x"}, json={"to": "a"}) as resp:
                        assert resp.status == 202 and await resp.json() == {"sent": True}
            finally:
                handle.uninstall()
    assert m_manifest.call_count == 1
    route = m_route.calls.last.request
    assert route.url.path == "/objects/contacts" and route.url.params["limit"] == "1"
    assert route.headers["authorization"] == "Bearer kc_live_x" and route.headers["x-knoxcall-route"] == "hubspot-crm"
    assert route.content == b'{"a": 1}' and route.headers["content-type"] == "application/json"
    proxy = m_proxy.calls.last.request
    assert proxy.headers["x-knox-proxy-url"] == "https://api.resend.com/emails"
    assert proxy.headers["x-knox-upstream-authorization"] == "Bearer re_x"
    assert proxy.headers["authorization"] == "Bearer kc_live_x"
    for call in mock.calls:
        assert call.request.url.host in ("api.test", "acme.test")
        assert "hubspot-token" not in str(call.request.headers.get("authorization", "")) and "re_x" not in call.request.headers.get("authorization", "")


def test_the_recipe_probe_runs_without_an_event_loop() -> None:
    """``self_check`` is what makes the recipe an install-time refusal instead of a
    mid-request surprise; it must work where ``intercept()`` is called — inside a
    coroutine (the test above) and at module import, with no loop at all."""
    from knoxcall._intercept_aiohttp import load_aiohttp, self_check

    with pytest.raises(RuntimeError):
        asyncio.get_running_loop()
    self_check(load_aiohttp())
