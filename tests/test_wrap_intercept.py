"""Route-aware transport + interceptor — the Python mirror of
``sdk/knoxcall-node/test/wrap-intercept.test.ts`` (route-aware-interception-plan.md PR3).

Capture is at the SDK's boundary: a FAKE client records ``call()`` /
``ephemeral()`` and serves the manifest through ``manifest_fetch``, and the
process-wide interceptor is exercised against ``httpx.Client`` /
``httpx.AsyncClient`` / ``requests`` whose ORIGINAL transports are replaced
by a canned responder before install (so an unmatched host never reaches the
network). Every test drives the real store, resolver and senders.
"""

from __future__ import annotations

import asyncio
import warnings
from typing import Any

import httpx
import pytest

from knoxcall import KnoxWrapAsyncTransport, KnoxWrapTransport, routed
from knoxcall._intercept_patch import install_intercept
from knoxcall.errors import APIConnectionError, PermissionDeniedError


def entry(host: str, slug: str, base: str = "/", **over: Any) -> dict[str, Any]:
    return {"host": host, "base_path": base, "slug": slug, "route_id": f"id-{slug}", "requires_clients": False, "allowed_methods": None, "updated_at": None, **over}


HUBSPOT = entry("api.hubapi.com", "hubspot-crm", "/crm/v3")
HUBSPOT_ROOT = entry("api.hubapi.com", "hubspot")


class FakeClient:
    """Records every data-plane call; serves the manifest from ``routes`` (a list,
    a callable, or the string ``"forbidden"``)."""

    def __init__(self, *, routes: Any = (), sandbox: bool = False, route_status: int = 200, route_headers: dict[str, str] | None = None, route_body: Any = None, ephemeral_error: Exception | None = None, promoted: str | None = None) -> None:
        self.sandbox = sandbox
        self.base_url = "https://api.test"
        self.proxy_base_url = "https://acme.test"
        self.environment = None
        self._routes = routes
        self._route_status = route_status
        self._route_headers = route_headers or {}
        self._route_body = route_body if route_body is not None else {"ok": True}
        self._ephemeral_error = ephemeral_error
        self._promoted = promoted
        self.manifest_calls = 0
        self.route_calls: list[dict[str, Any]] = []
        self.ephemeral_calls: list[dict[str, Any]] = []

    async def fetch_manifest(self) -> dict[str, Any]:
        self.manifest_calls += 1
        if self._routes == "forbidden":
            raise PermissionDeniedError("insufficient scope", status=403)
        routes = self._routes() if callable(self._routes) else list(self._routes)
        return {"version": "sha256:" + (",".join(r["slug"] for r in routes) or "empty"), "ttl_seconds": 60, "environment": "production", "sandbox": False, "routes": routes}

    async def call(self, route: str, *, method: str = "GET", path: str = "/", body: Any = None, headers: dict[str, str] | None = None, timeout: float | None = None, **extra: Any) -> httpx.Response:
        self.route_calls.append({"route": route, "method": method, "path": path, "body": body, "headers": headers or {}})
        return httpx.Response(self._route_status, headers={"content-type": "application/json", **self._route_headers}, json=self._route_body)

    async def ephemeral(self, upstream_url: str, *, method: str = "GET", body: Any = None, headers: dict[str, str] | None = None, mode: str | None = None, upstream_authorization: str | None = None, upstream_auth_secret: str | None = None, upstream_auth_scheme: str | None = None, timeout: float | None = None, **extra: Any) -> httpx.Response:
        if self._ephemeral_error is not None:
            raise self._ephemeral_error
        self.ephemeral_calls.append({"url": upstream_url, "method": method, "body": body, "headers": headers or {}, "upstream_authorization": upstream_authorization, "upstream_auth_secret": upstream_auth_secret})
        h = {"content-type": "application/json"}
        if self._promoted:
            h["x-knox-promoted-route"] = self._promoted
        return httpx.Response(200, headers=h, json={"ok": True})


def sync_runner(coro: Any) -> Any:
    return asyncio.run(coro)


class Direct(httpx.BaseTransport):
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(200, text="DIRECT", request=request)


class AsyncDirect(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(200, text="DIRECT", request=request)


def make_sync(client: FakeClient, **opts: Any) -> tuple[KnoxWrapTransport, Direct]:
    direct = Direct()
    t = KnoxWrapTransport(client, sync_runner, direct_transport=direct, manifest_fetch=client.fetch_manifest, **opts)
    return t, direct


@pytest.fixture(autouse=True)
def _no_kill_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KNOXCALL_INTERCEPT", raising=False)


# ── explicit transport, routes="auto" ─────────────────────────────────────────

def test_routes_off_default_never_consults_the_manifest() -> None:
    client = FakeClient(routes=[HUBSPOT])
    t, _ = make_sync(client)
    with httpx.Client(transport=t) as http:
        http.get("https://api.hubapi.com/crm/v3/objects", headers={"authorization": "Bearer t"})
    assert client.manifest_calls == 0
    assert len(client.ephemeral_calls) == 1
    assert t.manifest() is None


def test_route_covering_host_and_path_goes_through_the_route_rebased_with_no_provider_credential() -> None:
    client = FakeClient(routes=[HUBSPOT, HUBSPOT_ROOT])
    seen: list[dict[str, Any]] = []
    t, _ = make_sync(client, routes="auto", on_reroute=seen.append)
    t.ready()
    assert len(t.manifest()["routes"]) == 2
    with httpx.Client(transport=t) as http:
        http.post("https://api.hubapi.com/crm/v3/objects/contacts?limit=1", headers={"authorization": "Bearer hubspot-token"}, content=b'{"a":1}')
    r = client.route_calls[0]
    assert (r["route"], r["method"], r["path"]) == ("hubspot-crm", "POST", "/objects/contacts?limit=1")
    assert "authorization" not in r["headers"]  # the Route injects the secret
    assert r["body"] == b'{"a":1}'
    assert client.ephemeral_calls == []
    assert seen[0]["mode"] == "route" and seen[0]["slug"] == "hubspot-crm" and seen[0]["reason"] == "manifest"


def test_path_outside_the_deeper_base_falls_to_the_root_route_and_uncovered_host_goes_ephemeral() -> None:
    client = FakeClient(routes=[HUBSPOT, HUBSPOT_ROOT])
    t, _ = make_sync(client, routes="auto")
    t.ready()
    with httpx.Client(transport=t) as http:
        http.post("https://api.hubapi.com/oauth/v1/token", headers={"authorization": "Bearer t"}, content=b"")
        http.post("https://api.resend.com/emails", headers={"authorization": "Bearer re_x"}, content=b"{}")
    assert client.route_calls[0]["route"] == "hubspot" and client.route_calls[0]["path"] == "/oauth/v1/token"
    assert client.ephemeral_calls[0]["url"] == "https://api.resend.com/emails"
    assert client.ephemeral_calls[0]["upstream_authorization"] == "Bearer re_x"


def test_own_hosts_are_never_routed_and_the_kill_switch_makes_everything_direct(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeClient(routes=[HUBSPOT_ROOT])
    t, direct = make_sync(client, routes="auto")
    t.ready()
    with httpx.Client(transport=t) as http:
        http.get("https://api.test/v1/routes")
        assert len(direct.requests) == 1
        monkeypatch.setenv("KNOXCALL_INTERCEPT", "off")
        r = http.get("https://api.hubapi.com/crm/v3/objects")
        assert r.text == "DIRECT"
    assert client.route_calls == [] and client.ephemeral_calls == []


def test_knoxcall_origin_401_in_route_mode_refreshes_once_and_resends_ephemeral_when_the_route_is_gone() -> None:
    routes: list[dict[str, Any]] = [HUBSPOT_ROOT]
    client = FakeClient(routes=lambda: routes, route_status=401)
    refused: list[dict[str, Any]] = []
    t, _ = make_sync(client, routes="auto", on_refused=refused.append)
    t.ready()
    routes = []  # the Route was disabled between the poll and this request
    with httpx.Client(transport=t) as http:
        r = http.post("https://api.hubapi.com/x", headers={"authorization": "Bearer t"}, content=b"payload")
    assert r.status_code == 200
    assert len(client.route_calls) == 1  # the fake client has no re-mint; one refusal, one refresh
    assert client.manifest_calls == 2
    assert client.ephemeral_calls[0]["body"] == b"payload"
    assert refused[0]["slug"] == "hubspot" and refused[0]["status"] == 401 and refused[0]["redecided"] == "ephemeral"


def test_knoxcall_origin_401_whose_refresh_changes_nothing_is_returned_as_is_never_a_loop() -> None:
    client = FakeClient(routes=[HUBSPOT_ROOT], route_status=401)
    refused: list[dict[str, Any]] = []
    t, _ = make_sync(client, routes="auto", on_refused=refused.append)
    t.ready()
    with httpx.Client(transport=t) as http:
        r = http.post("https://api.hubapi.com/x", headers={"authorization": "Bearer t"}, content=b"payload")
    assert r.status_code == 401
    assert len(client.route_calls) == 1
    assert client.manifest_calls == 2
    assert client.ephemeral_calls == []
    assert refused[0]["redecided"] is None


def test_upstream_401_through_the_route_is_not_a_refusal() -> None:
    client = FakeClient(routes=[HUBSPOT_ROOT], route_status=401, route_headers={"x-knox-upstream-status": "401"})
    t, _ = make_sync(client, routes="auto")
    t.ready()
    with httpx.Client(transport=t) as http:
        r = http.get("https://api.hubapi.com/x", headers={"authorization": "Bearer t"})
    assert r.status_code == 401
    assert client.manifest_calls == 1


# Founder decision 2026-09-26: an AUTHENTICATED key gets a real 404 for a route
# that does not resolve. A stale manifest naming a Route deleted since the poll
# is exactly that, so the 404 route_not_found envelope is a refresh trigger too
# (PARITY §21.1). No re-mint is spent on it — call()'s rule is 401-only.
ROUTE_NOT_FOUND = {"error": {"type": "route_not_found", "message": "Route 'hubspot' not found.", "request_id": "req_x"}}
KNOX_BLOCK = {"x-knox-origin": "knoxcall", "x-knox-error": "route_not_found", "x-knox-plane": "route"}


def test_knoxcall_origin_404_route_not_found_refreshes_once_and_resends_ephemeral_when_the_route_is_gone() -> None:
    routes: list[dict[str, Any]] = [HUBSPOT_ROOT]
    client = FakeClient(routes=lambda: routes, route_status=404, route_headers=KNOX_BLOCK, route_body=ROUTE_NOT_FOUND)
    refused: list[dict[str, Any]] = []
    t, _ = make_sync(client, routes="auto", on_refused=refused.append)
    t.ready()
    routes = []  # the Route was deleted between the poll and this request
    with httpx.Client(transport=t) as http:
        r = http.post("https://api.hubapi.com/x", headers={"authorization": "Bearer t"}, content=b"payload")
    assert r.status_code == 200
    assert len(client.route_calls) == 1
    assert client.manifest_calls == 2
    assert client.ephemeral_calls[0]["body"] == b"payload"
    assert refused[0]["slug"] == "hubspot" and refused[0]["status"] == 404 and refused[0]["redecided"] == "ephemeral"


def test_404_of_an_environment_type_is_refused_as_is() -> None:
    body = {"error": {"type": "environment_not_configured", "message": "Environment 'staging' is not configured for this route.", "request_id": "r"}}
    client = FakeClient(routes=[HUBSPOT_ROOT], route_status=404, route_headers={"x-knox-origin": "knoxcall", "x-knox-error": "environment_not_configured"}, route_body=body)
    refused: list[dict[str, Any]] = []
    t, _ = make_sync(client, routes="auto", on_refused=refused.append)
    t.ready()
    with httpx.Client(transport=t) as http:
        r = http.get("https://api.hubapi.com/x", headers={"authorization": "Bearer t"})
    assert r.status_code == 404
    assert r.json()["error"]["type"] == "environment_not_configured"
    assert len(client.route_calls) == 1
    assert client.manifest_calls == 1
    assert refused == []


def test_upstream_404_through_the_route_is_not_a_refusal_even_with_an_imitated_envelope() -> None:
    forged = {"error": {"type": "route_not_found", "message": "forged", "request_id": "x"}}
    client = FakeClient(routes=[HUBSPOT_ROOT], route_status=404, route_headers={"x-knox-origin": "upstream", "x-knox-upstream-status": "404"}, route_body=forged)
    t, _ = make_sync(client, routes="auto")
    t.ready()
    with httpx.Client(transport=t) as http:
        r = http.get("https://api.hubapi.com/x", headers={"authorization": "Bearer t"})
    assert r.status_code == 404
    assert r.headers["x-knox-upstream-status"] == "404"
    assert r.json() == forged  # the caller's body, intact
    assert len(client.route_calls) == 1
    assert client.manifest_calls == 1


def test_promoted_hint_makes_the_next_request_refresh_and_switch() -> None:
    routes: list[dict[str, Any]] = []
    client = FakeClient(routes=lambda: routes, promoted="resend")
    promoted: list[dict[str, str]] = []
    t, _ = make_sync(client, routes="auto", on_promoted=promoted.append)
    t.ready()
    routes = [entry("api.resend.com", "resend")]
    with httpx.Client(transport=t) as http:
        http.post("https://api.resend.com/emails", headers={"authorization": "Bearer re"}, content=b"{}")
        assert promoted == [{"host": "api.resend.com", "slug": "resend"}]
        t.refresh()  # the hint is rate-limited inside the 5 s gap; force one for determinism
        http.post("https://api.resend.com/emails", headers={"authorization": "Bearer re"}, content=b"{}")
    assert client.route_calls[-1]["route"] == "resend"


def test_manifest_refused_credential_keeps_listed_hosts_ephemeral_and_warns_once() -> None:
    client = FakeClient(routes="forbidden")
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        t, _ = make_sync(client, routes="auto")
        t.ready()
        assert t.manifest() is None
        with httpx.Client(transport=t) as http:
            http.get("https://api.hubapi.com/x", headers={"authorization": "Bearer t"})
    assert len(client.ephemeral_calls) == 1
    assert len([x for x in w if "routes:read" in str(x.message)]) == 1


def test_d4_unreachable_is_an_error_by_default_direct_is_a_transit_only_opt_in() -> None:
    client = FakeClient(routes=[], ephemeral_error=APIConnectionError("ECONNREFUSED"))
    strict, direct = make_sync(client, routes="auto")
    strict.ready()
    with httpx.Client(transport=strict) as http, pytest.raises(APIConnectionError):
        http.get("https://api.resend.com/emails", headers={"authorization": "Bearer re"})
    assert direct.requests == []

    fallbacks: list[dict[str, Any]] = []
    lenient, direct2 = make_sync(client, routes="auto", unavailable="direct", on_fallback=fallbacks.append)
    lenient.ready()
    with httpx.Client(transport=lenient) as http:
        r = http.get("https://api.resend.com/emails", headers={"authorization": "Bearer re"})
    assert r.text == "DIRECT" and fallbacks[0]["host"] == "api.resend.com"

    escrow, direct3 = make_sync(client, routes="auto", unavailable="direct", credential={"secret": "resend-key"})
    escrow.ready()
    with httpx.Client(transport=escrow) as http, pytest.raises(APIConnectionError):
        http.get("https://api.resend.com/emails")
    assert direct3.requests == []


def test_on_unmatched_path_fires_once_per_host_and_prefix() -> None:
    client = FakeClient(routes=[HUBSPOT])
    unmatched: list[dict[str, str]] = []
    t, _ = make_sync(client, routes="auto", on_unmatched_path=unmatched.append)
    t.ready()
    with httpx.Client(transport=t) as http:
        for p in ("/oauth/v1/token", "/oauth/v1/refresh", "/settings/v3/users"):
            http.get(f"https://api.hubapi.com{p}", headers={"authorization": "Bearer t"})
    assert len(client.ephemeral_calls) == 3
    assert len(unmatched) == 2


async def test_async_transport_route_mode_and_refusal_refresh() -> None:
    routes: list[dict[str, Any]] = [HUBSPOT_ROOT]
    client = FakeClient(routes=lambda: routes, route_status=401)
    direct = AsyncDirect()
    t = KnoxWrapAsyncTransport(client, direct_transport=direct, manifest_fetch=client.fetch_manifest, routes="auto")
    await t.ready()
    routes = []
    async with httpx.AsyncClient(transport=t) as http:
        r = await http.post("https://api.hubapi.com/x", headers={"authorization": "Bearer t"}, content=b"payload")
    assert r.status_code == 200
    assert len(client.route_calls) == 1 and len(client.ephemeral_calls) == 1
    assert client.manifest_calls == 2


# ── process-wide interceptor ───────────────────────────────────────────────────

class Canned:
    """Replaces the ORIGINAL httpx/urllib3 transports for the duration of a test
    so an unmatched host answers here, never on the network."""

    def __init__(self) -> None:
        self.original: list[str] = []

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        canned = self

        def sync_handle(self_: Any, request: httpx.Request) -> httpx.Response:
            canned.original.append(str(request.url))
            return httpx.Response(200, text="ORIGINAL", request=request)

        async def async_handle(self_: Any, request: httpx.Request) -> httpx.Response:
            canned.original.append(str(request.url))
            return httpx.Response(200, text="ORIGINAL", request=request)

        monkeypatch.setattr(httpx.HTTPTransport, "handle_request", sync_handle)
        monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", async_handle)
        try:
            from urllib3.connectionpool import HTTPConnectionPool
            from urllib3.response import HTTPResponse
            import io

            def urlopen(self_: Any, method: str, url: str, body: Any = None, headers: Any = None, *a: Any, **kw: Any) -> Any:
                canned.original.append(f"{self_.scheme}://{self_.host}{url}")
                return HTTPResponse(body=io.BytesIO(b"ORIGINAL"), headers={"content-type": "text/plain"}, status=200, reason="OK", preload_content=False, request_method=method, request_url=url)

            monkeypatch.setattr(HTTPConnectionPool, "urlopen", urlopen)
        except ImportError:  # pragma: no cover
            pass


def test_intercept_sync_httpx_and_requests_route_ephemeral_and_untouched(monkeypatch: pytest.MonkeyPatch) -> None:
    canned = Canned()
    canned.install(monkeypatch)
    client = FakeClient(routes=[HUBSPOT, HUBSPOT_ROOT])
    handle = install_intercept(
        client=client, runner=sync_runner, stacks=["httpx", "urllib3"], hosts=["api.resend.com"], host_options={},
        require_context=False, transport_opts={"routes": "auto", "manifest_fetch": client.fetch_manifest},
    )
    try:
        handle.ready()
        assert len(handle.manifest()["routes"]) == 2
        with httpx.Client() as http:  # an untouched httpx client on the default transport
            http.get("https://api.hubapi.com/crm/v3/objects", headers={"authorization": "Bearer t"})
            http.post("https://api.resend.com/emails", headers={"authorization": "Bearer re"}, content=b"{}")
            assert http.get("https://api.openai.com/v1/models").text == "ORIGINAL"
        assert client.route_calls[0]["route"] == "hubspot-crm" and client.route_calls[0]["path"] == "/objects"
        assert client.ephemeral_calls[0]["url"] == "https://api.resend.com/emails"

        import requests  # an untouched requests session on urllib3

        requests.get("https://api.hubapi.com/oauth/v1/token", headers={"authorization": "Bearer t"})
        assert client.route_calls[-1]["route"] == "hubspot" and client.route_calls[-1]["path"] == "/oauth/v1/token"
        assert requests.get("https://api.openai.com/v1/models").text == "ORIGINAL"
        assert canned.original == ["https://api.openai.com/v1/models", "https://api.openai.com/v1/models"]
    finally:
        handle.uninstall()
    assert not handle.installed
    assert handle.manifest() is None
    # restored: a matched host now goes to the (canned) original
    with httpx.Client() as http:
        assert http.get("https://api.hubapi.com/crm/v3/objects").text == "ORIGINAL"


async def test_intercept_async_httpx_on_the_async_client(monkeypatch: pytest.MonkeyPatch) -> None:
    canned = Canned()
    canned.install(monkeypatch)
    client = FakeClient(routes=[HUBSPOT_ROOT])
    handle = install_intercept(
        client=client, runner=None, stacks=["httpx"], hosts=[], host_options={},
        require_context=False, transport_opts={"routes": "auto", "manifest_fetch": client.fetch_manifest},
    )
    try:
        await handle.aready()
        async with httpx.AsyncClient() as http:
            await http.get("https://api.hubapi.com/anything")
            assert (await http.get("https://api.openai.com/v1/models")).text == "ORIGINAL"
        assert client.route_calls[0]["route"] == "hubspot"
    finally:
        handle.uninstall()


def test_intercept_own_hosts_never_intercepted_even_when_listed_or_in_the_manifest(monkeypatch: pytest.MonkeyPatch) -> None:
    canned = Canned()
    canned.install(monkeypatch)
    client = FakeClient(routes=[entry("api.test", "self")])
    handle = install_intercept(
        client=client, runner=sync_runner, stacks=["httpx"], hosts=["api.test", "acme.test"], host_options={},
        require_context=False, transport_opts={"routes": "auto", "manifest_fetch": client.fetch_manifest},
    )
    try:
        handle.ready()
        with httpx.Client() as http:
            http.get("https://api.test/v1/routes")
            http.get("https://acme.test/x")
        assert client.route_calls == [] and client.ephemeral_calls == []
        assert len(canned.original) == 2
    finally:
        handle.uninstall()


def test_intercept_per_host_escrow_kill_switch_require_context_and_refresh(monkeypatch: pytest.MonkeyPatch) -> None:
    canned = Canned()
    canned.install(monkeypatch)
    routes: list[dict[str, Any]] = []
    client = FakeClient(routes=lambda: routes)
    handle = install_intercept(
        client=client, runner=sync_runner, stacks=["httpx"],
        hosts=["api.resend.com", "api.mailgun.net"], host_options={"api.resend.com": {"credential": {"secret": "resend-key"}}},
        require_context=True, transport_opts={"routes": "auto", "manifest_fetch": client.fetch_manifest},
    )
    try:
        handle.ready()
        with httpx.Client() as http:
            http.post("https://api.resend.com/emails", content=b"{}")  # outside routed(): untouched
            assert canned.original[-1] == "https://api.resend.com/emails"
            with routed():
                http.post("https://api.resend.com/emails", content=b"{}")
                http.post("https://api.mailgun.net/v3/x", headers={"authorization": "Basic abc"}, content=b"")
            assert client.ephemeral_calls[0]["upstream_auth_secret"] == "resend-key"
            assert client.ephemeral_calls[1]["upstream_authorization"] == "Basic abc"
            # a Route created after install is picked up by refresh(), no re-install
            routes = [HUBSPOT_ROOT]
            handle.refresh()
            with routed():
                http.get("https://api.hubapi.com/x")
            assert client.route_calls[-1]["route"] == "hubspot"
            monkeypatch.setenv("KNOXCALL_INTERCEPT", "off")
            with routed():
                assert http.get("https://api.hubapi.com/x").text == "ORIGINAL"
    finally:
        handle.uninstall()


def test_intercept_refuses_routes_off_without_hosts_and_a_double_install(monkeypatch: pytest.MonkeyPatch) -> None:
    Canned().install(monkeypatch)
    client = FakeClient(routes=[])
    with pytest.raises(TypeError):
        install_intercept(client=client, runner=sync_runner, stacks=["httpx"], hosts=[], host_options={}, require_context=False, transport_opts={"routes": "off"})
    h = install_intercept(client=client, runner=sync_runner, stacks=["httpx"], hosts=["a.example"], host_options={}, require_context=False, transport_opts={"routes": "off"})
    try:
        with pytest.raises(RuntimeError):
            install_intercept(client=client, runner=sync_runner, stacks=["httpx"], hosts=["b.example"], host_options={}, require_context=False, transport_opts={"routes": "off"})
    finally:
        h.uninstall()
    with pytest.raises(TypeError):
        install_intercept(client=client, runner=None, stacks=["urllib3"], hosts=["a.example"], host_options={}, require_context=False, transport_opts={"routes": "off"})


# ── the conditional poll through the transport (PARITY §21.1) ─────────────────


class ConditionalFakeClient(FakeClient):
    """A fake whose ``fetch_manifest`` takes ``if_none_match`` and answers the
    server's 304 (``None``) when it names the current version — what the real
    ``wrap.intercept_manifest`` does. Records what the store handed it."""

    def __init__(self, **kw: Any) -> None:
        super().__init__(**kw)
        self.if_none_match_seen: list[str | None] = []

    async def fetch_manifest(self, *, if_none_match: str | None = None) -> dict[str, Any] | None:  # type: ignore[override]
        self.if_none_match_seen.append(if_none_match)
        m = await super().fetch_manifest()
        if if_none_match is not None and if_none_match == m["version"]:
            return None
        return m


def test_transport_polls_conditionally_a_304_keeps_the_manifest_and_a_change_replaces_it() -> None:
    routes = [HUBSPOT]
    client = ConditionalFakeClient(routes=lambda: routes)
    refreshes: list[dict[str, Any]] = []
    t, _ = make_sync(client, routes="auto", on_refresh=refreshes.append)
    t.ready()
    v1 = t.manifest()["version"]
    assert client.if_none_match_seen == [None]
    assert len(refreshes) == 1

    t.refresh()  # forced, as a refusal-driven refresh is: still conditional
    assert client.if_none_match_seen == [None, v1]
    assert client.manifest_calls == 2
    assert t.manifest()["version"] == v1 and t.manifest()["routes"] == [HUBSPOT]
    assert len(refreshes) == 1  # a 304 changed nothing, so no hook

    routes = [HUBSPOT_ROOT]
    t.refresh()
    v2 = t.manifest()["version"]
    assert client.if_none_match_seen[-1] == v1 and v2 != v1
    assert len(refreshes) == 2
    assert refreshes[1]["added"] == [HUBSPOT_ROOT] and refreshes[1]["removed"] == [HUBSPOT]

    t.refresh()
    assert client.if_none_match_seen[-1] == v2 and t.manifest()["version"] == v2
    assert len(refreshes) == 2

    # The decision still reads the held manifest after a 304: the covered host routes.
    with httpx.Client(transport=t) as http:
        http.post("https://api.hubapi.com/oauth/v1/token", headers={"authorization": "Bearer t"}, content=b"")
    assert client.route_calls[-1]["route"] == "hubspot"


def test_a_zero_argument_manifest_fetch_seam_still_polls_unconditionally() -> None:
    """``FakeClient.fetch_manifest`` (every test above) takes no version — the
    store must not hand it one. Pinned here so the tolerance is a contract."""
    client = FakeClient(routes=[HUBSPOT])
    t, _ = make_sync(client, routes="auto")
    t.ready()
    t.refresh()
    assert client.manifest_calls == 2
    assert t.manifest()["routes"] == [HUBSPOT]
