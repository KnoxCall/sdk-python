"""The interceptors' reroute marker on the WIRE (PARITY §21.2).

``test_wrap_intercept.py`` captures at a FAKE client, which records the
``call()`` arguments and never builds a request — so it cannot see the header.
This file drives the REAL ``KnoxCallAsync`` over an ``httpx.MockTransport`` that
serves the token, the manifest and both data planes, and asserts what leaves
the process: a route-mode reroute carries ``x-knoxcall-origin: sdk-intercept``;
an ephemeral hop and a direct ``call()`` carry nothing.
"""

from __future__ import annotations

from typing import Any

import httpx

from knoxcall import KnoxCallAsync
from knoxcall.auth.bootstrap import ClientCredentials

API = "https://api.example.test"
PROXY = "https://acme.example.test"
HUBSPOT = {
    "host": "api.hubapi.com",
    "base_path": "/crm/v3",
    "slug": "hubspot-crm",
    "route_id": "r-crm",
    "requires_clients": False,
    "allowed_methods": None,
    "updated_at": None,
}


def _client(handler: Any) -> KnoxCallAsync:
    return KnoxCallAsync(
        tenant="acme",
        base_url=API,
        proxy_base_url=PROXY,
        bootstrap=ClientCredentials(client_id="tk_x", client_secret="sec"),
        http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        retry_base_delay=0.001,
    )


async def test_route_mode_reroute_carries_the_marker_and_nothing_else_does():
    seen: list[dict[str, Any]] = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/oauth/token":
            return httpx.Response(200, json={"access_token": "kc_live_aaaa", "token_type": "Bearer", "expires_in": 3600})
        if req.url.path == "/v1/wrap/intercept-manifest":
            manifest = {"version": "sha256:hubspot-crm", "ttl_seconds": 60, "environment": "production", "sandbox": False, "routes": [HUBSPOT]}
            return httpx.Response(200, json={"data": manifest, "meta": {"request_id": "m1"}})
        seen.append({"url": str(req.url), "headers": dict(req.headers)})
        return httpx.Response(200, json={"ok": True})

    async with _client(handler) as client:
        # ROUTE mode: the marker rides the route hop.
        routed = client.wrap.transport(routes="auto")
        await routed.ready()
        resp = await routed.handle_async_request(
            httpx.Request("POST", "https://api.hubapi.com/crm/v3/objects/contacts", headers={"authorization": "Bearer hub"}, content=b"{}")
        )
        assert resp.status_code == 200
        route_hops = [s for s in seen if s["url"].startswith(PROXY)]
        assert len(route_hops) == 1
        assert route_hops[0]["headers"]["x-knoxcall-route"] == "hubspot-crm"
        assert route_hops[0]["headers"]["x-knoxcall-origin"] == "sdk-intercept"
        routed.stop()

        # EPHEMERAL: a different log; the hop carries nothing.
        seen.clear()
        ephemeral = client.wrap.transport()  # routes="off": every host is listed, all ephemeral
        await ephemeral.handle_async_request(
            httpx.Request("GET", "https://api.resend.com/emails", headers={"authorization": "Bearer tok"})
        )
        proxy_hops = [s for s in seen if s["url"] == API + "/v1/proxy"]
        assert len(proxy_hops) == 1
        assert "x-knoxcall-origin" not in proxy_hops[0]["headers"]

        # DIRECT: absence IS "direct" on the server.
        seen.clear()
        await client.call("hubspot-crm", path="/objects")
        assert seen[0]["headers"]["x-knoxcall-route"] == "hubspot-crm"
        assert "x-knoxcall-origin" not in seen[0]["headers"]
