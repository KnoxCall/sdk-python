"""The conditional manifest poll on the wire (PARITY §21.1 "Conditional poll"):
which header leaves, in which form, and what a 304 becomes — through the real
``wrap.intercept_manifest`` and the real core, against a stub that behaves as
``src/client-api/wrap.ts`` does. The store-level walk of
``sdk/fixtures/intercept-store-conditional.json`` lives in test_intercept_store.py."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

from knoxcall import KnoxCall, KnoxCallAsync, manifest_etag
from knoxcall.auth.bootstrap import AccessToken
from knoxcall.core import NOT_MODIFIED

FIXTURE = json.loads(
    (Path(__file__).resolve().parents[2] / "fixtures" / "intercept-store-conditional.json").read_text(encoding="utf-8")
)
ROUTES = [
    {"host": "api.hubapi.com", "base_path": "/crm/v3", "slug": "hubspot-crm", "route_id": "r-crm",
     "requires_clients": False, "allowed_methods": None, "updated_at": None},
]


class ManifestServer:
    """Behaves as the server does: ``ETag: W/"<version>"`` on every answer and a
    ``304`` with no body when ``If-None-Match`` carries that tag. ``overrides``
    maps a 1-based call number to a canned response."""

    def __init__(self, overrides: dict[int, httpx.Response] | None = None) -> None:
        self.overrides = overrides or {}
        self.seen: list[httpx.Request] = []

    @staticmethod
    def version() -> str:
        return "sha256:" + ",".join(r["slug"] for r in ROUTES)

    def __call__(self, req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/v1/wrap/intercept-manifest", req.url
        self.seen.append(req)
        n = len(self.seen)
        if n in self.overrides:
            return self.overrides[n]
        etag = manifest_etag(self.version())
        inm = req.headers.get("if-none-match")
        if inm and etag in [t.strip() for t in inm.split(",")]:
            return httpx.Response(304, headers={"ETag": etag})
        return httpx.Response(
            200,
            headers={"ETag": etag},
            json={"data": {"version": self.version(), "ttl_seconds": 60, "environment": "production",
                           "sandbox": False, "routes": ROUTES}, "meta": {"request_id": "m"}},
        )

    def if_none_match(self) -> list[str | None]:
        return [r.headers.get("if-none-match") for r in self.seen]


def _client(http: httpx.AsyncClient) -> KnoxCallAsync:
    return KnoxCallAsync(tenant="acme", base_url="https://api.test", bootstrap=AccessToken(access_token="kc_live_x"), http=http)


def test_wire_form_of_every_fixture_step_is_the_servers_weak_etag() -> None:
    for step in FIXTURE["steps"]:
        held = step["expect"]["fetch_if_none_match"]
        if held is None:
            assert step["expect"]["wire_if_none_match"] is None, step["name"]
        else:
            assert manifest_etag(held) == step["expect"]["wire_if_none_match"], step["name"]


async def test_sends_if_none_match_as_weak_etag_and_returns_none_on_304() -> None:
    server = ManifestServer()
    async with httpx.AsyncClient(transport=httpx.MockTransport(server)) as http:
        async with _client(http) as client:
            first = await client.wrap.intercept_manifest()
            assert [r["slug"] for r in first["routes"]] == ["hubspot-crm"]

            unchanged = await client.wrap.intercept_manifest(if_none_match=first["version"])
            assert unchanged is None

            stale = await client.wrap.intercept_manifest(if_none_match="sha256:stale")
            assert stale is not None and stale["version"] == first["version"]

            # if_none_match=None is the unconditional call, not a header with no value.
            explicit = await client.wrap.intercept_manifest(if_none_match=None)
            assert explicit is not None and explicit["version"] == first["version"]
    assert server.if_none_match() == [None, manifest_etag(first["version"]), 'W/"sha256:stale"', None]


async def test_a_401_on_the_conditional_poll_still_gets_the_one_reauth_and_the_retry_carries_the_header() -> None:
    server = ManifestServer(overrides={2: httpx.Response(401, json={"error": {"type": "authentication_error", "message": "expired"}})})
    async with httpx.AsyncClient(transport=httpx.MockTransport(server)) as http:
        async with _client(http) as client:
            first = await client.wrap.intercept_manifest()
            res = await client.wrap.intercept_manifest(if_none_match=first["version"])
    assert res is None
    tag = manifest_etag(first["version"])
    assert server.if_none_match() == [None, tag, tag]  # unconditional, the 401, the re-authed retry


async def test_without_the_opt_in_a_304_keeps_its_old_shape() -> None:
    """The core seam is opt-in: ``request()`` without ``allow_not_modified`` still
    parses the empty body as ``None`` rather than returning the sentinel."""
    server = ManifestServer(overrides={1: httpx.Response(304)})
    async with httpx.AsyncClient(transport=httpx.MockTransport(server)) as http:
        async with _client(http) as client:
            plain = await client.request(method="GET", path="/v1/wrap/intercept-manifest")
            assert plain is None and plain is not NOT_MODIFIED
            server.overrides = {2: httpx.Response(304)}
            opted = await client.request(method="GET", path="/v1/wrap/intercept-manifest", allow_not_modified=True)
            assert opted is NOT_MODIFIED


def test_sync_facade_forwards_if_none_match() -> None:
    seen: list[dict[str, Any]] = []

    async def fake(**kw: Any) -> None:
        seen.append(kw)
        return None

    with KnoxCall(tenant="acme", base_url="https://api.test", bootstrap=AccessToken(access_token="kc_live_x")) as client:
        client._async.wrap.intercept_manifest = fake  # type: ignore[method-assign]
        assert client.wrap.intercept_manifest(if_none_match="sha256:v1") is None
        assert client.wrap.intercept_manifest(environment="staging") is None
    assert seen == [{"environment": None, "if_none_match": "sha256:v1"}, {"environment": "staging", "if_none_match": None}]
