"""PARITY §5 — where the data plane lives under a proxy base.

On a KnoxCall cloud tenant host the proxy is served ONLY under ``/api``
(server.ts strips the prefix; every other path on that host is the dashboard).
Until 2026-09-25 ``call()`` sent ``f"{proxy_base}{path}"``, so every documented
``path="/users"`` example answered the dashboard HTML on a real tenant host, and
the five live smokes passed only because each hard-coded ``path="/api/get"``.
Measured on a local server that day: ``GET /api/get`` → 200 with
X-Knox-Upstream-Status; ``GET /get`` → the SPA branch, no upstream call. These
pin the URL ``call()`` builds for every base shape.
"""
from __future__ import annotations

import httpx
import pytest

from knoxcall import KnoxCallAsync
from knoxcall.auth.bootstrap import AccessTokenBootstrap
from knoxcall.core import data_plane_path_prefix

ENV_VARS = ["KNOXCALL_PROXY_BASE_URL", "KNOXCALL_BASE_URL", "KNOXCALL_API_BASE_URL", "KNOXCALL_TENANT", "KNOXCALL_ENVIRONMENT"]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize(
    ("base", "want"),
    [
        ("https://acme.knoxcall.com", "/api"),
        ("https://acme.knoxcall.com/", "/api"),
        ("https://sandbox-acme.knoxcall.com", "/api"),
        ("http://sandbox-acme.knoxcall.com:3100", "/api"),
        ("https://ACME.KnoxCall.com", "/api"),
        ("https://acme.knoxcall.com/api", ""),
        ("https://acme.knoxcall.com/proxy", ""),
        ("https://api.knoxcall.com", ""),
        ("https://sandbox.knoxcall.com", ""),
        ("https://api-staging.knoxcall.com", ""),
        ("https://sandbox-staging.knoxcall.com", ""),
        ("https://www.knoxcall.com", ""),
        ("https://staging.knoxcall.com", ""),
        ("https://admin.knoxcall.com", ""),
        ("https://a.b.knoxcall.com", ""),
        ("https://knoxcall.com", ""),
        ("https://acme.knoxcall.com.evil.test", ""),
        ("http://localhost:3000", ""),
        ("https://knox.example.com", ""),
        ("not a url", ""),
    ],
)
def test_data_plane_path_prefix_rule(base, want):
    assert data_plane_path_prefix(base) == want


async def _url_of(path: str = "/users", **opts) -> str:
    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(str(req.url))
        return httpx.Response(200, json={"ok": True})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme",
            bootstrap=AccessTokenBootstrap(type="access_token", access_token="kc_live_pre"),
            http=http,
            **opts,
        ) as client:
            await client.call("r_1", path=path)
    assert len(seen) == 1
    return seen[0]


@pytest.mark.asyncio
async def test_derived_sandbox_shape():
    assert await _url_of(base_url="https://sandbox.knoxcall.com") == "https://sandbox-acme.knoxcall.com/api/users"


@pytest.mark.asyncio
async def test_derived_plain_shape():
    assert await _url_of(base_url="https://api.knoxcall.com") == "https://acme.knoxcall.com/api/users"


@pytest.mark.asyncio
async def test_explicit_override_naming_a_tenant_host_any_port():
    # The live smoke harness's shape.
    got = await _url_of("/get", base_url="http://sandbox.knoxcall.com:3100", proxy_base_url="http://sandbox-acme.knoxcall.com:3100")
    assert got == "http://sandbox-acme.knoxcall.com:3100/api/get"


@pytest.mark.asyncio
async def test_env_override_behaves_the_same(monkeypatch):
    monkeypatch.setenv("KNOXCALL_PROXY_BASE_URL", "https://sandbox-acme.knoxcall.com")
    assert await _url_of("/get", base_url="https://sandbox.knoxcall.com") == "https://sandbox-acme.knoxcall.com/api/get"


@pytest.mark.asyncio
async def test_override_carrying_the_entry_point_is_verbatim_never_doubled():
    got = await _url_of("/get", base_url="https://sandbox.knoxcall.com", proxy_base_url="https://sandbox-acme.knoxcall.com/api")
    assert got == "https://sandbox-acme.knoxcall.com/api/get"


@pytest.mark.asyncio
async def test_loopback_override_is_verbatim():
    assert await _url_of("/get", base_url="http://localhost:3000", proxy_base_url="http://localhost:3000") == "http://localhost:3000/get"


@pytest.mark.asyncio
async def test_self_hosted_base_is_verbatim():
    assert await _url_of("/get", base_url="https://knox.example.com") == "https://knox.example.com/get"


@pytest.mark.asyncio
async def test_bare_and_unslashed_and_api_prefixed_upstream_paths():
    assert await _url_of("users", base_url="https://api.knoxcall.com") == "https://acme.knoxcall.com/api/users"
    assert await _url_of("/api/v2/tickets", base_url="https://api.knoxcall.com") == "https://acme.knoxcall.com/api/api/v2/tickets"
    assert await _url_of("/", base_url="https://api.knoxcall.com") == "https://acme.knoxcall.com/api/"


@pytest.mark.asyncio
async def test_bound_routes_inherit_it():
    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(str(req.url))
        return httpx.Response(200, json={"ok": True})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme",
            base_url="https://api.knoxcall.com",
            bootstrap=AccessTokenBootstrap(type="access_token", access_token="kc_live_pre"),
            http=http,
        ) as client:
            await client.route("r_1").get("/users")
    assert seen == ["https://acme.knoxcall.com/api/users"]
