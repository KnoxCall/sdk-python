"""Tests for flat construction, env fallbacks, and bound routes (PARITY §2/§6)."""

from __future__ import annotations

import httpx
import pytest

from knoxcall import BootstrapError, KnoxCall, KnoxCallAsync
from knoxcall.auth.bootstrap import ClientCredentials

_ENV_VARS = (
    "KNOXCALL_TENANT",
    "KNOXCALL_ENVIRONMENT",
    "KNOXCALL_BASE_URL",
    "KNOXCALL_PROXY_BASE_URL",
    "KNOXCALL_ACCESS_TOKEN",
    "KNOXCALL_API_KEY",
    "KNOXCALL_CLIENT_ID",
    "KNOXCALL_CLIENT_SECRET",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in _ENV_VARS:
        monkeypatch.delenv(var, raising=False)


def _token_response(token: str = "kc_live_aaaa") -> httpx.Response:
    return httpx.Response(
        200, json={"access_token": token, "token_type": "Bearer", "expires_in": 3600}
    )


def _http(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


_URLS = dict(base_url="https://api.example.test", proxy_base_url="https://acme.example.test")


# ── Flat credential kwargs ────────────────────────────────────────────────────


async def test_flat_client_credentials_mint_identically_to_bootstrap():
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/oauth/token":
            seen.append((dict(req.headers), req.content.decode()))
            return _token_response()
        return httpx.Response(200, json={"ok": True})

    async with KnoxCallAsync(
        tenant="acme", client_id="tk_x", client_secret="sec", http=_http(handler), **_URLS
    ) as client:
        await client.call("r_1", path="/x")

    headers, form = seen[0]
    assert headers["authorization"].startswith("Basic ")
    assert "grant_type=client_credentials" in form


async def test_flat_access_token_and_api_key_attach_bearer_without_token_endpoint():
    for kwarg in ({"access_token": "kc_live_pre"}, {"api_key": "kc_live_pre"}):
        paths = []

        def handler(req: httpx.Request) -> httpx.Response:
            paths.append(req.url.path)
            return httpx.Response(200, json={"auth": req.headers.get("authorization")})

        async with KnoxCallAsync(tenant="acme", http=_http(handler), **_URLS, **kwarg) as client:
            res = await client.call("r_1", path="/x")
        assert "/oauth/token" not in paths
        assert res.json()["auth"] == "Bearer kc_live_pre"


async def test_legacy_tk_key_travels_as_x_knoxcall_key_on_call():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["headers"] = dict(req.headers)
        return httpx.Response(200, json={"ok": True})

    async with KnoxCallAsync(tenant="acme", api_key="tk_live_legacy", http=_http(handler), **_URLS) as client:
        await client.call("r_1", path="/x")

    # proxy OAuth detection matches `Bearer kc_` only — tk_ must use the header
    assert seen["headers"]["x-knoxcall-key"] == "tk_live_legacy"
    assert "authorization" not in seen["headers"]


def test_conflict_matrix_raises_bootstrap_error():
    bootstrap = ClientCredentials(client_id="tk_x", client_secret="sec")
    conflicts = [
        dict(bootstrap=bootstrap, client_id="tk_x"),
        dict(access_token="kc_a", api_key="kc_b"),
        dict(api_key="kc_a", client_id="tk_x", client_secret="s"),
        dict(client_id="tk_x"),  # missing client_secret
        dict(client_secret="s"),  # missing client_id
    ]
    for kwargs in conflicts:
        with pytest.raises(BootstrapError):
            KnoxCallAsync(tenant="acme", **kwargs)


# ── Tenant env fallback / zero-arg ────────────────────────────────────────────


def test_tenant_from_env_enables_zero_tenant_construction(monkeypatch):
    monkeypatch.setenv("KNOXCALL_TENANT", "envcorp")
    client = KnoxCallAsync(access_token="kc_live_x")
    assert client.tenant == "envcorp"
    # proxy URL must derive from the env-resolved tenant
    assert client._proxy_base_url == "https://envcorp.knoxcall.com"


def test_explicit_tenant_beats_env(monkeypatch):
    monkeypatch.setenv("KNOXCALL_TENANT", "envcorp")
    client = KnoxCallAsync(tenant="explicit", access_token="kc_live_x")
    assert client.tenant == "explicit"


def test_hostile_tenant_slug_rejected_before_becoming_a_host():
    # "evil.com#" would yield https://evil.com#.knoxcall.com, whose real host
    # is evil.com — refuse to send the tenant's token there.
    with pytest.raises(BootstrapError):
        KnoxCallAsync(tenant="evil.com#", access_token="kc_live_x")
    with pytest.raises(BootstrapError):
        KnoxCallAsync(tenant="a/b", access_token="kc_live_x")


async def test_hostile_tenant_slug_from_token_response_rejected():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/oauth/token":
            return httpx.Response(
                200,
                json={"access_token": "kc_live_a", "token_type": "Bearer",
                      "expires_in": 3600, "tenant": "evil.com#"},
            )
        return httpx.Response(200, json={"ok": True})

    async with KnoxCallAsync(client_id="tk_x", client_secret="s", http=_http(handler)) as client:
        with pytest.raises(BootstrapError):
            await client.call("r_1", path="/x")


async def test_tenant_discovered_from_token_response():
    """No tenant anywhere: the token response's `tenant` member supplies it
    and the proxy hostname derives from it lazily on the first call()."""
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/oauth/token":
            return httpx.Response(
                200,
                json={"access_token": "kc_live_a", "token_type": "Bearer",
                      "expires_in": 3600, "tenant": "discovered"},
            )
        seen["host"] = req.url.host
        return httpx.Response(200, json={"ok": True})

    async with KnoxCallAsync(client_id="tk_x", client_secret="s", http=_http(handler)) as client:
        res = await client.call("r_1", path="/x")
    assert res.status_code == 200
    assert client.tenant == "discovered"
    assert seen["host"] == "discovered.knoxcall.com"


async def test_tenant_discovered_via_account_for_static_tokens():
    """Pre-acquired tokens never hit the token endpoint, so discovery falls
    back to one GET /v1/account."""
    paths = []
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        paths.append(req.url.path)
        if req.url.path == "/v1/account":
            return httpx.Response(200, json={"data": {"slug": "fromaccount", "name": "X"}})
        seen["host"] = req.url.host
        return httpx.Response(200, json={"ok": True})

    async with KnoxCallAsync(access_token="kc_live_pre", http=_http(handler)) as client:
        await client.call("r_1", path="/x")
        await client.call("r_1", path="/y")
    assert paths.count("/v1/account") == 1  # discovered once, then cached
    assert seen["host"] == "fromaccount.knoxcall.com"


async def test_undiscoverable_tenant_raises_actionable_error():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/account":
            return httpx.Response(200, json={"data": {"name": "no slug here"}})
        return httpx.Response(200, json={"ok": True})

    async with KnoxCallAsync(access_token="kc_live_pre", http=_http(handler)) as client:
        with pytest.raises(BootstrapError, match="KNOXCALL_TENANT"):
            await client.call("r_1", path="/x")


async def test_management_requests_need_no_tenant():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/oauth/token":
            return _token_response()
        return httpx.Response(200, json={"data": [], "meta": {
            "total": 0, "page": 1, "per_page": 20, "total_pages": 0, "request_id": "req_x"}})

    async with KnoxCallAsync(client_id="tk_x", client_secret="s", http=_http(handler)) as client:
        assert (await client.routes.list())["data"] == []
    assert client.tenant is None  # never needed, never discovered


def test_zero_arg_sync_construction_with_full_env(monkeypatch):
    monkeypatch.setenv("KNOXCALL_TENANT", "envcorp")
    monkeypatch.setenv("KNOXCALL_CLIENT_ID", "tk_env")
    monkeypatch.setenv("KNOXCALL_CLIENT_SECRET", "sec")
    with KnoxCall() as client:
        assert client._async.tenant == "envcorp"


# ── Bound routes ──────────────────────────────────────────────────────────────


def _capture_handler(seen: dict):
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/oauth/token":
            return _token_response()
        seen["headers"] = dict(req.headers)
        seen["method"] = req.method
        seen["url"] = str(req.url)
        return httpx.Response(200, json={"ok": True})
    return handler


async def test_bound_route_injects_route_and_environment():
    seen: dict = {}
    async with KnoxCallAsync(
        tenant="acme", client_id="tk_x", client_secret="s", http=_http(_capture_handler(seen)), **_URLS
    ) as client:
        printnode = client.route("r_1", environment="production", headers={"X-A": "bound"})
        res = await printnode.get("/computers")

    assert res.status_code == 200
    assert seen["headers"]["x-knoxcall-route"] == "r_1"
    assert seen["headers"]["x-knoxcall-environment"] == "production"
    assert seen["headers"]["x-a"] == "bound"
    assert seen["url"].endswith("/computers")


async def test_bound_route_per_call_values_beat_bound_defaults():
    seen: dict = {}
    async with KnoxCallAsync(
        tenant="acme", client_id="tk_x", client_secret="s", http=_http(_capture_handler(seen)), **_URLS
    ) as client:
        bound = client.route("r_1", environment="production", headers={"X-A": "bound"})
        await bound.post("/printjobs", body={"a": 1}, environment="staging", headers={"X-A": "call"})

    assert seen["method"] == "POST"
    assert seen["headers"]["x-knoxcall-environment"] == "staging"
    assert seen["headers"]["x-a"] == "call"


async def test_bound_route_generic_request_method():
    seen: dict = {}
    async with KnoxCallAsync(
        tenant="acme", client_id="tk_x", client_secret="s", http=_http(_capture_handler(seen)), **_URLS
    ) as client:
        await client.route("r_1").request("DELETE", "/printjobs/42")

    assert seen["method"] == "DELETE"
    assert seen["url"].endswith("/printjobs/42")


async def test_client_default_environment_applies_to_calls():
    seen: dict = {}
    async with KnoxCallAsync(
        tenant="acme", environment="production", client_id="tk_x", client_secret="s",
        http=_http(_capture_handler(seen)), **_URLS,
    ) as client:
        await client.call("r_1", path="/x")
    assert seen["headers"]["x-knoxcall-environment"] == "production"


async def test_environment_resolution_order_per_call_bound_client():
    seen: dict = {}
    async with KnoxCallAsync(
        tenant="acme", environment="client-env", client_id="tk_x", client_secret="s",
        http=_http(_capture_handler(seen)), **_URLS,
    ) as client:
        # client default flows through an unbound route handle
        await client.route("r_1").get("/x")
        assert seen["headers"]["x-knoxcall-environment"] == "client-env"
        # bound default beats client default
        await client.route("r_1", environment="bound-env").get("/x")
        assert seen["headers"]["x-knoxcall-environment"] == "bound-env"
        # per-call beats both
        await client.route("r_1", environment="bound-env").get("/x", environment="call-env")
        assert seen["headers"]["x-knoxcall-environment"] == "call-env"


def test_environment_from_env_var(monkeypatch):
    monkeypatch.setenv("KNOXCALL_ENVIRONMENT", "staging")
    client = KnoxCallAsync(tenant="acme", access_token="kc_x")
    assert client.environment == "staging"
    assert KnoxCallAsync(tenant="acme", environment="production", access_token="kc_x").environment == "production"


def test_sync_bound_route_delegates_through_loop_thread():
    seen: dict = {}
    client = KnoxCall(
        tenant="acme", client_id="tk_x", client_secret="s",
        http=_http(_capture_handler(seen)), **_URLS,
    )
    try:
        printnode = client.route("r_1", environment="production")
        res = printnode.get("/computers")
        assert res.status_code == 200
        assert seen["headers"]["x-knoxcall-environment"] == "production"
    finally:
        client.close()
