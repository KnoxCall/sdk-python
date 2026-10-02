"""Envelope unwrapping, page-based pagination/iterate (both facades),
sandbox constructor, new resource endpoints, and SignupError hierarchy.

All mocks return the REAL server envelope: single objects as
``{data, meta:{request_id}}``, paginated lists as
``{data: [...], meta:{total, page, per_page, total_pages, request_id}}``.
"""

from __future__ import annotations
import json

import httpx
import pytest

from knoxcall import KnoxCall, KnoxCallAsync, KnoxCallError, SignupError
from knoxcall.auth.bootstrap import AccessToken

_BOOTSTRAP = AccessToken(access_token="kc_live_x")


def _meta(**extra) -> dict:
    return {"request_id": "req_00000000-0000-0000-0000-000000000000", **extra}


def _success(data) -> httpx.Response:
    return httpx.Response(200, json={"data": data, "meta": _meta()})


def _page(items: list, *, total: int, page: int, per_page: int) -> httpx.Response:
    total_pages = max(1, -(-total // per_page)) if total else 0
    return httpx.Response(200, json={
        "data": items,
        "meta": _meta(total=total, page=page, per_page=per_page, total_pages=total_pages),
    })


def _async_client(handler, **extra) -> KnoxCallAsync:
    return KnoxCallAsync(
        tenant="acme",
        base_url="https://api.example.test",
        bootstrap=_BOOTSTRAP,
        http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        **extra,
    )


def _sync_client(handler, **extra):
    return KnoxCall(
        tenant="acme",
        base_url="https://api.example.test",
        bootstrap=_BOOTSTRAP,
        http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        **extra,
    )


def _three_route_pages(seen_queries: list):
    """Handler serving 5 routes across 3 pages of 2 (page/per_page only)."""
    routes = [{"id": f"r_{i}", "name": f"route-{i}"} for i in range(1, 6)]

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/v1/routes"
        params = dict(req.url.params)
        seen_queries.append(params)
        assert "cursor" not in params and "limit" not in params  # no cursor pagination
        page = int(params.get("page", 1))
        per_page = int(params.get("per_page", 20))
        items = routes[(page - 1) * per_page: page * per_page]
        return _page(items, total=len(routes), page=page, per_page=per_page)

    return handler


# ── pagination / iterate ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_returns_typed_page_envelope():
    async with _async_client(_three_route_pages([])) as client:
        result = await client.routes.list(page=2, per_page=2)
    assert [r["id"] for r in result["data"]] == ["r_3", "r_4"]
    assert result["meta"] == {
        "total": 5, "page": 2, "per_page": 2, "total_pages": 3,
        "request_id": "req_00000000-0000-0000-0000-000000000000",
    }


@pytest.mark.asyncio
async def test_iterate_walks_all_pages_async():
    seen = []
    async with _async_client(_three_route_pages(seen)) as client:
        names = [r["name"] async for r in client.routes.iterate(per_page=2)]
    assert names == [f"route-{i}" for i in range(1, 6)]
    assert [q.get("page") for q in seen] == ["1", "2", "3"]  # stopped at total_pages


def test_iterate_walks_all_pages_sync_facade():
    seen = []
    with _sync_client(_three_route_pages(seen)) as client:
        names = [r["name"] for r in client.routes.iterate(per_page=2)]
    assert names == [f"route-{i}" for i in range(1, 6)]
    assert [q.get("page") for q in seen] == ["1", "2", "3"]


def test_sync_iterate_is_lazy_generator():
    seen = []
    with _sync_client(_three_route_pages(seen)) as client:
        it = client.routes.iterate(per_page=2)
        assert next(it)["id"] == "r_1"
        assert len(seen) == 1  # only page 1 fetched so far
        it.close()  # abandoning mid-page closes the bridged async generator


@pytest.mark.asyncio
async def test_iterate_stops_on_empty_page_defensively():
    def handler(req: httpx.Request) -> httpx.Response:
        return _page([], total=10, page=int(dict(req.url.params).get("page", 1)), per_page=2)

    async with _async_client(handler) as client:
        assert [r async for r in client.routes.iterate()] == []


@pytest.mark.asyncio
async def test_vault_tokens_iterate_pages():
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/v1/vaults/pci/tokens"
        page = int(dict(req.url.params).get("page", 1))
        items = [{"id": f"t_{page}", "token": f"tok_{page}"}] if page <= 2 else []
        return _page(items, total=2, page=page, per_page=1)

    async with _async_client(handler) as client:
        tokens = [t["token"] async for t in client.vaults.iterate_tokens("pci", per_page=1)]
    assert tokens == ["tok_1", "tok_2"]


def test_vault_tokens_iterate_sync_facade():
    def handler(req: httpx.Request) -> httpx.Response:
        page = int(dict(req.url.params).get("page", 1))
        items = [{"id": f"t_{page}", "token": f"tok_{page}"}] if page <= 2 else []
        return _page(items, total=2, page=page, per_page=1)

    with _sync_client(handler) as client:
        assert [t["token"] for t in client.vaults.iterate_tokens("pci", per_page=1)] == [
            "tok_1", "tok_2",
        ]


@pytest.mark.asyncio
async def test_audit_logs_iterate_carries_filters_every_page():
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        params = dict(req.url.params)
        seen.append(params)
        page = int(params.get("page", 1))
        items = [{"id": f"a_{page}", "action": "secret.created"}] if page <= 2 else []
        return _page(items, total=2, page=page, per_page=1)

    async with _async_client(handler) as client:
        entries = [
            e async for e in client.audit_logs.iterate(per_page=1, action="secret.created")
        ]
    assert len(entries) == 2
    assert all(q.get("action") == "secret.created" for q in seen)


# ── single-object unwrapping ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_unwraps_data():
    def handler(req: httpx.Request) -> httpx.Response:
        return _success({"id": "r_1", "slug": "payments-stripe", "configured_environments": []})

    async with _async_client(handler) as client:
        route = await client.routes.get("r_1")
    assert route["slug"] == "payments-stripe"
    assert "meta" not in route


@pytest.mark.asyncio
async def test_account_get_and_usage_unwrap():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/account":
            return _success({"id": "t_1", "slug": "acme", "subscription_plan": "pro"})
        if req.url.path == "/v1/account/usage":
            return _success({"plan": "pro", "api_calls": {"used": 5, "limit": None, "percentage": 0}})
        return httpx.Response(404)

    async with _async_client(handler) as client:
        assert (await client.account.get())["slug"] == "acme"
        assert (await client.account.get_usage())["api_calls"]["used"] == 5


@pytest.mark.asyncio
async def test_bare_array_endpoints_unwrap_to_lists():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/environments":
            return _success([{"id": "e_1", "name": "production"}])
        if req.url.path == "/v1/crypto/keys":
            return _success([{"id": "k_1", "name": "app-key"}])
        if req.url.path == "/v1/agents":
            return _success([{"id": "ag_1", "name": "ci-agent"}])
        if req.url.path == "/v1/routes/r_1/environments":
            return _success([{"environment_name": "staging"}])
        if req.url.path == "/v1/clients/c_1/credentials":
            return _success([{"id": "cred_1", "kind": "ip"}])
        return httpx.Response(404)

    async with _async_client(handler) as client:
        assert (await client.environments.list())[0]["name"] == "production"
        assert (await client.crypto.list_keys())[0]["name"] == "app-key"
        assert (await client.agents.list())[0]["name"] == "ci-agent"
        assert (await client.routes.list_environments("r_1"))[0]["environment_name"] == "staging"
        assert (await client.clients.list_credentials("c_1"))[0]["kind"] == "ip"


@pytest.mark.asyncio
async def test_agents_create_unwraps_once_only_secret():
    def handler(req: httpx.Request) -> httpx.Response:
        # POST /v1/agents is hand-rolled: meta has secret_shown_once, no request_id
        return httpx.Response(201, json={
            "data": {"id": "ag_1", "name": "ci", "agent_id": "agent_x", "agent_secret": "as_once"},
            "meta": {"secret_shown_once": True},
        })

    async with _async_client(handler) as client:
        created = await client.agents.create(name="ci")
    assert created["agent_secret"] == "as_once"


@pytest.mark.asyncio
async def test_dyn_db_leases_unwrap_keeps_inner_limit_offset():
    def handler(req: httpx.Request) -> httpx.Response:
        assert dict(req.url.params) == {"limit": "5", "offset": "10"}
        return _success({
            "leases": [{"id": 7, "status": "active"}], "total": 11, "limit": 5, "offset": 10,
        })

    async with _async_client(handler) as client:
        leases = await client.dynamic_db.list_leases(limit=5, offset=10)
    assert leases["total"] == 11
    assert leases["leases"][0]["id"] == 7


@pytest.mark.asyncio
async def test_vault_delete_returns_deleted_true():
    def handler(req: httpx.Request) -> httpx.Response:
        return _success({"deleted": True})

    async with _async_client(handler) as client:
        assert (await client.vaults.delete("pci-vault"))["deleted"] is True


@pytest.mark.asyncio
async def test_pki_cert_and_crl_stay_raw_text():
    pem = "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n"

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=pem, headers={"content-type": "text/x-pem-file"})

    async with _async_client(handler) as client:
        assert await client.pki.get_root_cert("root-1") == pem
        assert await client.pki.get_crl("root-1") == pem


# ── new endpoints: route field-actions ────────────────────────────────────────


@pytest.mark.asyncio
async def test_route_actions_crud():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.method, req.url.path))
        if req.method == "GET":
            return _success([{"id": "act_1", "direction": "request", "action": "tokenize"}])
        if req.method == "POST":
            body = json.loads(req.content)
            assert body == {
                "direction": "request", "action": "encrypt",
                "selectors": ["$.card.number"], "key_name": "app-key",
            }
            return _success({"id": "act_2", "direction": "request", "action": "encrypt"})
        return _success({"deleted": True})

    async with _async_client(handler) as client:
        actions = await client.routes.list_actions("r_1")
        assert actions[0]["id"] == "act_1"
        created = await client.routes.create_action(
            "r_1", direction="request", action="encrypt",
            selectors=["$.card.number"], key_name="app-key",
        )
        assert created["id"] == "act_2"
        await client.routes.delete_action("r_1", "act_2")

    assert ("GET", "/v1/routes/r_1/actions") in calls
    assert ("POST", "/v1/routes/r_1/actions") in calls
    assert ("DELETE", "/v1/routes/r_1/actions/act_2") in calls


def test_route_actions_on_sync_facade():
    def handler(req: httpx.Request) -> httpx.Response:
        return _success([{"id": "act_1", "direction": "response", "action": "decrypt"}])

    with _sync_client(handler) as client:
        assert client.routes.list_actions("r_1")[0]["action"] == "decrypt"


# ── new endpoints: portable encryption ────────────────────────────────────────


@pytest.mark.asyncio
async def test_portable_encryption_endpoints():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.method, req.url.path))
        if req.url.path == "/v1/encrypt":
            assert json.loads(req.content) == {"data": {"ssn": "123"}, "key": "app-key"}
            return _success({"ciphertext": {"ssn": "kc:v1:..."}, "key": "app-key", "key_version": 3})
        if req.url.path == "/v1/decrypt":
            return _success({"plaintext": {"ssn": "123"}})
        if req.url.path == "/v1/inspect":
            assert json.loads(req.content) == {"value": "kc:v1:..."}
            return _success({"encrypted": True, "scheme": "ecdh-p256", "version": 1})
        if req.url.path == "/v1/client-tokens":
            body = json.loads(req.content)
            assert body == {"action": "decrypt", "data": "kc:v1:...", "ttl_seconds": 60}
            return _success({"token": "ct_x", "expires_at": "2026-07-03T00:00:00Z", "action": "decrypt"})
        if req.url.path == "/v1/encrypt/sealing-bundle":
            assert dict(req.url.params) == {"key": "app-key"}
            return _success({
                "public_key_raw": "BArandom",
                "key_ref": {"tenant_id": "t_1", "app_key_id": "k_1", "key_version": 3},
            })
        return httpx.Response(404)

    async with _async_client(handler) as client:
        enc = await client.crypto.encrypt_data({"ssn": "123"}, key="app-key")
        assert enc["key_version"] == 3 and enc["ciphertext"]["ssn"].startswith("kc:")
        dec = await client.crypto.decrypt_data(enc["ciphertext"])
        assert dec["plaintext"]["ssn"] == "123"
        info = await client.crypto.inspect("kc:v1:...")
        assert info["encrypted"] is True
        tok = await client.crypto.mint_client_token(action="decrypt", data="kc:v1:...", ttl_seconds=60)
        assert tok["token"] == "ct_x"
        bundle = await client.crypto.get_sealing_bundle(key="app-key")
        assert bundle["key_ref"]["key_version"] == 3

    assert ("GET", "/v1/encrypt/sealing-bundle") in calls


@pytest.mark.asyncio
async def test_mint_tokenize_capability_token():
    """Card-Grade Vaults A1 — the `tokenize` action binds a vault + page origins.

    The mint sends `vault` and `origins` and NO `data`: the value does not exist
    when the token is minted, so there is nothing to pin, and the server refuses
    a `data` on this action rather than ignoring it.
    """
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/client-tokens":
            body = json.loads(req.content)
            assert body == {
                "action": "tokenize",
                "vault": "cardholder_pii",
                "origins": ["https://shop.example.com"],
                "ttl_seconds": 300,
            }
            assert "data" not in body
            return _success({
                "token": "kct_tokenize",
                "expires_at": "2026-07-03T00:00:00Z",
                "action": "tokenize",
                "vault_id": "44444444-4444-4444-8444-444444444444",
                "origins": ["https://shop.example.com"],
            })
        return httpx.Response(404)

    async with _async_client(handler) as client:
        tok = await client.crypto.mint_client_token(
            action="tokenize",
            vault="cardholder_pii",
            origins=["https://shop.example.com"],
            ttl_seconds=300,
        )
        assert tok["action"] == "tokenize"
        assert tok["vault_id"] == "44444444-4444-4444-8444-444444444444"
        assert tok["origins"] == ["https://shop.example.com"]


def test_mint_tokenize_capability_token_on_sync_facade():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/client-tokens":
            assert json.loads(req.content)["action"] == "tokenize"
            return _success({
                "token": "kct_tokenize", "expires_at": "2026-07-03T00:00:00Z",
                "action": "tokenize", "vault_id": "v-1",
                "origins": ["https://shop.example.com"],
            })
        return httpx.Response(404)

    # The sync facade must expose everything the async client does — a method
    # that works only on one is a parity bug (sdk/PARITY.md).
    with _sync_client(handler) as client:
        tok = client.crypto.mint_client_token(
            action="tokenize", vault="pii", origins=["https://shop.example.com"],
        )
        assert tok["vault_id"] == "v-1"


def test_portable_encryption_on_sync_facade():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/encrypt":
            return _success({"ciphertext": "kc:v1:x", "key": "default", "key_version": 1})
        if req.url.path == "/v1/encrypt/sealing-bundle":
            return _success({"public_key_raw": "B", "key_ref": {}})
        return httpx.Response(404)

    with _sync_client(handler) as client:
        assert client.crypto.encrypt_data("hello")["key"] == "default"
        assert client.crypto.get_sealing_bundle()["public_key_raw"] == "B"


# ── new endpoints: webhooks test + event-types ────────────────────────────────


@pytest.mark.asyncio
async def test_webhooks_event_types_and_test():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/webhooks/event-types":
            return _success({"event_types": [
                {"value": "request.success", "label": "Success", "description": "2xx"},
            ]})
        if req.url.path == "/v1/webhooks/wh_1/test" and req.method == "POST":
            return _success({"success": True, "status": 200, "response_time_ms": 12})
        return httpx.Response(404)

    async with _async_client(handler) as client:
        types_ = await client.webhooks.list_event_types()
        assert types_["event_types"][0]["value"] == "request.success"
        result = await client.webhooks.test("wh_1")
        assert result["success"] is True and result["response_time_ms"] == 12


def test_webhooks_event_types_and_test_sync_facade():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/webhooks/event-types":
            return _success({"event_types": []})
        if req.url.path == "/v1/webhooks/wh_1/test":
            return _success({"success": False, "response_time_ms": 3, "error": "connect refused"})
        return httpx.Response(404)

    with _sync_client(handler) as client:
        assert client.webhooks.list_event_types() == {"event_types": []}
        assert client.webhooks.test("wh_1")["error"] == "connect refused"


# ── api keys: page params + once-only key ─────────────────────────────────────


@pytest.mark.asyncio
async def test_api_keys_page_params_and_create_unwrap():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "GET":
            seen["params"] = dict(req.url.params)
            return _page([{"id": "ak_1", "key_id": "AKE1"}], total=1, page=1, per_page=50)
        return _success({"key_id": "AKE2", "api_key": "AKE2.secret", "key_type": "standard"})

    async with _async_client(handler) as client:
        page = await client.api_keys.list(page=1, per_page=50)
        assert seen["params"] == {"page": "1", "per_page": "50"}
        assert page["meta"]["per_page"] == 50
        created = await client.api_keys.create(name="ci")
        assert created["api_key"] == "AKE2.secret"


# ── roles + role_ids on key create (plan §6 item 1.3) ─────────────────────────


@pytest.mark.asyncio
async def test_api_keys_create_sends_role_ids_and_returns_id():
    sent = {}

    def handler(req: httpx.Request) -> httpx.Response:
        sent["body"] = json.loads(req.content)
        return _success({
            "id": "f0a1b2c3-d4e5-6f7a-8b9c-0d1e2f3a4b5c",
            "key_id": "AKE2",
            "api_key": "AKE2.secret",
            "key_prefix": "tk_cd",
            "key_type": "standard",
            "name": "tf",
            "role_ids": ["b3f1c2d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d"],
            "message": "save it",
        })

    async with _async_client(handler) as client:
        created = await client.api_keys.create(
            name="tf", role_ids=["b3f1c2d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d"]
        )
    assert sent["body"] == {"name": "tf", "role_ids": ["b3f1c2d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d"]}
    assert created["id"] == "f0a1b2c3-d4e5-6f7a-8b9c-0d1e2f3a4b5c"
    assert created["role_ids"] == ["b3f1c2d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d"]


@pytest.mark.asyncio
async def test_api_keys_create_omits_role_ids_when_not_given():
    sent = {}

    def handler(req: httpx.Request) -> httpx.Response:
        sent["body"] = json.loads(req.content)
        return _success({"id": "x", "key_id": "AKE2", "api_key": "s", "role_ids": []})

    async with _async_client(handler) as client:
        await client.api_keys.create(name="plain")
    assert "role_ids" not in sent["body"]


@pytest.mark.asyncio
async def test_roles_list_forwards_subject_kind():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["path"] = req.url.path
        seen["params"] = dict(req.url.params)
        return _page(
            [{
                "id": "b3f1c2d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
                "name": "Key — Infrastructure",
                "description": None,
                "applies_to": ["api_key"],
                "is_default": False,
                "seeded": True,
            }],
            total=1, page=1, per_page=20,
        )

    async with _async_client(handler) as client:
        page = await client.roles.list(subject_kind="api_key")
    assert seen["path"] == "/v1/roles"
    assert seen["params"] == {"subject_kind": "api_key"}
    assert page["data"][0]["seeded"] is True
    assert page["data"][0]["applies_to"] == ["api_key"]


def test_roles_list_sync_facade():
    def handler(req: httpx.Request) -> httpx.Response:
        return _page([{"id": "r1", "name": "Key — Editor", "applies_to": ["api_key"]}],
                     total=1, page=1, per_page=20)

    with _sync_client(handler) as client:
        assert client.roles.list()["data"][0]["id"] == "r1"


@pytest.mark.asyncio
async def test_privilege_escalation_surfaces_as_permission_denied():
    from knoxcall import PermissionDeniedError

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": {
            "type": "privilege_escalation",
            "message": 'Refused grant from role "Key — Infrastructure": '
                       '{"resource_type":"vault","actions":["create"],"effect":"allow"}',
            "request_id": "req_1",
        }})

    async with _async_client(handler) as client:
        with pytest.raises(PermissionDeniedError) as exc:
            await client.api_keys.create(name="x", role_ids=["b3f1c2d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d"])
    assert exc.value.code == "privilege_escalation"


# ── wrap-credential escrow ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_wrap_escrow_posts_body_and_unwraps_metadata():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/wrap/credentials" and req.method == "POST":
            seen["body"] = json.loads(req.content)
            return _success({
                "secret_id": "s_wrap_1",
                "name": "stripe-live",
                "provider": "stripe",
                "allowed_hosts": ["api.stripe.com"],
                "sandbox": False,
            })
        return httpx.Response(404)

    async with _async_client(handler) as client:
        result = await client.wrap.escrow(
            provider="stripe",
            name="stripe-live",
            value="sk_live_abc",
            hosts=["api.stripe.com"],
        )

    assert seen["body"] == {
        "provider": "stripe",
        "name": "stripe-live",
        "value": "sk_live_abc",
        "hosts": ["api.stripe.com"],
    }
    # metadata unwrapped from the {data, meta} envelope; value never returned
    assert result["secret_id"] == "s_wrap_1"
    assert result["allowed_hosts"] == ["api.stripe.com"]
    assert result["sandbox"] is False
    assert "meta" not in result
    assert "value" not in result


def test_wrap_escrow_sync_facade():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/wrap/credentials" and req.method == "POST":
            seen["body"] = json.loads(req.content)
            return _success({
                "secret_id": "s_wrap_2",
                "name": "sendgrid",
                "provider": "sendgrid",
                "allowed_hosts": ["api.sendgrid.com"],
                "sandbox": True,
            })
        return httpx.Response(404)

    with _sync_client(handler) as client:
        result = client.wrap.escrow(
            provider="sendgrid",
            name="sendgrid",
            value="SG.raw",
            hosts=["api.sendgrid.com"],
        )

    assert seen["body"]["value"] == "SG.raw"
    assert result["secret_id"] == "s_wrap_2"
    assert result["sandbox"] is True


# ── wrap base-URL gateway tokens ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_wrap_gateway_url_posts_body_and_unwraps_metadata():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/wrap/tokens" and req.method == "POST":
            seen["body"] = json.loads(req.content)
            return _success({
                "id": "wt_1",
                "token": "wtk_secret_abc",
                "base_url": "https://api.example.test/wg/wtk_secret_abc/api.stripe.com",
                "host": "api.stripe.com",
                "secret_id": "s_wrap_1",
                "sandbox": False,
                "expires_at": "2026-09-01T00:00:00Z",
            })
        return httpx.Response(404)

    async with _async_client(handler) as client:
        result = await client.wrap.gateway_url(
            secret="stripe-live",
            host="api.stripe.com",
            ttl_seconds=3600,
            label="checkout box",
        )

    assert seen["body"] == {
        "secret": "stripe-live",
        "host": "api.stripe.com",
        "ttl_seconds": 3600,
        "label": "checkout box",
    }
    # metadata unwrapped from the {data, meta} envelope
    assert result["id"] == "wt_1"
    assert result["base_url"].endswith("/wg/wtk_secret_abc/api.stripe.com")
    assert result["secret_id"] == "s_wrap_1"
    assert result["expires_at"] == "2026-09-01T00:00:00Z"
    assert "meta" not in result


@pytest.mark.asyncio
async def test_wrap_gateway_url_omits_unset_body_fields():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(req.content)
        return _success({
            "id": "wt_2",
            "token": "wtk_x",
            "base_url": "https://api.example.test/wg/wtk_x/api.resend.com",
            "host": "api.resend.com",
            "secret_id": "s_wrap_2",
            "sandbox": True,
            "expires_at": None,
        })

    async with _async_client(handler) as client:
        result = await client.wrap.gateway_url(secret="resend-live")

    # only `secret` on the wire when host/ttl_seconds/label/style are unset
    assert seen["body"] == {"secret": "resend-live"}
    assert result["id"] == "wt_2"
    assert result["expires_at"] is None


@pytest.mark.asyncio
async def test_wrap_gateway_url_forwards_style_and_surfaces_base_url_style():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/wrap/tokens" and req.method == "POST":
            seen["body"] = json.loads(req.content)
            return _success({
                "id": "wt_3",
                "token": "wtk_sub",
                "base_url": "https://checkout.wrap.knoxcall.com",
                "base_url_style": "subdomain",
                "host": "api.stripe.com",
                "secret_id": "s_wrap_3",
                "sandbox": False,
                "expires_at": None,
            })
        return httpx.Response(404)

    async with _async_client(handler) as client:
        result = await client.wrap.gateway_url(
            secret="stripe-live", host="api.stripe.com", style="subdomain"
        )

    # `style` is forwarded verbatim in the POST body
    assert seen["body"] == {"secret": "stripe-live", "host": "api.stripe.com", "style": "subdomain"}
    # the returned form is surfaced on the result
    assert result["base_url_style"] == "subdomain"
    assert result["base_url"] == "https://checkout.wrap.knoxcall.com"


@pytest.mark.asyncio
async def test_wrap_list_gateway_tokens_returns_tokens_array():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.method, req.url.path))
        if req.url.path == "/v1/wrap/tokens" and req.method == "GET":
            return _success({"tokens": [
                {
                    "id": "wt_1",
                    "secret_id": "s_wrap_1",
                    "host": "api.stripe.com",
                    "label": "checkout box",
                    "created_at": "2026-08-14T00:00:00Z",
                    "expires_at": "2026-09-01T00:00:00Z",
                    "revoked_at": None,
                    "last_used_at": "2026-08-15T12:00:00Z",
                },
                {
                    "id": "wt_2",
                    "secret_id": "s_wrap_2",
                    "host": "api.resend.com",
                    "label": None,
                    "created_at": "2026-08-14T00:00:00Z",
                    "expires_at": None,
                    "revoked_at": None,
                    "last_used_at": None,
                },
            ]})
        return httpx.Response(404)

    async with _async_client(handler) as client:
        tokens = await client.wrap.list_gateway_tokens()

    assert ("GET", "/v1/wrap/tokens") in calls
    # the `tokens` array is surfaced (envelope + `tokens` key unwrapped)
    assert isinstance(tokens, list)
    assert [t["id"] for t in tokens] == ["wt_1", "wt_2"]
    assert tokens[0]["host"] == "api.stripe.com"
    assert tokens[0]["last_used_at"] == "2026-08-15T12:00:00Z"
    # metadata only — the token itself is never returned by list
    assert all("token" not in t for t in tokens)


@pytest.mark.asyncio
async def test_wrap_revoke_gateway_token_deletes_and_unwraps():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        # url.path decodes %2F → /, so match on the decoded path and assert the
        # encoding on the wire via raw_path below.
        calls.append((req.method, req.url.path, req.url.raw_path))
        if req.url.path == "/v1/wrap/tokens/wt/1" and req.method == "DELETE":
            return _success({"id": "wt/1", "revoked": True})
        return httpx.Response(404)

    async with _async_client(handler) as client:
        result = await client.wrap.revoke_gateway_token("wt/1")

    method, _path, raw_path = calls[0]
    assert method == "DELETE"
    # id is URL-encoded in the path on the wire ('/' → %2F)
    assert raw_path == b"/v1/wrap/tokens/wt%2F1"
    assert result == {"id": "wt/1", "revoked": True}


def test_wrap_gateway_on_sync_facade():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.method, req.url.path))
        if req.url.path == "/v1/wrap/tokens" and req.method == "POST":
            return _success({
                "id": "wt_9",
                "token": "wtk_9",
                "base_url": "https://api.example.test/wg/wtk_9/api.stripe.com",
                "host": "api.stripe.com",
                "secret_id": "s_wrap_9",
                "sandbox": False,
                "expires_at": None,
            })
        if req.url.path == "/v1/wrap/tokens" and req.method == "GET":
            return _success({"tokens": [
                {"id": "wt_9", "secret_id": "s_wrap_9", "host": "api.stripe.com",
                 "label": None, "created_at": "2026-08-14T00:00:00Z",
                 "expires_at": None, "revoked_at": None, "last_used_at": None},
            ]})
        if req.url.path == "/v1/wrap/tokens/wt_9" and req.method == "DELETE":
            return _success({"id": "wt_9", "revoked": True})
        return httpx.Response(404)

    with _sync_client(handler) as client:
        minted = client.wrap.gateway_url(secret="stripe-live", host="api.stripe.com")
        assert minted["base_url"].endswith("/wg/wtk_9/api.stripe.com")
        listed = client.wrap.list_gateway_tokens()
        assert listed[0]["id"] == "wt_9"
        assert client.wrap.revoke_gateway_token("wt_9")["revoked"] is True

    assert ("POST", "/v1/wrap/tokens") in calls
    assert ("GET", "/v1/wrap/tokens") in calls
    assert ("DELETE", "/v1/wrap/tokens/wt_9") in calls


# ── opportunities ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_opportunities_list_gets_v1_opportunities_with_filters():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.method == "GET"
        assert req.url.path == "/v1/opportunities"
        seen["params"] = dict(req.url.params)
        return _page(
            [{
                "id": "opp_1",
                "source": "gateway_traffic",
                "service": "Stripe",
                "destination_host": "api.stripe.com",
                "status": "pending",
                "confidence": 0.9,
                "suggested_route_json": {"name": "stripe"},
                "evidence_json": {"hits": 12},
                "accepted_route_id": None,
                "created_at": "2026-08-01T00:00:00Z",
                "updated_at": "2026-08-01T00:00:00Z",
                "acted_at": None,
            }],
            total=1, page=1, per_page=20,
        )

    async with _async_client(handler) as client:
        page = await client.opportunities.list(status="pending", page=1, per_page=20)

    assert seen["params"] == {"status": "pending", "page": "1", "per_page": "20"}
    assert page["data"][0]["id"] == "opp_1"
    assert page["meta"]["total_pages"] == 1


@pytest.mark.asyncio
async def test_opportunities_accept_posts_body_and_unwraps():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/opportunities/opp_1/accept" and req.method == "POST":
            seen["body"] = json.loads(req.content)
            return _success({
                "opportunity_id": "opp_1",
                "route": {"id": "r_9", "slug": "wrapped-stripe", "name": "Stripe"},
                "collection_id": "col_1",
                "environment": "production",
            })
        return httpx.Response(404)

    async with _async_client(handler) as client:
        result = await client.opportunities.accept(
            "opp_1",
            collection_name="Wrapped APIs",
            environment="production",
            secret="stripe-live",
            header_name="Authorization",
            value_prefix="Bearer ",
        )

    assert seen["body"] == {
        "collection_name": "Wrapped APIs",
        "environment": "production",
        "secret": "stripe-live",
        "header_name": "Authorization",
        "value_prefix": "Bearer ",
    }
    assert result["opportunity_id"] == "opp_1"
    assert result["route"]["slug"] == "wrapped-stripe"
    assert result["collection_id"] == "col_1"
    assert "meta" not in result


@pytest.mark.asyncio
async def test_opportunities_accept_omits_unset_body_fields():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(req.content)
        return _success({
            "opportunity_id": "opp_2",
            "route": {"id": "r_1", "slug": None, "name": "svc"},
            "collection_id": "col_2",
            "environment": "default",
        })

    async with _async_client(handler) as client:
        await client.opportunities.accept("opp_2")
    assert seen["body"] == {}  # empty body when no options passed


@pytest.mark.asyncio
async def test_opportunities_dismiss_posts_and_unwraps():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.method, req.url.path))
        if req.url.path == "/v1/opportunities/opp_1/dismiss" and req.method == "POST":
            return _success({"opportunity_id": "opp_1", "status": "dismissed"})
        return httpx.Response(404)

    async with _async_client(handler) as client:
        result = await client.opportunities.dismiss("opp_1")

    assert ("POST", "/v1/opportunities/opp_1/dismiss") in calls
    assert result == {"opportunity_id": "opp_1", "status": "dismissed"}


def test_opportunities_on_sync_facade():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.method, req.url.path))
        if req.url.path == "/v1/opportunities" and req.method == "GET":
            return _page(
                [{"id": "opp_1", "source": "agent_monitor", "service": "svc",
                  "status": "pending"}],
                total=1, page=1, per_page=20,
            )
        if req.url.path == "/v1/opportunities/opp_1/accept":
            return _success({
                "opportunity_id": "opp_1",
                "route": {"id": "r_1", "slug": "svc", "name": "svc"},
                "collection_id": "col_1",
                "environment": "production",
            })
        if req.url.path == "/v1/opportunities/opp_1/dismiss":
            return _success({"opportunity_id": "opp_1", "status": "dismissed"})
        return httpx.Response(404)

    with _sync_client(handler) as client:
        assert client.opportunities.list()["data"][0]["id"] == "opp_1"
        assert client.opportunities.accept("opp_1")["route"]["slug"] == "svc"
        assert client.opportunities.dismiss("opp_1")["status"] == "dismissed"

    assert ("GET", "/v1/opportunities") in calls
    assert ("POST", "/v1/opportunities/opp_1/accept") in calls
    assert ("POST", "/v1/opportunities/opp_1/dismiss") in calls


# ── sandbox constructor option ────────────────────────────────────────────────


def test_sandbox_defaults_base_url():
    client = KnoxCallAsync(tenant="acme", sandbox=True, bootstrap=_BOOTSTRAP)
    assert client.sandbox is True
    assert client.base_url == "https://sandbox.knoxcall.com"


def test_sandbox_explicit_base_url_wins():
    client = KnoxCallAsync(
        tenant="acme", sandbox=True, base_url="http://localhost:3000", bootstrap=_BOOTSTRAP
    )
    assert client.base_url == "http://localhost:3000"


def test_sandbox_env_base_url_wins(monkeypatch):
    monkeypatch.setenv("KNOXCALL_BASE_URL", "https://selfhost.example.test")
    client = KnoxCallAsync(tenant="acme", sandbox=True, bootstrap=_BOOTSTRAP)
    assert client.base_url == "https://selfhost.example.test"


@pytest.mark.asyncio
async def test_sandbox_data_plane_uses_sandbox_tenant_subdomain():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(str(req.url))
        return httpx.Response(200, json={"ok": True})

    async with KnoxCallAsync(
        tenant="acme",
        sandbox=True,
        bootstrap=_BOOTSTRAP,
        http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    ) as client:
        await client.call("demo-route", path="/ping")

    assert calls[0].startswith("https://sandbox-acme.knoxcall.com/")


def test_sandbox_through_sync_factory():
    client = KnoxCall(tenant="acme", sandbox=True, bootstrap=_BOOTSTRAP)
    try:
        assert client._async.base_url == "https://sandbox.knoxcall.com"
        assert client._async.sandbox is True
    finally:
        client.close()


# ── SignupError hierarchy ─────────────────────────────────────────────────────


def test_signup_error_is_a_knoxcall_error_with_original_attributes():
    assert issubclass(SignupError, KnoxCallError)
    err = SignupError("Signup failed with status 429", status=429, type="rate_limited")
    assert err.status == 429
    assert err.type == "rate_limited"
    try:
        raise err
    except KnoxCallError as caught:  # catchable via the SDK base class
        assert caught is err


def test_signup_sync_exported():
    from knoxcall import signup, signup_sync, claim_signup, claim_signup_sync
    import inspect as _inspect
    assert _inspect.iscoroutinefunction(signup)
    assert not _inspect.iscoroutinefunction(signup_sync)
    assert _inspect.iscoroutinefunction(claim_signup)
    assert not _inspect.iscoroutinefunction(claim_signup_sync)


# ── Signup: the F-25 two-step contract (wave-2 row 2-561) ────────────────────
#
# sdk/PARITY.md §11 requires all three success shapes to be covered: the
# signup 202 (which carries NO credential), the claim poll's pending 202 (a
# SUCCESS, not an error), and the claim poll's ready 200. Until 2026-08-28
# signup answered 201 with an instant API key for an unregistered address and
# 202 for a registered one — a complete account-existence oracle.

_SIGNUP_ACCEPTED = {
    "status": "pending",
    "claim_handle": "sck_Yy3n0Rz1qF8mKpX2sVb7dH9tLwQ4eJ6uA1cN5gZ8kT0",
    "claim_path": "/v1/signup/claim",
    "poll_after_seconds": 5,
    "expires_at": "2026-08-29T09:14:22.117Z",
    "message": "If this email can be registered, a sign-in link has been sent.",
    "documentation": "https://docs.knoxcall.com",
}

_CLAIM_READY = {
    "status": "ready",
    "tenant": {"id": "t_1", "slug": "acme", "name": "Acme Inc", "region": "us", "plan": "free"},
    "starter": {
        "route": {"id": "r_1", "name": "getting-started", "target_base_url": "https://httpbin.org"},
        "api_key": {
            "id": "ak_1",
            "key_id": "kid",
            "api_key": "tk_test_once",
            "key_prefix": "tk_te",
            "key_type": "test",
        },
        "sandbox_host": "sandbox-acme.knoxcall.com",
        "curl": "curl ...",
    },
    "sandbox": {
        "management_api": "https://sandbox.knoxcall.com/v1",
        "proxy_host": "sandbox-acme.knoxcall.com",
        "note": "n",
    },
    "documentation": "https://docs.knoxcall.com",
}


def _signup_transport(status: int, data: dict, seen: dict) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content or b"{}")
        return httpx.Response(status, json={"data": data, "meta": {"request_id": "req_1"}})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_signup_returns_a_claim_handle_and_no_credential():
    from knoxcall import signup

    seen: dict = {}
    res = await signup(
        email="dev@example.com",
        tenant_name="Acme Inc",
        base_url="https://api.test",
        http=_signup_transport(202, _SIGNUP_ACCEPTED, seen),
    )

    assert seen["url"] == "https://api.test/v1/signup"
    assert res["status"] == "pending"
    assert res["claim_handle"].startswith("sck_")
    # The whole point of row 2-561: nothing key-shaped in the signup reply.
    assert "tk_" not in json.dumps(res)
    assert "starter" not in res


async def test_claim_signup_pending_is_a_success_not_an_error():
    from knoxcall import claim_signup

    seen: dict = {}
    res = await claim_signup(
        claim_handle="sck_handle",
        base_url="https://api.test",
        http=_signup_transport(
            202,
            {"status": "pending", "message": "Not ready yet.", "poll_after_seconds": 5,
             "expires_at": "2026-08-29T09:14:22.117Z"},
            seen,
        ),
    )

    assert seen["url"] == "https://api.test/v1/signup/claim"
    assert seen["body"] == {"claim_handle": "sck_handle"}
    assert res["status"] == "pending"
    assert "tk_" not in json.dumps(res)


async def test_claim_signup_ready_carries_the_one_time_key():
    from knoxcall import claim_signup

    res = await claim_signup(
        claim_handle="sck_handle",
        base_url="https://api.test",
        http=_signup_transport(200, _CLAIM_READY, {}),
    )

    assert res["status"] == "ready"
    assert res["starter"]["api_key"]["api_key"] == "tk_test_once"
    assert res["starter"]["api_key"]["key_type"] == "test"
    assert res["tenant"]["slug"] == "acme"


async def test_claim_signup_raises_signup_error_when_already_collected():
    from knoxcall import claim_signup

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            409, json={"error": {"type": "claim_already_collected", "message": "already collected"}}
        )

    with pytest.raises(SignupError) as excinfo:
        await claim_signup(
            claim_handle="sck_handle",
            base_url="https://api.test",
            http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )
    assert excinfo.value.status == 409
    assert excinfo.value.type == "claim_already_collected"


@pytest.mark.asyncio
async def test_wrap_intercept_manifest_gets_the_manifest_and_forwards_environment():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.method, req.url.path, dict(req.url.params)))
        if req.url.path == "/v1/wrap/intercept-manifest" and req.method == "GET":
            return _success({
                "version": "sha256:abc",
                "ttl_seconds": 60,
                "environment": req.url.params.get("environment", "production"),
                "sandbox": False,
                "routes": [{
                    "host": "api.hubapi.com", "base_path": "/crm/v3", "slug": "hubspot", "route_id": "r-1",
                    "requires_clients": False, "allowed_methods": None, "updated_at": "2026-09-25T00:00:00.000Z",
                }],
            })
        return httpx.Response(404)

    async with _async_client(handler) as client:
        m = await client.wrap.intercept_manifest()
        staging = await client.wrap.intercept_manifest(environment="staging")

    assert m["version"] == "sha256:abc"
    assert m["ttl_seconds"] == 60
    assert m["environment"] == "production"
    assert m["routes"][0]["host"] == "api.hubapi.com"
    assert m["routes"][0]["slug"] == "hubspot"
    assert m["routes"][0]["base_path"] == "/crm/v3"
    # the environment query is sent only when asked for
    assert calls[0] == ("GET", "/v1/wrap/intercept-manifest", {})
    assert calls[1] == ("GET", "/v1/wrap/intercept-manifest", {"environment": "staging"})
    assert staging["environment"] == "staging"
