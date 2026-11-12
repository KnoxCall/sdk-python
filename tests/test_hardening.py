"""Tests for the hardened request pipeline and the thread-safe sync wrapper."""

from __future__ import annotations
import asyncio
import datetime
import decimal
import json
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from knoxcall import (
    APIConnectionError,
    KnoxCall,
    KnoxCallAsync,
    KnoxCallError,
    MemoryTokenStore,
    PermissionDeniedError,
)
from knoxcall.auth.bootstrap import ClientCredentials
from knoxcall.auth.token_store import CachedToken
from knoxcall.errors import error_from_response
from knoxcall.redacted import Redacted

_BOOTSTRAP = ClientCredentials(
    client_id="tk_x", client_secret="sec"
)


def _token_response(token: str = "kc_live_aaaa", expires_in: int = 3600) -> httpx.Response:
    return httpx.Response(
        200, json={"access_token": token, "token_type": "Bearer", "expires_in": expires_in}
    )


def _client_kwargs(handler, **extra):
    transport = httpx.MockTransport(handler)
    return dict(
        tenant="acme",
        base_url="https://api.example.test",
        proxy_base_url="https://acme.example.test",
        bootstrap=_BOOTSTRAP,
        http=httpx.AsyncClient(transport=transport),
        retry_base_delay=0.001,
        **extra,
    )


# ── Sync wrapper ──────────────────────────────────────────────────────────────


def test_sync_wrapper_concurrent_threads():
    """A module-level singleton must survive concurrent calls from many threads."""
    counts = {"proxy": 0, "token": 0}
    lock = threading.Lock()

    async def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/oauth/token":
            with lock:
                counts["token"] += 1
            return _token_response()
        await asyncio.sleep(0.01)  # force calls to overlap on the loop
        with lock:
            counts["proxy"] += 1
        return httpx.Response(200, json={"ok": True})

    client = KnoxCall(**_client_kwargs(handler))
    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(
                pool.map(lambda _: client.call("r_1", path="/things"), range(32))
            )
        assert all(r.status_code == 200 for r in results)
        assert counts["proxy"] == 32
        assert counts["token"] == 1  # single-flight held across threads
    finally:
        client.close()


def test_sync_wrapper_without_context_manager_and_idempotent_close():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/oauth/token":
            return _token_response()
        return httpx.Response(200, json={"ok": True})

    client = KnoxCall(**_client_kwargs(handler))
    assert client.call("r_1", path="/x").status_code == 200
    client.close()
    client.close()  # second close is a no-op
    with pytest.raises(KnoxCallError, match="closed"):
        client.call("r_1", path="/x")


def test_sync_wrapper_sign_out_and_reauthenticate():
    tokens = iter(["kc_live_one", "kc_live_two"])

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/oauth/token":
            return _token_response(next(tokens))
        return httpx.Response(200, json={"auth": req.headers["authorization"]})

    with KnoxCall(**_client_kwargs(handler)) as client:
        first = client.call("r_1", path="/x").json()["auth"]
        client.sign_out()
        second = client.call("r_1", path="/x").json()["auth"]
    assert first == "Bearer kc_live_one"
    assert second == "Bearer kc_live_two"


# ── call() hardening ──────────────────────────────────────────────────────────


async def test_call_purges_token_and_retries_once_on_401():
    minted: list[str] = []
    seq = iter(["kc_live_revoked", "kc_live_fresh"])

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/oauth/token":
            token = next(seq)
            minted.append(token)
            return _token_response(token)
        if req.headers["authorization"] == "Bearer kc_live_revoked":
            return httpx.Response(401, json={"error": "Unauthorized"})
        return httpx.Response(200, json={"ok": True})

    async with KnoxCallAsync(**_client_kwargs(handler)) as client:
        res = await client.call("r_1", path="/x")
    assert res.status_code == 200
    assert minted == ["kc_live_revoked", "kc_live_fresh"]


async def test_call_second_401_is_returned_not_looped():
    token_calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/oauth/token":
            token_calls.append(1)
            return _token_response("kc_live_bad")
        return httpx.Response(401, json={"error": "Unauthorized"})

    async with KnoxCallAsync(**_client_kwargs(handler)) as client:
        res = await client.call("r_1", path="/x")
    assert res.status_code == 401
    assert len(token_calls) == 2  # original + the single re-auth, no infinite loop


async def test_call_retries_idle_disconnect_for_get_only():
    state = {"get_fails": 1, "post_attempts": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/oauth/token":
            return _token_response()
        if req.method == "GET":
            if state["get_fails"]:
                state["get_fails"] -= 1
                raise httpx.RemoteProtocolError("Server disconnected")
            return httpx.Response(200, json={"ok": True})
        state["post_attempts"] += 1
        raise httpx.RemoteProtocolError("Server disconnected")

    async with KnoxCallAsync(**_client_kwargs(handler)) as client:
        res = await client.call("r_1", path="/x")
        assert res.status_code == 200  # GET retried transparently
        with pytest.raises(APIConnectionError):
            await client.call("r_1", method="POST", path="/x", body={"a": 1})
    assert state["post_attempts"] == 1  # mutating request NOT replayed


async def test_call_retries_connect_error_even_for_post():
    state = {"fails": 1, "attempts": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/oauth/token":
            return _token_response()
        state["attempts"] += 1
        if state["fails"]:
            state["fails"] -= 1
            raise httpx.ConnectError("connection refused")
        return httpx.Response(200, json={"ok": True})

    async with KnoxCallAsync(**_client_kwargs(handler)) as client:
        res = await client.call("r_1", method="POST", path="/x", body={"a": 1})
    assert res.status_code == 200
    assert state["attempts"] == 2  # never reached the wire → safe to retry


async def test_call_sends_route_environment_and_query():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/oauth/token":
            return _token_response()
        seen["headers"] = dict(req.headers)
        seen["url"] = str(req.url)
        return httpx.Response(200, json={"ok": True})

    async with KnoxCallAsync(**_client_kwargs(handler)) as client:
        await client.call(
            "r_1",
            path="/x",
            environment="production",
            query={"page": 2},
            headers={"x-knoxcall-route": "spoofed", "X-Custom": "1"},
        )
    # explicit arguments beat the headers dict
    assert seen["headers"]["x-knoxcall-route"] == "r_1"
    assert seen["headers"]["x-knoxcall-environment"] == "production"
    assert seen["headers"]["x-custom"] == "1"
    assert "page=2" in seen["url"]


async def test_call_strips_caller_supplied_proxy_auth_headers():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/oauth/token":
            return _token_response()
        seen["headers"] = dict(req.headers)
        return httpx.Response(200, json={"ok": True})

    async with KnoxCallAsync(**_client_kwargs(handler)) as client:
        await client.call(
            "r_1",
            path="/x",
            headers={
                # An integrator forwarding untrusted end-user headers must not
                # be able to inject an alternate proxy identity or override the
                # SDK credential.
                "x-knoxcall-agent-id": "attacker-agent",
                "X-Knoxcall-Agent-Token": "attacker-token",
                "Authorization": "Bearer kc_live_attacker",
                "DPoP": "forged-proof",
                "x-knoxcall-key": "tk_attacker",
                # The interceptors' reroute marker (PARITY §21.2) is SDK-owned
                # too: an app must not relabel its own direct calls as intercepted.
                "X-KnoxCall-Origin": "sdk-intercept",
                "X-Custom": "ok",
            },
        )
    # The SDK's own credential is the only auth on the wire...
    assert seen["headers"]["authorization"] == "Bearer kc_live_aaaa"
    # ...and none of the caller's proxy-auth headers survive.
    assert "x-knoxcall-agent-id" not in seen["headers"]
    assert "x-knoxcall-agent-token" not in seen["headers"]
    assert "x-knoxcall-key" not in seen["headers"]
    assert "dpop" not in seen["headers"]
    assert "x-knoxcall-origin" not in seen["headers"]
    # Non-auth caller headers still pass through.
    assert seen["headers"]["x-custom"] == "ok"


async def test_direct_call_carries_no_origin_marker_and_rejects_an_unknown_one():
    """A direct ``call()`` sends no ``x-knoxcall-origin`` — absence IS "direct"
    on the server (PARITY §21.2) — and the internal ``_origin`` accepts only
    the one marker, so a typo cannot silently send nothing."""
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/oauth/token":
            return _token_response()
        seen["headers"] = dict(req.headers)
        return httpx.Response(200, json={"ok": True})

    async with KnoxCallAsync(**_client_kwargs(handler)) as client:
        await client.call("r_1", path="/x")
        assert seen["headers"]["x-knoxcall-route"] == "r_1"
        assert "x-knoxcall-origin" not in seen["headers"]

        seen.clear()
        await client.route("r_1").get("/x")
        assert "x-knoxcall-origin" not in seen["headers"]

        with pytest.raises(ValueError, match="unknown call origin"):
            await client.call("r_1", path="/x", _origin="something-else")


# ── Body encoding ─────────────────────────────────────────────────────────────


async def test_call_body_encodes_erp_types():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/oauth/token":
            return _token_response()
        seen["body"] = json.loads(req.content)
        seen["content_type"] = req.headers["content-type"]
        return httpx.Response(200)

    a_uuid = uuid.uuid4()
    async with KnoxCallAsync(**_client_kwargs(handler)) as client:
        await client.call(
            "r_1",
            method="POST",
            path="/x",
            body={
                "when": datetime.datetime(2026, 6, 10, 12, 30),
                "day": datetime.date(2026, 6, 10),
                "amount": decimal.Decimal("19.99"),
                "ref": a_uuid,
                "tags": {"b", "b"},
            },
        )
    assert seen["content_type"] == "application/json"
    assert seen["body"]["when"] == "2026-06-10T12:30:00"
    assert seen["body"]["day"] == "2026-06-10"
    assert seen["body"]["amount"] == pytest.approx(19.99)
    assert seen["body"]["ref"] == str(a_uuid)
    assert seen["body"]["tags"] == ["b"]


async def test_call_str_and_bytes_bodies_pass_through_with_custom_content_type():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/oauth/token":
            return _token_response()
        seen["body"] = req.content
        seen["content_type"] = req.headers["content-type"]
        return httpx.Response(200)

    async with KnoxCallAsync(**_client_kwargs(handler)) as client:
        await client.call(
            "r_1", method="POST", path="/x",
            body=b"%PDF-1.4 raw", headers={"Content-Type": "application/pdf"},
        )
    assert seen["body"] == b"%PDF-1.4 raw"
    assert seen["content_type"] == "application/pdf"


# ── Token lifecycle ───────────────────────────────────────────────────────────


async def test_short_lived_tokens_are_not_refetched_every_request():
    token_calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/oauth/token":
            token_calls.append(1)
            return _token_response(expires_in=60)  # shorter than the 5-min window
        return httpx.Response(200, json={"ok": True})

    async with KnoxCallAsync(**_client_kwargs(handler)) as client:
        for _ in range(5):
            await client.call("r_1", path="/x")
    assert len(token_calls) == 1


async def test_stale_but_valid_token_used_when_token_endpoint_down():
    store = MemoryTokenStore()
    # Inside the 5-minute refresh-ahead window, but still genuinely valid.
    await store.set(
        "acme:",
        CachedToken(
            access_token=Redacted("kc_live_stale"),
            expires_at=time.time() + 60,
            lifetime=3600,
        ),
    )

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/oauth/token":
            return httpx.Response(503, json={"error": "unavailable"})
        return httpx.Response(200, json={"auth": req.headers["authorization"]})

    async with KnoxCallAsync(**_client_kwargs(handler, token_store=store)) as client:
        res = await client.call("r_1", path="/x")
    assert res.json()["auth"] == "Bearer kc_live_stale"


# ── DPoP auto mode ────────────────────────────────────────────────────────────


async def test_dpop_auto_upgrades_when_client_requires_dpop():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/oauth/token":
            if "dpop" not in req.headers:
                return httpx.Response(
                    400,
                    json={
                        "error": "invalid_dpop_proof",
                        "error_description": "this client requires a DPoP proof on token requests",
                    },
                )
            return httpx.Response(
                200,
                json={"access_token": "kc_live_dpop", "token_type": "DPoP", "expires_in": 3600},
            )
        return httpx.Response(
            200,
            json={
                "auth": req.headers["authorization"],
                "has_proof": "dpop" in req.headers,
            },
        )

    async with KnoxCallAsync(**_client_kwargs(handler)) as client:  # dpop="auto"
        body = (await client.call("r_1", path="/x")).json()
    assert body["auth"].startswith("DPoP kc_live_dpop")
    assert body["has_proof"] is True


def test_invalid_dpop_mode_rejected():
    with pytest.raises(KnoxCallError, match="dpop"):
        KnoxCallAsync(tenant="acme", bootstrap=_BOOTSTRAP, dpop="sometimes")


# ── request() re-auth + Retry-After ───────────────────────────────────────────


async def test_request_transparent_reauth_on_401():
    seq = iter(["kc_live_old", "kc_live_new"])

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/oauth/token":
            return _token_response(next(seq))
        if req.headers["authorization"] == "Bearer kc_live_old":
            return httpx.Response(401, json={"error": "Unauthorized"})
        return httpx.Response(200, json={"data": [], "meta": {
            "total": 0, "page": 1, "per_page": 20, "total_pages": 0, "request_id": "req_x"}})

    async with KnoxCallAsync(**_client_kwargs(handler)) as client:
        assert (await client.routes.list())["data"] == []


def test_retry_delay_honors_retry_after_capped():
    client = KnoxCallAsync(tenant="acme", bootstrap=_BOOTSTRAP)
    short = error_from_response(429, {"error": "rate_limited"}, {"retry-after": "2"})
    long = error_from_response(429, {"error": "rate_limited"}, {"retry-after": "600"})
    assert client._retry_delay(short, 1) == 2.0
    assert client._retry_delay(long, 1) == 30.0


# ── Secret hygiene + error names ──────────────────────────────────────────────


def test_bootstrap_repr_does_not_leak_secret():
    assert "sec" not in repr(_BOOTSTRAP)
    assert "tk_x" in repr(_BOOTSTRAP)  # client_id is not sensitive


def test_bootstrap_renames_and_deprecated_aliases():
    from knoxcall import AccessToken, ClientCredentialsBootstrap, OIDCTokenExchange

    # Old names still construct the same classes; type discriminator defaults.
    assert ClientCredentialsBootstrap is ClientCredentials
    cc = ClientCredentialsBootstrap(client_id="tk_x", client_secret="sec")
    assert cc.type == "client_credentials"
    assert AccessToken(access_token="kc_live_x").type == "access_token"
    oidc = OIDCTokenExchange(subject_token="jwt", issuer="https://oidc.vercel.com")
    assert oidc.type == "oidc_token_exchange"
    assert "jwt" not in repr(oidc)


def test_permission_denied_error_mapping_and_alias():
    import builtins

    import knoxcall.errors as errors_mod

    err = error_from_response(403, {"error": "forbidden"}, {})
    assert isinstance(err, PermissionDeniedError)
    assert errors_mod.PermissionError is PermissionDeniedError
    assert not isinstance(err, builtins.PermissionError)


# Audit finding H1: the canonical /v1 error is {"error":{"type","message",
# "request_id"}} — `error` is a DICT. The old mapper rendered a dict-repr and set
# `code` to the dict; these guard the fix.
def test_parses_canonical_shape_a_nested_error():
    err = error_from_response(
        403,
        {"error": {"type": "wrong_key_type", "message": "This key type cannot be used here.", "request_id": "req-9"}},
        {},
    )
    assert isinstance(err, PermissionDeniedError)
    assert str(err) == "This key type cannot be used here."
    assert "{" not in str(err)  # not a dict-repr
    assert err.code == "wrong_key_type"
    assert err.request_id == "req-9"  # from the body when no header present


def test_prefers_request_id_header_over_body():
    err = error_from_response(
        404,
        {"error": {"type": "not_found", "message": "nope", "request_id": "body-id"}},
        {"x-request-id": "header-id"},
    )
    assert err.request_id == "header-id"


def test_maps_402_plan_limit_to_payment_required():
    from knoxcall.errors import PaymentRequiredError

    err = error_from_response(
        402,
        {"error": {"type": "plan_limit", "message": "Vault limit reached. Upgrade your plan.", "request_id": "req-2"}},
        {},
    )
    assert isinstance(err, PaymentRequiredError)
    assert err.code == "plan_limit"
    assert not isinstance(err, PermissionDeniedError)


def test_flat_shape_c_prefers_human_message_over_code():
    err = error_from_response(
        409,
        {"error": "request_in_progress", "message": "A request with this idempotency key is still being processed."},
        {},
    )
    assert str(err) == "A request with this idempotency key is still being processed."
    assert err.code == "request_in_progress"
