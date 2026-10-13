"""End-to-end SDK tests using a stub httpx transport."""

from __future__ import annotations
import json

import httpx
import pytest

from knoxcall import KnoxCallAsync, AuthenticationError, RateLimitError, ServerError, ValidationError
from knoxcall.auth.bootstrap import (
    AccessTokenBootstrap,
    ClientCredentialsBootstrap,
    OidcTokenExchangeBootstrap,
)


def _make_transport(handler):
    return httpx.MockTransport(handler)


def _ok(body: dict) -> httpx.Response:
    return httpx.Response(200, json=body)


def _meta(**extra) -> dict:
    """The meta the server's success() helper builds."""
    return {"request_id": "req_00000000-0000-0000-0000-000000000000", **extra}


def _success(data) -> httpx.Response:
    """A real single-object success envelope: {data, meta}."""
    return httpx.Response(200, json={"data": data, "meta": _meta()})


def _paginated(items: list, *, total: int, page: int = 1, per_page: int = 20) -> httpx.Response:
    """A real paginated envelope exactly as helpers.ts builds it."""
    total_pages = max(1, -(-total // per_page))
    return httpx.Response(200, json={
        "data": items,
        "meta": _meta(total=total, page=page, per_page=per_page, total_pages=total_pages),
    })


@pytest.mark.asyncio
async def test_client_credentials_mints_and_attaches_bearer():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.method, str(req.url), dict(req.headers), req.content.decode() if req.content else ""))
        if req.url.path == "/oauth/token":
            return _ok({"access_token": "kc_live_aaaa", "token_type": "Bearer", "expires_in": 3600})
        if req.url.path == "/v1/routes":
            return _paginated([{"id": "r_1", "name": "test"}], total=1)
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme",
            base_url="https://api.example.test",
            bootstrap=ClientCredentialsBootstrap(
                type="client_credentials", client_id="tk_x", client_secret="sec"
            ),
            http=http,
        ) as client:
            await client.routes.list()

    token_call = calls[0]
    assert token_call[1].endswith("/oauth/token")
    assert "Basic " in token_call[2].get("authorization", "")
    assert "grant_type=client_credentials" in token_call[3]

    api_call = calls[1]
    assert api_call[1].endswith("/v1/routes")
    assert api_call[2]["authorization"] == "Bearer kc_live_aaaa"
    assert api_call[2]["knoxcall-version"]


@pytest.mark.asyncio
async def test_caches_token_across_calls():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req.url.path)
        if req.url.path == "/oauth/token":
            return _ok({"access_token": "kc_live_x", "token_type": "Bearer", "expires_in": 3600})
        return _paginated([], total=0)

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme",
            base_url="https://api.example.test",
            bootstrap=ClientCredentialsBootstrap(
                type="client_credentials", client_id="tk_x", client_secret="sec"
            ),
            http=http,
        ) as client:
            await client.routes.list()
            await client.routes.list()
            await client.routes.list()

    token_calls = [c for c in calls if c == "/oauth/token"]
    assert len(token_calls) == 1


@pytest.mark.asyncio
async def test_access_token_bootstrap_skips_token_endpoint():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req.url.path)
        return _paginated([], total=0)

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme",
            base_url="https://api.example.test",
            bootstrap=AccessTokenBootstrap(type="access_token", access_token="kc_live_preset"),
            http=http,
        ) as client:
            await client.routes.list()

    assert "/oauth/token" not in calls
    assert "/v1/routes" in calls


@pytest.mark.asyncio
async def test_oidc_token_exchange_grant_body():
    seen_body = {}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/oauth/token":
            seen_body["body"] = req.content.decode()
            return _ok({"access_token": "kc_live_y", "token_type": "Bearer", "expires_in": 3600})
        return _paginated([], total=0)

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme",
            base_url="https://api.example.test",
            bootstrap=OidcTokenExchangeBootstrap(
                type="oidc_token_exchange",
                subject_token="eyJraWQiOiJ4In0.aGVsbG8.",
                issuer="https://gh",
            ),
            http=http,
        ) as client:
            await client.routes.list()

    assert "grant_type=urn" in seen_body["body"]
    assert "subject_token" in seen_body["body"]
    assert "audience=knoxcall" in seen_body["body"]


@pytest.mark.asyncio
async def test_dpop_adds_proof_header():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.url.path, dict(req.headers)))
        if req.url.path == "/oauth/token":
            return _ok({"access_token": "kc_live_dpop", "token_type": "DPoP", "expires_in": 3600})
        return _paginated([], total=0)

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme",
            base_url="https://api.example.test",
            bootstrap=ClientCredentialsBootstrap(
                type="client_credentials", client_id="tk_x", client_secret="sec"
            ),
            dpop="always",
            http=http,
        ) as client:
            await client.routes.list()

    token_call = next(c for c in calls if c[0] == "/oauth/token")
    assert token_call[1].get("dpop")

    api_call = next(c for c in calls if c[0] == "/v1/routes")
    assert api_call[1]["authorization"] == "DPoP kc_live_dpop"
    assert api_call[1].get("dpop")
    # DPoP proof is a 3-part JWT
    assert api_call[1]["dpop"].count(".") == 2


@pytest.mark.asyncio
async def test_idempotency_key_on_post_only():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.method, req.url.path, dict(req.headers)))
        if req.url.path == "/v1/routes" and req.method == "POST":
            return _success({"id": "r_1", "name": "x"})
        return _paginated([], total=0)

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme",
            base_url="https://api.example.test",
            bootstrap=AccessTokenBootstrap(type="access_token", access_token="kc_live_x"),
            http=http,
        ) as client:
            await client.routes.list()
            await client.routes.create(name="x", target_base_url="y")

    get_call = next(c for c in calls if c[0] == "GET" and c[1] == "/v1/routes")
    post_call = next(c for c in calls if c[0] == "POST" and c[1] == "/v1/routes")
    assert "x-idempotency-key" not in get_call[2]
    assert post_call[2]["x-idempotency-key"]
    assert len(post_call[2]["x-idempotency-key"]) == 26  # ULID


@pytest.mark.asyncio
async def test_user_idempotency_key_preserved():
    seen_key = {}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "POST" and req.url.path == "/v1/routes":
            seen_key["k"] = req.headers.get("x-idempotency-key")
            return _success({"id": "r_1"})
        return _paginated([], total=0)

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme",
            base_url="https://api.example.test",
            bootstrap=AccessTokenBootstrap(type="access_token", access_token="kc_live_x"),
            http=http,
        ) as client:
            await client.routes.create(name="x", target_base_url="y", idempotency_key="my-key-123")

    assert seen_key["k"] == "my-key-123"


@pytest.mark.asyncio
async def test_maps_401_to_authentication_error():
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid_token"})

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme",
            base_url="https://api.example.test",
            bootstrap=AccessTokenBootstrap(type="access_token", access_token="kc_live_x"),
            retry_max_attempts=1,
            http=http,
        ) as client:
            with pytest.raises(AuthenticationError):
                await client.routes.list()


@pytest.mark.asyncio
async def test_maps_422_to_validation_error_with_fields():
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            422,
            json={"error": "validation_failed", "fields": {"name": ["required"]}},
        )

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme",
            base_url="https://api.example.test",
            bootstrap=AccessTokenBootstrap(type="access_token", access_token="kc_live_x"),
            retry_max_attempts=1,
            http=http,
        ) as client:
            with pytest.raises(ValidationError) as exc:
                await client.routes.create(name="", target_base_url="")
            assert exc.value.fields == {"name": ["required"]}


@pytest.mark.asyncio
async def test_maps_429_to_rate_limit_with_retry_after():
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            429,
            headers={"retry-after": "60"},
            json={"error": "rate_limit_exceeded"},
        )

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme",
            base_url="https://api.example.test",
            bootstrap=AccessTokenBootstrap(type="access_token", access_token="kc_live_x"),
            retry_max_attempts=1,
            http=http,
        ) as client:
            with pytest.raises(RateLimitError) as exc:
                await client.routes.list()
            assert exc.value.retry_after == 60


@pytest.mark.asyncio
async def test_maps_503_dependency_unavailable_to_server_error_with_retry_after():
    # KnoxCall could not reach one of its own dependencies: a retryable server
    # fault carrying Retry-After — never an authentication failure (it used to
    # be an opaque 401 on the data plane), and honoured like a 429's.
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            503,
            headers={"retry-after": "5", "x-request-id": "req-dep-1"},
            json={
                "error": {
                    "type": "dependency_unavailable",
                    "message": "KnoxCall could not reach its control plane in time.",
                    "request_id": "req-dep-1",
                    "dependency": "control_plane",
                    "retry_after": 5,
                }
            },
        )

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme",
            base_url="https://api.example.test",
            bootstrap=AccessTokenBootstrap(type="access_token", access_token="kc_live_x"),
            retry_max_attempts=1,
            http=http,
        ) as client:
            with pytest.raises(ServerError) as exc:
                await client.routes.list()
            assert not isinstance(exc.value, AuthenticationError)
            assert exc.value.status == 503
            assert exc.value.code == "dependency_unavailable"
            assert exc.value.request_id == "req-dep-1"
            assert exc.value.retry_after == 5
            # The retry loop waits the header on a 503 exactly as on a 429, capped at 30 s.
            assert client._retry_delay(exc.value, 1) == 5.0
            assert client._retry_delay(ServerError("shed", status=503, retry_after=600), 1) == 30.0
            # A plain 5xx with no header keeps the jittered backoff.
            plain = ServerError("boom", status=500)
            assert plain.retry_after is None
            assert client._retry_delay(plain, 1) <= client._retry_max_delay


@pytest.mark.asyncio
async def test_retries_on_5xx():
    attempts = {"n": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/routes":
            attempts["n"] += 1
            if attempts["n"] < 3:
                return httpx.Response(503, json={"error": "unavailable"})
            return _paginated([{"id": "r_1"}], total=1)
        return _paginated([], total=0)

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme",
            base_url="https://api.example.test",
            bootstrap=AccessTokenBootstrap(type="access_token", access_token="kc_live_x"),
            retry_max_attempts=3,
            retry_base_delay=0.001,
            retry_max_delay=0.005,
            http=http,
        ) as client:
            result = await client.routes.list()
            assert result["data"][0]["id"] == "r_1"
            assert attempts["n"] == 3


@pytest.mark.asyncio
async def test_does_not_retry_on_400():
    attempts = {"n": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/routes":
            attempts["n"] += 1
            return httpx.Response(400, json={"error": "invalid_request"})
        return _paginated([], total=0)

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme",
            base_url="https://api.example.test",
            bootstrap=AccessTokenBootstrap(type="access_token", access_token="kc_live_x"),
            retry_max_attempts=5,
            retry_base_delay=0.001,
            retry_max_delay=0.005,
            http=http,
        ) as client:
            with pytest.raises(Exception):
                await client.routes.list()
            assert attempts["n"] == 1


@pytest.mark.asyncio
async def test_redacted_does_not_leak_in_repr():
    from knoxcall.redacted import Redacted
    r = Redacted("kc_live_supersecret")
    assert repr(r) == "[REDACTED]"
    assert str(r) == "[REDACTED]"
    assert "supersecret" not in repr(r)
    # Round-trip via JSON
    assert json.dumps({"t": str(r)}) == '{"t": "[REDACTED]"}'


@pytest.mark.asyncio
async def test_ulid_format():
    from knoxcall.ulid import ulid
    u = ulid()
    assert len(u) == 26
    assert all(c in "0123456789ABCDEFGHJKMNPQRSTVWXYZ" for c in u)


def test_dpop_thumbprint_stable():
    from knoxcall.auth.dpop import DpopKeyPair
    kp = DpopKeyPair.generate()
    t1 = kp.thumbprint()
    t2 = kp.thumbprint()
    assert t1 == t2
    assert len(t1) == 43  # sha256 b64url


def test_dpop_sign_produces_three_parts():
    from knoxcall.auth.dpop import DpopKeyPair
    kp = DpopKeyPair.generate()
    proof = kp.sign(method="POST", url="https://api.example.test/oauth/token")
    assert proof.count(".") == 2


# ---------------------------------------------------------------------------
# Secrets resource
# ---------------------------------------------------------------------------

def _bootstrap():
    from knoxcall.auth.bootstrap import AccessTokenBootstrap
    return AccessTokenBootstrap(type="access_token", access_token="kc_live_x")


@pytest.mark.asyncio
async def test_secrets_list():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/secrets":
            assert req.method == "GET"
            return _paginated([{"id": "s_1", "name": "my-key"}], total=1)
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme", base_url="https://api.example.test", bootstrap=_bootstrap(), http=http
        ) as client:
            result = await client.secrets.list()

    assert result["data"][0]["id"] == "s_1"
    assert result["meta"]["total_pages"] == 1


@pytest.mark.asyncio
async def test_secrets_create_sends_body():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/secrets" and req.method == "POST":
            seen["body"] = json.loads(req.content)
            return _success({"id": "s_2", "name": "stripe-key"})
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme", base_url="https://api.example.test", bootstrap=_bootstrap(), http=http
        ) as client:
            result = await client.secrets.create(
                name="stripe-key", secret_type="api_key", value="sk_live_abc"
            )

    assert seen["body"]["name"] == "stripe-key"
    assert seen["body"]["secret_type"] == "api_key"
    assert seen["body"]["value"] == "sk_live_abc"
    assert result["id"] == "s_2"


# Audit finding M3: OAuth2 / certificate secrets were not creatable via the typed
# SDK (base create() is closed to name/secret_type/value).
@pytest.mark.asyncio
async def test_secrets_create_oauth2_hits_typed_route():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/secrets/oauth2" and req.method == "POST":
            seen["body"] = json.loads(req.content)
            return _success({"id": "s_oauth", "name": "stripe", "secret_type": "oauth2"})
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme", base_url="https://api.example.test", bootstrap=_bootstrap(), http=http
        ) as client:
            result = await client.secrets.create_oauth2(
                name="stripe", provider="custom", client_id="ci", client_secret="cs", scopes=["read"]
            )

    assert seen["body"] == {"name": "stripe", "provider": "custom", "client_id": "ci", "client_secret": "cs", "scopes": ["read"]}
    assert result["id"] == "s_oauth"


@pytest.mark.asyncio
async def test_secrets_create_certificate_hits_typed_route():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/secrets/certificate" and req.method == "POST":
            seen["body"] = json.loads(req.content)
            return _success({"id": "s_cert", "name": "mtls", "secret_type": "certificate"})
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme", base_url="https://api.example.test", bootstrap=_bootstrap(), http=http
        ) as client:
            result = await client.secrets.create_certificate(
                name="mtls", certificate_content="-----BEGIN CERT-----", certificate_type="pem"
            )

    assert seen["body"]["certificate_content"].startswith("-----BEGIN CERT")
    assert result["id"] == "s_cert"


@pytest.mark.asyncio
async def test_secrets_get_encodes_id():
    seen_url = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen_url["u"] = str(req.url)
        return _success({"id": "s_3"})

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme", base_url="https://api.example.test", bootstrap=_bootstrap(), http=http
        ) as client:
            await client.secrets.get("s_3 with spaces")

    assert "%20" in seen_url["u"]


# ---------------------------------------------------------------------------
# Webhooks resource
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_webhooks_list():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/webhooks":
            assert req.method == "GET"
            return _paginated([{"id": "wh_1", "name": "my-hook"}], total=1)
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme", base_url="https://api.example.test", bootstrap=_bootstrap(), http=http
        ) as client:
            result = await client.webhooks.list()

    assert result["data"][0]["id"] == "wh_1"


@pytest.mark.asyncio
async def test_webhooks_create():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/webhooks" and req.method == "POST":
            seen["body"] = json.loads(req.content)
            return _success({"id": "wh_2", "secret_key": "whsec_once"})
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme", base_url="https://api.example.test", bootstrap=_bootstrap(), http=http
        ) as client:
            await client.webhooks.create(
                name="orders", url="https://example.com/hook", event_types=["route.request"]
            )

    assert seen["body"]["event_types"] == ["route.request"]


# ---------------------------------------------------------------------------
# Clients resource
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_clients_list():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/clients":
            return _paginated([{"id": "c_1", "name": "service-a"}], total=1)
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme", base_url="https://api.example.test", bootstrap=_bootstrap(), http=http
        ) as client:
            result = await client.clients.list()

    assert result["data"][0]["id"] == "c_1"


# ---------------------------------------------------------------------------
# verify_webhook_signature (F1.4)
# ---------------------------------------------------------------------------

def test_verify_webhook_signature_valid():
    import hashlib
    import hmac as _hmac
    from knoxcall import verify_webhook_signature

    secret = "whsec_test"
    body = b'{"event":"route.request"}'
    expected = _hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    assert verify_webhook_signature(raw_body=body, signature=expected, secret=secret) is True


def test_verify_webhook_signature_str_body():
    import hashlib
    import hmac as _hmac
    from knoxcall import verify_webhook_signature

    secret = "whsec_test"
    body = '{"event":"route.request"}'
    expected = _hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()

    assert verify_webhook_signature(raw_body=body, signature=expected, secret=secret) is True


def test_verify_webhook_signature_wrong_secret():
    from knoxcall import verify_webhook_signature
    assert verify_webhook_signature(raw_body=b"hello", signature="deadbeef", secret="wrong") is False


def test_verify_webhook_signature_timestamp_tolerance_pass():
    import hashlib
    import hmac as _hmac
    import time
    from knoxcall import verify_webhook_signature

    secret = "whsec_test"
    body = b"payload"
    expected = _hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    now = int(time.time())

    assert verify_webhook_signature(
        raw_body=body, signature=expected, secret=secret,
        timestamp=now - 10, tolerance_seconds=30,
    ) is True


def test_verify_webhook_signature_timestamp_too_old():
    import hashlib
    import hmac as _hmac
    import time
    from knoxcall import verify_webhook_signature

    secret = "whsec_test"
    body = b"payload"
    expected = _hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    now = int(time.time())

    assert verify_webhook_signature(
        raw_body=body, signature=expected, secret=secret,
        timestamp=now - 600, tolerance_seconds=30,
    ) is False


# ---------------------------------------------------------------------------
# RedisTokenStore (F1.2)
# ---------------------------------------------------------------------------

class _FakeRedis:
    """Minimal in-memory stand-in that satisfies AsyncRedisClient."""

    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    async def get(self, key: str) -> str | None:
        return self._store.get(key)

    async def set(self, key: str, value: str | bytes, *, nx: bool = False, ex: int | None = None) -> bool | None:
        v = value.decode() if isinstance(value, bytes) else value
        if nx:
            if key in self._store:
                return None
            self._store[key] = v
            return True
        self._store[key] = v
        return True

    async def delete(self, *keys: str) -> int:
        count = 0
        for k in keys:
            if k in self._store:
                del self._store[k]
                count += 1
        return count


@pytest.mark.asyncio
async def test_redis_store_set_and_get():
    import time
    from knoxcall.auth.token_store import RedisTokenStore, CachedToken
    from knoxcall.redacted import Redacted

    redis = _FakeRedis()
    store = RedisTokenStore(redis, prefix="test:")
    token = CachedToken(
        access_token=Redacted("kc_live_abc"),
        expires_at=time.time() + 3600,
        scope=["routes:read"],
        token_type="Bearer",
    )
    await store.set("tenant:scope", token)
    result = await store.get("tenant:scope")
    assert result is not None
    assert result.access_token.expose() == "kc_live_abc"
    assert result.scope == ["routes:read"]


@pytest.mark.asyncio
async def test_redis_store_delete():
    import time
    from knoxcall.auth.token_store import RedisTokenStore, CachedToken
    from knoxcall.redacted import Redacted

    redis = _FakeRedis()
    store = RedisTokenStore(redis)
    token = CachedToken(
        access_token=Redacted("kc_live_x"), expires_at=time.time() + 3600
    )
    await store.set("k", token)
    assert await store.get("k") is not None
    await store.delete("k")
    assert await store.get("k") is None


@pytest.mark.asyncio
async def test_redis_store_corrupt_cache_returns_none():
    from knoxcall.auth.token_store import RedisTokenStore

    redis = _FakeRedis()
    redis._store["knoxcall:token:k"] = "not-json"
    store = RedisTokenStore(redis)
    assert await store.get("k") is None


@pytest.mark.asyncio
async def test_redis_store_with_lock_single_flight():
    """Only one concurrent refresh should call fn; second sees the cached result."""
    import asyncio
    import time
    from knoxcall.auth.token_store import RedisTokenStore, CachedToken
    from knoxcall.redacted import Redacted

    redis = _FakeRedis()
    store = RedisTokenStore(redis)
    call_count = {"n": 0}

    async def refresh():
        call_count["n"] += 1
        await asyncio.sleep(0.01)
        t = CachedToken(access_token=Redacted("kc_live_r"), expires_at=time.time() + 3600)
        await store.set("k", t)
        return t

    results = await asyncio.gather(
        store.with_lock("k", refresh),
        store.with_lock("k", refresh),
    )
    # Both complete; the important thing is fn ran at least once and
    # both returned a valid token.
    assert all(r.access_token.expose() == "kc_live_r" for r in results)


@pytest.mark.asyncio
async def test_redis_store_key_prefix():
    import time
    from knoxcall.auth.token_store import RedisTokenStore, CachedToken
    from knoxcall.redacted import Redacted

    redis = _FakeRedis()
    store = RedisTokenStore(redis, prefix="myapp:")
    token = CachedToken(access_token=Redacted("t"), expires_at=time.time() + 3600)
    await store.set("key", token)
    assert "myapp:token:key" in redis._store


# ---------------------------------------------------------------------------
# clients resource — create / update / delete
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_clients_create():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/clients" and req.method == "POST":
            seen["body"] = json.loads(req.content)
            return _success({"id": "c_2", "name": "web-server"})
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme", base_url="https://api.example.test", bootstrap=_bootstrap(), http=http
        ) as client:
            result = await client.clients.create(name="web-server", ip_address="10.0.0.1")

    assert seen["body"]["name"] == "web-server"
    assert seen["body"]["ip_address"] == "10.0.0.1"
    assert result["id"] == "c_2"


@pytest.mark.asyncio
async def test_clients_update():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/clients/c_1" and req.method == "PATCH":
            seen["body"] = json.loads(req.content)
            return _success({"id": "c_1"})
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme", base_url="https://api.example.test", bootstrap=_bootstrap(), http=http
        ) as client:
            await client.clients.update("c_1", name="renamed", enabled=False)

    assert seen["body"]["name"] == "renamed"
    assert seen["body"]["enabled"] is False


@pytest.mark.asyncio
async def test_clients_delete():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.method, req.url.path))
        return _success({"deleted": True})

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme", base_url="https://api.example.test", bootstrap=_bootstrap(), http=http
        ) as client:
            await client.clients.delete("c_1")

    assert ("DELETE", "/v1/clients/c_1") in calls


# ---------------------------------------------------------------------------
# oauth_clients resource
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_oauth_clients_list():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/oauth-clients" and req.method == "GET":
            # oauth-clients bypasses success(): {data} bare, no meta, no pagination
            return _ok({"data": [{"id": "oc_1", "name": "my-app"}]})
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme", base_url="https://api.example.test", bootstrap=_bootstrap(), http=http
        ) as client:
            result = await client.oauth_clients.list()

    assert result[0]["id"] == "oc_1"


@pytest.mark.asyncio
async def test_oauth_clients_create():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/oauth-clients" and req.method == "POST":
            seen["body"] = json.loads(req.content)
            return httpx.Response(
                201,
                json={
                    "data": {
                        "id": "oc_2", "client_id": "tk_abcd1234",
                        "client_secret": "deadbeef", "type": "confidential",
                        "grant_types": ["client_credentials"],
                    },
                    "warning": "Copy the client_secret now.",
                },
            )
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme", base_url="https://api.example.test", bootstrap=_bootstrap(), http=http
        ) as client:
            result = await client.oauth_clients.create(
                name="ci-runner", grant_types=["client_credentials"], require_dpop=True
            )

    assert seen["body"]["name"] == "ci-runner"
    assert seen["body"]["require_dpop"] is True
    assert result["client_id"] == "tk_abcd1234"
    assert "client_secret" in result
    # top-level warning is folded into the returned object
    assert result["warning"] == "Copy the client_secret now."


@pytest.mark.asyncio
async def test_oauth_clients_update():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/oauth-clients/oc_1" and req.method == "PATCH":
            seen["body"] = json.loads(req.content)
            return _ok({"data": {"id": "oc_1"}})
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme", base_url="https://api.example.test", bootstrap=_bootstrap(), http=http
        ) as client:
            await client.oauth_clients.update(
                "oc_1", allowed_scopes=["routes:read", "secrets:read"], active=True
            )

    assert seen["body"]["allowed_scopes"] == ["routes:read", "secrets:read"]
    assert seen["body"]["active"] is True


@pytest.mark.asyncio
async def test_oauth_clients_rotate_secret():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.method, req.url.path))
        return _ok({
            "data": {"client_id": "tk_x", "client_secret": "newSecret"},
            "warning": "Copy it now.",
        })

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme", base_url="https://api.example.test", bootstrap=_bootstrap(), http=http
        ) as client:
            result = await client.oauth_clients.rotate_secret("oc_1")

    assert ("POST", "/v1/oauth-clients/oc_1/rotate-secret") in calls
    assert result["client_secret"] == "newSecret"
    assert result["warning"] == "Copy it now."


@pytest.mark.asyncio
async def test_oauth_clients_revoke():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.method, req.url.path))
        return _ok({"data": {"revoked": True}})

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme", base_url="https://api.example.test", bootstrap=_bootstrap(), http=http
        ) as client:
            result = await client.oauth_clients.revoke("oc_1")

    assert ("DELETE", "/v1/oauth-clients/oc_1") in calls
    assert result["revoked"] is True


# ---------------------------------------------------------------------------
# call() — proxy requests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_call_sends_route_header_and_bearer():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.method, str(req.url), dict(req.headers)))
        return httpx.Response(200, json={"customers": []})

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme",
            base_url="https://api.example.test",
            proxy_base_url="https://proxy.example.test",
            bootstrap=AccessTokenBootstrap(type="access_token", access_token="kc_live_x"),
            http=http,
        ) as client:
            resp = await client.call("stripe-customers", method="GET", path="/v1/customers")

    assert resp.status_code == 200
    call = calls[0]
    assert call[1] == "https://proxy.example.test/v1/customers"
    assert call[2]["x-knoxcall-route"] == "stripe-customers"
    assert call[2]["authorization"] == "Bearer kc_live_x"


@pytest.mark.asyncio
async def test_call_with_environment_header():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(dict(req.headers))
        return httpx.Response(200, json={})

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme",
            base_url="https://api.example.test",
            proxy_base_url="https://proxy.example.test",
            bootstrap=AccessTokenBootstrap(type="access_token", access_token="kc_live_x"),
            http=http,
        ) as client:
            await client.call("my-api", path="/status", environment="staging")

    assert calls[0]["x-knoxcall-environment"] == "staging"


@pytest.mark.asyncio
async def test_call_with_post_body():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["method"] = req.method
        seen["body"] = json.loads(req.content)
        return httpx.Response(201, json={"id": "cus_123"})

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme",
            base_url="https://api.example.test",
            proxy_base_url="https://proxy.example.test",
            bootstrap=AccessTokenBootstrap(type="access_token", access_token="kc_live_x"),
            http=http,
        ) as client:
            resp = await client.call(
                "stripe-customers",
                method="POST",
                path="/v1/customers",
                body={"email": "test@example.com"},
            )

    assert seen["method"] == "POST"
    assert seen["body"]["email"] == "test@example.com"
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_call_dpop_adds_proof():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/oauth/token":
            return _ok({"access_token": "kc_live_dpop", "token_type": "DPoP", "expires_in": 3600})
        calls.append(dict(req.headers))
        return httpx.Response(200, json={})

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme",
            base_url="https://api.example.test",
            proxy_base_url="https://proxy.example.test",
            bootstrap=ClientCredentialsBootstrap(
                type="client_credentials", client_id="tk_x", client_secret="sec"
            ),
            dpop="always",
            http=http,
        ) as client:
            await client.call("my-route", path="/data")

    assert calls[0]["authorization"].startswith("DPoP ")
    assert calls[0].get("dpop", "").count(".") == 2


@pytest.mark.asyncio
async def test_call_proxy_base_url_derived_from_production():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(str(req.url))
        return httpx.Response(200, json={})

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme",
            base_url="https://api.knoxcall.com",
            bootstrap=AccessTokenBootstrap(type="access_token", access_token="kc_live_x"),
            http=http,
        ) as client:
            await client.call("my-route", path="/test")

    assert calls[0].startswith("https://acme.knoxcall.com/")


# ---------------------------------------------------------------------------
# ephemeral() — one-shot proxy + wrap-support headers (PR2)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ephemeral_sets_proxy_url_header():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((str(req.url), dict(req.headers)))
        return httpx.Response(200, json={})

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme",
            base_url="https://api.example.test",
            bootstrap=AccessTokenBootstrap(type="access_token", access_token="kc_live_x"),
            http=http,
        ) as client:
            await client.ephemeral("https://stripe.com/v1/charges", method="POST")

    url, headers = calls[0]
    assert url == "https://api.example.test/v1/proxy"
    assert headers["x-knox-proxy-url"] == "https://stripe.com/v1/charges"
    # Additive options absent by default.
    assert "x-knox-proxy-mode" not in headers
    assert "x-knox-upstream-authorization" not in headers


@pytest.mark.asyncio
async def test_ephemeral_transparent_mode_emits_header():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(dict(req.headers))
        return httpx.Response(200, json={})

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme",
            base_url="https://api.example.test",
            bootstrap=AccessTokenBootstrap(type="access_token", access_token="kc_live_x"),
            http=http,
        ) as client:
            await client.ephemeral(
                "https://stripe.com/v1/charges",
                method="POST",
                mode="transparent",
            )

    assert calls[0]["x-knox-proxy-mode"] == "transparent"


@pytest.mark.asyncio
async def test_ephemeral_upstream_authorization_emits_header():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(dict(req.headers))
        return httpx.Response(200, json={})

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme",
            base_url="https://api.example.test",
            bootstrap=AccessTokenBootstrap(type="access_token", access_token="kc_live_x"),
            http=http,
        ) as client:
            await client.ephemeral(
                "https://stripe.com/v1/charges",
                method="POST",
                upstream_authorization="Bearer sk_live_provider_secret",
            )

    headers = calls[0]
    assert headers["x-knox-upstream-authorization"] == "Bearer sk_live_provider_secret"
    # The SDK's own KnoxCall auth is unaffected.
    assert headers["authorization"] == "Bearer kc_live_x"


@pytest.mark.asyncio
async def test_ephemeral_upstream_auth_secret_emits_headers():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(dict(req.headers))
        return httpx.Response(200, json={})

    async with httpx.AsyncClient(transport=_make_transport(handler)) as http:
        async with KnoxCallAsync(
            tenant="acme",
            base_url="https://api.example.test",
            bootstrap=AccessTokenBootstrap(type="access_token", access_token="kc_live_x"),
            http=http,
        ) as client:
            await client.ephemeral(
                "https://stripe.com/v1/charges",
                method="POST",
                upstream_auth_secret="stripe-secret-key",
                upstream_auth_scheme="Bearer",
            )

    headers = calls[0]
    assert headers["x-knox-upstream-auth-secret"] == "stripe-secret-key"
    assert headers["x-knox-upstream-auth-scheme"] == "Bearer"
    # The SDK's own KnoxCall auth is unaffected.
    assert headers["authorization"] == "Bearer kc_live_x"
