"""exchange_token() — credential-less RFC 8693 exchange against POST /v1/oauth/token.

Three behaviours a caller gets wrong, all asserted here:
  1. The response is a BARE OAuth body, not the ``{data, meta}`` envelope.
  2. ``resource`` is only sent when supplied — sending it empty is a refusal,
     not "no resource", because dropping it silently would mint an UNCONFINED
     token while the caller believes it is audience-restricted.
  3. The path is ``/v1/oauth/token``, NOT the root-host ``/oauth/token`` that
     mints management tokens.
  4. The HOST is the tenant data plane. Verified against a running server
     2026-08-25: the same request answers 400 invalid_grant on
     acme.knoxcall.com and 401 on api.knoxcall.com, so there is no default.
"""

from __future__ import annotations

import json

import httpx
import pytest

from knoxcall import (
    KNOXCALL_AUDIENCE,
    BootstrapError,
    KnoxCallError,
    TokenExchangeError,
    exchange_token,
    exchange_token_sync,
)
from knoxcall.resources.token_exchange import ID_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT

OK = {
    "access_token": "kc_live_agt_deadbeef",
    "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
    "token_type": "Bearer",
    "expires_in": 900,
    "scope": '{"providers":["anthropic"]}',
}


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_posts_the_grant_and_returns_the_bare_body():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        seen["headers"] = {k.lower(): v for k, v in request.headers.items()}
        return httpx.Response(200, json=OK)

    res = await exchange_token(
        subject_token="header.payload.sig",
        base_url="https://acme.test",
        http=_client(handler),
    )

    assert seen["url"] == "https://acme.test/v1/oauth/token"
    assert seen["body"]["grant_type"] == TOKEN_EXCHANGE_GRANT
    assert seen["body"]["subject_token_type"] == ID_TOKEN_TYPE
    assert seen["body"]["audience"] == KNOXCALL_AUDIENCE
    assert seen["body"]["subject_token"] == "header.payload.sig"
    # The subject token IS the credential — nothing else is sent.
    assert "authorization" not in seen["headers"]
    # Bare OAuth body: no envelope to unwrap.
    assert res["access_token"] == "kc_live_agt_deadbeef"
    assert "data" not in res


@pytest.mark.asyncio
async def test_omits_resource_when_not_requested():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json=OK)

    await exchange_token(subject_token="a.b.c", base_url="https://acme.test", http=_client(handler))
    assert "resource" not in seen["body"]


@pytest.mark.asyncio
async def test_forwards_an_empty_resource_verbatim():
    # It must reach the server and be refused invalid_target. Treating it as
    # absent would hand back an UNCONFINED agent token to a caller who asked
    # for a confined one.
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json=OK)

    await exchange_token(
        subject_token="a.b.c", resource="", base_url="https://acme.test", http=_client(handler)
    )
    assert seen["body"]["resource"] == ""


@pytest.mark.asyncio
async def test_raises_with_the_rfc6749_error_code():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400,
            json={
                "error": "invalid_grant",
                "error_description": "No tenant bindings registered for issuer https://x",
            },
        )

    with pytest.raises(TokenExchangeError) as exc:
        await exchange_token(
            subject_token="a.b.c", base_url="https://acme.test", http=_client(handler)
        )
    assert isinstance(exc.value, KnoxCallError)  # re-parented into the SDK hierarchy
    assert exc.value.status == 400
    assert exc.value.type == "invalid_grant"
    assert "No tenant bindings" in str(exc.value)


@pytest.mark.asyncio
async def test_raises_when_a_200_carries_no_access_token():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"token_type": "Bearer"})

    with pytest.raises(TokenExchangeError) as exc:
        await exchange_token(
            subject_token="a.b.c", base_url="https://acme.test", http=_client(handler)
        )
    assert exc.value.type == "token_exchange_failed"


@pytest.mark.asyncio
async def test_does_not_mask_a_non_json_error_page():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(502, text="<html>502</html>")

    with pytest.raises(TokenExchangeError) as exc:
        await exchange_token(
            subject_token="a.b.c", base_url="https://acme.test", http=_client(handler)
        )
    assert exc.value.status == 502


def test_sync_wrapper_returns_the_same_body():
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://acme.test/v1/oauth/token"
        return httpx.Response(200, json=OK)

    res = exchange_token_sync(
        subject_token="a.b.c", base_url="https://acme.test", http=_client(handler)
    )
    assert res["expires_in"] == 900


@pytest.mark.asyncio
async def test_derives_the_tenant_data_plane_host():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        return httpx.Response(200, json=OK)

    await exchange_token(subject_token="a.b.c", tenant="acme", http=_client(handler))
    assert seen["url"] == "https://acme.knoxcall.com/v1/oauth/token"


@pytest.mark.asyncio
async def test_derives_the_sandbox_data_plane_host():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        return httpx.Response(200, json=OK)

    await exchange_token(subject_token="a.b.c", tenant="acme", sandbox=True, http=_client(handler))
    assert seen["url"] == "https://sandbox-acme.knoxcall.com/v1/oauth/token"


@pytest.mark.asyncio
async def test_warns_when_the_exchange_would_cross_a_plaintext_hop():
    # The subject token IS a credential, so a plaintext hop leaks it. PARITY 15
    # already warns when a CLIENT is constructed against plaintext http; this
    # function deliberately constructs no client, so the control had to be added
    # on this path too or it would exist on one and be absent on the parallel one.
    from knoxcall._warn import KnoxCallSecurityWarning

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=OK)

    with pytest.warns(KnoxCallSecurityWarning, match="plaintext HTTP"):
        await exchange_token(
            subject_token="a.b.c", base_url="http://evil.example", http=_client(handler)
        )


@pytest.mark.asyncio
async def test_does_not_warn_for_https_or_loopback(recwarn):
    # The acceptance harness and local dev both use http://127.0.0.1, so a
    # refusal here would be wrong and a warning there would be noise.
    from knoxcall._warn import KnoxCallSecurityWarning

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=OK)

    await exchange_token(subject_token="a.b.c", base_url="https://acme.test", http=_client(handler))
    await exchange_token(
        subject_token="a.b.c", base_url="http://127.0.0.1:3000", http=_client(handler)
    )
    assert not [w for w in recwarn if isinstance(w.message, KnoxCallSecurityWarning)]


@pytest.mark.asyncio
async def test_refuses_to_guess_a_host():
    # api.knoxcall.com answers 401 for this request -- the endpoint is not
    # served there. A default would turn "wrong host" into "your CI token was
    # rejected", the hardest possible thing to debug.
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("no request should be sent")

    with pytest.raises(BootstrapError) as exc:
        await exchange_token(subject_token="a.b.c", http=_client(handler))
    assert "tenant" in str(exc.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["evil.com#", "a b", "-lead", "trail-", ""])
async def test_refuses_a_tenant_slug_that_is_not_a_dns_label(bad):
    # The slug becomes the host the workload OIDC token is sent to.
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("no request should be sent")

    with pytest.raises(BootstrapError):
        await exchange_token(subject_token="a.b.c", tenant=bad, http=_client(handler))
