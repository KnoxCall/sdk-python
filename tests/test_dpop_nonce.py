"""The DPoP server nonce (RFC 9449 §8) — PARITY §7.1, client Phase 4.3.

Four behaviours, and the fourth is the one that is easy to get wrong:

1. remember the most recent ``DPoP-Nonce`` per ORIGIN;
2. send it as the proof's ``nonce`` claim on every later request to that origin;
3. on the server's "use a nonce" refusal, re-sign ONCE with the nonce that
   refusal carried, with a new ``jti``, and never loop;
4. that refusal is NOT an authentication failure. A 401 normally purges the
   cached token and spends the one re-auth; a ``use_dpop_nonce`` 401 must do
   neither, or every nonce rotation costs a token mint — and the retry would
   then succeed for the wrong reason, which is what would hide it.

Capture is at the HTTP boundary (an injected transport that records the proofs
it is sent and answers with the headers the real server sends), so these drive
the real signer, the real store and the real retry loops.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import httpx
import pytest

from knoxcall import KnoxCall
from knoxcall.auth.dpop_nonce import DpopNonceStore, is_use_dpop_nonce, origin_of
from knoxcall.errors import AuthenticationError


def proof_claims(proof: str) -> dict[str, Any]:
    """The payload of a DPoP proof JWT, unverified (we signed it)."""
    payload = proof.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


# ── the store ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://api.knoxcall.com/v1/routes", "https://api.knoxcall.com"),
        ("https://api.knoxcall.com/v1/routes?a=1#f", "https://api.knoxcall.com"),
        ("https://API.KnoxCall.com/v1", "https://api.knoxcall.com"),
        ("http://localhost:3000/v1", "http://localhost:3000"),
        ("https://api.knoxcall.com:8443/v1", "https://api.knoxcall.com:8443"),
        ("not a url", ""),
        ("", ""),
    ],
)
def test_origin_is_scheme_host_port(url: str, expected: str) -> None:
    assert origin_of(url) == expected


def test_the_store_is_keyed_by_origin_not_by_url() -> None:
    s = DpopNonceStore()
    s.remember("https://api.knoxcall.com/oauth/token", {"dpop-nonce": "A"})
    # Same origin, different path and query — still the same nonce.
    assert s.get("https://api.knoxcall.com/v1/routes?x=1") == "A"
    # A DIFFERENT origin has not answered yet. The management API and a
    # tenant's data plane issue different values; sending one to the other
    # would be refused.
    assert s.get("https://acme.knoxcall.com/api/anything") is None
    s.remember("https://acme.knoxcall.com/api/x", {"dpop-nonce": "B"})
    assert s.get("https://acme.knoxcall.com/api/y") == "B"
    assert s.get("https://api.knoxcall.com/v1/routes") == "A"


def test_last_write_wins_and_blank_values_are_ignored() -> None:
    s = DpopNonceStore()
    s.remember("https://api.test/x", {"dpop-nonce": "first"})
    s.remember("https://api.test/x", {"dpop-nonce": "second"})
    assert s.get("https://api.test/x") == "second"
    # A header that is absent, empty or whitespace must not erase what we hold.
    for headers in ({}, {"dpop-nonce": ""}, {"dpop-nonce": "   "}):
        assert s.remember("https://api.test/x", headers) is None
        assert s.get("https://api.test/x") == "second"


def test_a_hostless_url_is_not_remembered() -> None:
    s = DpopNonceStore()
    assert s.remember("not a url", {"dpop-nonce": "x"}) is None
    assert s.snapshot() == {}


# ── the refusal predicate ────────────────────────────────────────────────────


def test_the_authorization_server_refusal_is_a_400_with_an_oauth_body() -> None:
    assert is_use_dpop_nonce(status=400, code="use_dpop_nonce", headers={}) is True


def test_the_resource_server_refusal_is_recognised_from_the_header_alone() -> None:
    """The tenant data plane keeps its deliberately opaque `Unauthorized` body,
    so the challenge header is the ONLY signal there. A predicate that read the
    body would work on /v1 and silently never fire on the data plane."""
    assert is_use_dpop_nonce(
        status=401, code=None, headers={"www-authenticate": 'DPoP error="use_dpop_nonce"'}
    ) is True
    # Case and surrounding parameters must not matter.
    assert is_use_dpop_nonce(
        status=401, code=None,
        headers={"www-authenticate": 'DPoP realm="knoxcall", ERROR="USE_DPOP_NONCE"'},
    ) is True


@pytest.mark.parametrize(
    "status,code,headers",
    [
        (401, "invalid_token", {}),
        (401, None, {"www-authenticate": 'DPoP error="invalid_token"'}),
        (403, "use_dpop_nonce", {}),
        (500, "use_dpop_nonce", {}),
        (200, None, {}),
        (None, None, None),
    ],
)
def test_nothing_else_is_a_nonce_refusal(status: Any, code: Any, headers: Any) -> None:
    assert is_use_dpop_nonce(status=status, code=code, headers=headers) is False


# ── end to end, through the real client ─────────────────────────────────────


class Recorder:
    """Records every request and answers from PER-SURFACE queues.

    Keyed by surface rather than one flat queue on purpose: a single queue let a
    token-endpoint response answer a `/v1` request once the script ran dry,
    which made a correctly-bounded retry look like a spurious success."""

    def __init__(
        self,
        *,
        token: list[httpx.Response] | None = None,
        api: list[httpx.Response] | None = None,
        default: httpx.Response | None = None,
    ) -> None:
        self.token = list(token or [])
        self.api = list(api or [])
        self.default = default
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        queue = self.token if "/oauth/token" in str(request.url) else self.api
        if queue:
            return queue.pop(0)
        if self.default is not None:
            return self.default
        raise AssertionError(f"unscripted request: {request.method} {request.url}")

    def proofs(self, *, path_contains: str | None = None) -> list[dict[str, Any]]:
        out = []
        for r in self.requests:
            if path_contains is not None and path_contains not in str(r.url):
                continue
            proof = r.headers.get("dpop")
            if proof:
                out.append(proof_claims(proof))
        return out

    def mints(self) -> list[httpx.Request]:
        return [r for r in self.requests if "/oauth/token" in str(r.url)]


def token_response(nonce: str | None = None) -> httpx.Response:
    headers = {"content-type": "application/json"}
    if nonce:
        headers["DPoP-Nonce"] = nonce
    return httpx.Response(
        200,
        headers=headers,
        json={"access_token": "kc_at_x", "token_type": "DPoP", "expires_in": 3600},
    )


def client_for(recorder: Recorder) -> Any:
    return KnoxCall(
        sync=True,
        tenant="acme",
        base_url="https://api.test",
        proxy_base_url="https://acme.test",
        client_id="tk_id",
        client_secret="shh",
        dpop="always",
        http=httpx.AsyncClient(transport=httpx.MockTransport(recorder)),
        retry_max_attempts=3,
    )


def test_the_nonce_from_the_mint_is_sent_on_the_next_api_call() -> None:
    rec = Recorder(
        token=[token_response("NONCE-1")],
        api=[
            httpx.Response(200, headers={"DPoP-Nonce": "NONCE-2"}, json={"data": {"ok": True}}),
            httpx.Response(200, json={"data": {"ok": True}}),
        ],
    )
    with client_for(rec) as c:
        c.routes.list()
        c.routes.list()

    mint, first_call, second_call = rec.proofs()[0], rec.proofs()[1], rec.proofs()[2]
    # The very first proof — the mint — has no nonce to send, and the server
    # accepts that.
    assert "nonce" not in mint
    assert first_call["nonce"] == "NONCE-1"
    # The API response carried a newer one, so the next call uses THAT.
    assert second_call["nonce"] == "NONCE-2"

def test_a_resource_server_refusal_re_signs_once_and_succeeds() -> None:
    rec = Recorder(
        token=[token_response("STALE")],
        api=[
            httpx.Response(
                401,
                headers={"www-authenticate": 'DPoP error="use_dpop_nonce"', "DPoP-Nonce": "FRESH"},
                json={"error": {"type": "use_dpop_nonce", "message": "nonce required"}},
            ),
            httpx.Response(200, json={"data": {"ok": True}}),
        ],
    )
    with client_for(rec) as c:
        c.routes.list()

    calls = rec.proofs(path_contains="/v1/routes")
    assert len(calls) == 2, "exactly one retry"
    assert calls[0]["nonce"] == "STALE"
    assert calls[1]["nonce"] == "FRESH", "the retry must use the nonce the refusal carried"
    assert calls[0]["jti"] != calls[1]["jti"], "a new jti: the refused proof's may have been spent"
    assert len(rec.mints()) == 1, "the nonce refusal must not have purged the token"

def test_a_nonce_refusal_does_not_spend_the_token_re_mint() -> None:
    """The failure this guards: a nonce refusal treated as an auth failure
    purges the cache, so every rotation costs a mint — and the retry succeeds
    anyway, which is what hides it."""
    rec = Recorder(
        token=[token_response("STALE")],
        api=[
            httpx.Response(401, headers={"www-authenticate": 'DPoP error="use_dpop_nonce"', "DPoP-Nonce": "FRESH"}),
            httpx.Response(200, json={"data": {"ok": True}}),
        ],
    )
    with client_for(rec) as c:
        c.routes.list()
    assert len(rec.mints()) == 1, f"the nonce refusal spent a token mint ({len(rec.mints())} mints)"

def test_a_real_401_still_re_mints() -> None:
    """The nonce branch must not swallow a genuine authentication failure."""
    rec = Recorder(
        token=[token_response("N1"), token_response("N2")],
        api=[
            httpx.Response(401, json={"error": {"type": "invalid_token", "message": "nope"}}),
            httpx.Response(200, json={"data": {"ok": True}}),
        ],
    )
    with client_for(rec) as c:
        c.routes.list()
    assert len(rec.mints()) == 2, "a real 401 must still purge and re-mint once"

def test_the_retry_never_loops() -> None:
    """A server that refuses every proof must surface the error, not spin."""
    def refusal() -> httpx.Response:
        return httpx.Response(
            401,
            headers={"www-authenticate": 'DPoP error="use_dpop_nonce"', "DPoP-Nonce": "N"},
            json={"error": {"type": "use_dpop_nonce", "message": "nonce required"}},
        )

    rec = Recorder(token=[token_response("N")], api=[], default=refusal())
    with client_for(rec) as c:
        with pytest.raises(AuthenticationError):
            c.routes.list()
    calls = rec.proofs(path_contains="/v1/routes")
    # ONE nonce re-sign, then the error surfaces. It must NOT also spend the
    # re-auth: the token was deliberately not purged, so that retry would
    # resend an identical request.
    assert len(calls) == 2, f"expected 1 retry, saw {len(calls)} attempts"
    assert len(rec.mints()) == 1, "a nonce refusal must never cost a mint"

def test_the_token_endpoint_re_signs_once_on_its_400() -> None:
    rec = Recorder(
        token=[
            httpx.Response(
                400,
                headers={"DPoP-Nonce": "FRESH"},
                json={"error": "use_dpop_nonce", "error_description": "nonce required"},
            ),
            token_response("FRESH"),
        ],
        api=[httpx.Response(200, json={"data": {"ok": True}})],
    )
    with client_for(rec) as c:
        c.routes.list()

    mints = rec.proofs(path_contains="/oauth/token")
    assert len(mints) == 2, "exactly one re-sign of the mint"
    assert "nonce" not in mints[0]
    assert mints[1]["nonce"] == "FRESH"
    assert mints[0]["jti"] != mints[1]["jti"]

def test_the_mint_re_signs_in_place_with_no_outer_retry_loop_to_fall_back_on() -> None:
    """Isolates the mint-level retry.

    ``authenticate()`` drives the token fetch directly, outside ``request()``'s
    retry loop — so if the mint did not retry itself, this 400 would reach the
    caller. The test above cannot show that: it goes through ``request()``,
    whose own nonce branch ALSO matches a 400 and would mask a missing
    mint-level retry entirely. Found by break-verifying, which is the only
    reason this test exists.
    """
    rec = Recorder(
        token=[
            httpx.Response(
                400,
                headers={"DPoP-Nonce": "FRESH"},
                json={"error": "use_dpop_nonce", "error_description": "nonce required"},
            ),
            token_response("FRESH"),
        ],
    )
    with client_for(rec) as c:
        c.authenticate()

    mints = rec.proofs(path_contains="/oauth/token")
    assert len(mints) == 2, "exactly one re-sign of the mint"
    assert "nonce" not in mints[0]
    assert mints[1]["nonce"] == "FRESH"
    assert mints[0]["jti"] != mints[1]["jti"]


def test_the_data_plane_refusal_is_retried_from_the_header_alone() -> None:
    """The opaque-body path. `call()` goes through the proxy send loop, not the
    management-API one, so it needs its own retry — and the body says nothing."""
    rec = Recorder(
        token=[token_response("STALE")],
        api=[
            httpx.Response(
                401,
                headers={"www-authenticate": 'DPoP error="use_dpop_nonce"', "DPoP-Nonce": "FRESH"},
                text="Unauthorized",
            ),
            httpx.Response(200, json={"ok": True}),
        ],
    )
    with client_for(rec) as c:
        resp = c.call("my-route", path="/v1/things")
    assert resp.status_code == 200
    calls = rec.proofs(path_contains="acme.test")
    assert len(calls) == 2
    # The data plane is a DIFFERENT ORIGIN from the management API, so the
    # nonce the mint returned (api.test) is correctly NOT sent here: this
    # origin has not answered yet. The retry then uses the one its own refusal
    # carried. A store keyed on anything coarser than the origin would have
    # sent api.test's nonce and been refused for it.
    assert "nonce" not in calls[0]
    assert calls[1]["nonce"] == "FRESH"
    assert len(rec.mints()) == 1

def test_an_upstream_401_is_not_a_nonce_refusal() -> None:
    """A stamped response is the upstream's answer, not KnoxCall's — it must
    not trigger a re-sign even if it somehow carries the challenge."""
    rec = Recorder(
        token=[token_response("N")],
        api=[
            httpx.Response(
                401,
                headers={
                    "x-knox-upstream-status": "401",
                    "www-authenticate": 'DPoP error="use_dpop_nonce"',
                },
                text="upstream says no",
            ),
        ],
    )
    with client_for(rec) as c:
        resp = c.call("my-route", path="/v1/things")
    assert resp.status_code == 401
    assert len(rec.proofs(path_contains="acme.test")) == 1, "no retry on an upstream answer"