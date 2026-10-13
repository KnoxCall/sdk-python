"""WorkloadCredentialProvider — WIF Phase 4.3. Twin of the Node SDK's
``test/workload-provider.test.ts``; ``sdk/PARITY.md`` is the shared contract.

The contract worth testing is not "it caches a token". It is the two rules that
come from KnoxCall assertions being SINGLE-USE:

  1. every exchange reads a FRESH assertion from the source, and an assertion
     whose bytes were already spent is refused locally with an error that names
     the real cause — rather than forwarded to be refused as a replay, which
     reads as "your CI identity was rejected";
  2. N concurrent callers cause ONE exchange, because each exchange spends an
     assertion and a herd would burn N of them to have N-1 refused.

Plus the two-tier boundary: advisory failures are survivable, mandatory ones are
not, and the 90 seconds between them is the point of having two tiers.

These drive the REAL ``exchange_token`` through ``httpx.MockTransport``, so the
wire payload is asserted too — a provider that cached correctly while sending
the wrong ``subject_token_type`` would pass a mock-the-function test.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from knoxcall.redacted import Redacted
from knoxcall.auth.workload_provider import (
    ADVISORY_REFRESH_SECONDS,
    MANDATORY_REFRESH_SECONDS,
    StaleAssertionError,
    WorkloadCredentialProvider,
)

LIFETIME = 900.0  # expires_in, seconds — what the gateway mints today


class Exchange:
    """A fake ``POST /v1/oauth/token`` that records every request it is sent."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.fail_next: Exception | None = None
        self._n = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.fail_next is not None:
            err, self.fail_next = self.fail_next, None
            raise err
        self._n += 1
        return httpx.Response(
            200,
            json={
                "access_token": f"kp_live_tok{self._n}",
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "token_type": "Bearer",
                "expires_in": LIFETIME,
            },
        )

    @property
    def count(self) -> int:
        return len(self.requests)

    def body(self, i: int) -> dict:
        import json

        return json.loads(self.requests[i].content)


class Clock:
    def __init__(self, start: float = 1_000_000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t


def fresh_source():
    """A distinct assertion per call, as a real platform token endpoint produces."""
    state = {"n": 0}

    def produce() -> str:
        state["n"] += 1
        return f"assertion-{state['n']}"

    return produce


def make(exchange: Exchange, clock: Clock, **opts) -> WorkloadCredentialProvider:
    opts.setdefault("assertion", fresh_source())
    return WorkloadCredentialProvider(
        tenant="acme",
        http=httpx.AsyncClient(transport=httpx.MockTransport(exchange.handler)),
        now=clock,
        **opts,
    )


# ── the single-use rule ──────────────────────────────────────────────────────


async def test_reads_a_fresh_assertion_for_every_exchange():
    ex, clock = Exchange(), Clock()
    p = make(ex, clock, assertion=fresh_source())

    await p.get_access_token()
    clock.t += LIFETIME - MANDATORY_REFRESH_SECONDS / 2  # past the mandatory line
    await p.get_access_token()

    assert ex.count == 2
    assert ex.body(0)["subject_token"] == "assertion-1"
    assert ex.body(1)["subject_token"] == "assertion-2"


async def test_refuses_a_repeated_assertion_without_sending_it():
    ex, clock = Exchange(), Clock()
    p = make(ex, clock, assertion=lambda: "captured-once-at-startup")

    await p.get_access_token()
    assert ex.count == 1

    clock.t += LIFETIME  # force a mandatory refresh
    with pytest.raises(StaleAssertionError):
        await p.get_access_token()

    # The doomed request is never made: the whole point is to fail at the real
    # cause instead of surfacing the server's replay refusal.
    assert ex.count == 1, "a spent assertion was sent to the server"


async def test_the_refusal_explains_what_to_do():
    ex, clock = Exchange(), Clock()
    p = make(ex, clock, assertion=lambda: "same-bytes")
    await p.get_access_token()
    clock.t += LIFETIME

    with pytest.raises(StaleAssertionError, match="single-use"):
        await p.get_access_token()
    with pytest.raises(StaleAssertionError, match="NEWLY minted"):
        await p.get_access_token()


async def test_an_empty_assertion_is_refused_before_any_exchange():
    ex, clock = Exchange(), Clock()
    p = make(ex, clock, assertion=lambda: "")
    with pytest.raises(StaleAssertionError):
        await p.get_access_token()
    assert ex.count == 0


async def test_a_failed_exchange_does_not_burn_the_assertion():
    # The server claims the assertion before minting, so only a SUCCESS makes
    # those bytes unusable. Burning the fingerprint on a network error would
    # strand a caller whose assertion is still perfectly good.
    ex, clock = Exchange(), Clock()
    p = make(ex, clock, assertion=lambda: "retryable-assertion")

    ex.fail_next = httpx.ConnectError("connection reset")
    with pytest.raises(httpx.ConnectError):
        await p.get_access_token()

    assert isinstance(await p.get_access_token(), Redacted)
    assert ex.count == 2
    assert ex.body(1)["subject_token"] == "retryable-assertion"


async def test_an_async_assertion_source_is_supported():
    # A real source is usually a metadata fetch, which is async.
    ex, clock = Exchange(), Clock()

    async def produce() -> str:
        await asyncio.sleep(0)
        return "minted-asynchronously"

    p = make(ex, clock, assertion=produce)
    await p.get_access_token()
    assert ex.body(0)["subject_token"] == "minted-asynchronously"


# ── the two-tier schedule ────────────────────────────────────────────────────


async def test_serves_the_cached_token_while_comfortably_alive():
    ex, clock = Exchange(), Clock()
    p = make(ex, clock)
    first = await p.get_access_token()
    clock.t += LIFETIME - ADVISORY_REFRESH_SECONDS - 10  # still above the advisory line

    assert (await p.get_access_token()).expose() == first.expose()
    assert ex.count == 1


async def test_refreshes_opportunistically_inside_the_advisory_window():
    ex, clock = Exchange(), Clock()
    p = make(ex, clock)
    await p.get_access_token()
    clock.t += LIFETIME - ADVISORY_REFRESH_SECONDS + 10

    await p.get_access_token()
    assert ex.count == 2


async def test_an_advisory_window_failure_is_survivable(recwarn):
    ex, clock = Exchange(), Clock()
    p = make(ex, clock)
    first = await p.get_access_token()
    clock.t += LIFETIME - ADVISORY_REFRESH_SECONDS + 10

    ex.fail_next = httpx.ConnectError("token endpoint 503")
    served = await p.get_access_token()

    assert served.expose() == first.expose(), (
        "a survivable blip took down a caller with valid credentials"
    )
    assert any("advisory token refresh failed" in str(w.message) for w in recwarn)


async def test_a_mandatory_window_failure_raises():
    ex, clock = Exchange(), Clock()
    p = make(ex, clock)
    await p.get_access_token()
    clock.t += LIFETIME - MANDATORY_REFRESH_SECONDS + 10

    ex.fail_next = httpx.ConnectError("token endpoint 503")
    with pytest.raises(httpx.ConnectError):
        await p.get_access_token()


async def test_never_hands_out_a_token_below_the_mandatory_margin():
    ex, clock = Exchange(), Clock()
    p = make(ex, clock)
    await p.get_access_token()
    start = clock.t
    for elapsed in (880.0, 895.0, 899.0, 901.0):
        clock.t = start + elapsed
        token = await p.get_access_token()
        assert token.expose()
    # Each of those crossed a refresh line, so the cache was renewed rather than
    # a near-dead token handed over.
    assert ex.count > 1


# ── concurrency ──────────────────────────────────────────────────────────────


async def test_n_simultaneous_callers_spend_one_assertion():
    ex, clock = Exchange(), Clock()
    source = fresh_source()
    calls = {"n": 0}

    def counted() -> str:
        calls["n"] += 1
        return source()

    p = make(ex, clock, assertion=counted)
    tokens = await asyncio.gather(*(p.get_access_token() for _ in range(8)))

    assert ex.count == 1, "a thundering herd burned one assertion per caller"
    assert calls["n"] == 1
    assert len({t.expose() for t in tokens}) == 1, "callers got different tokens from one exchange"


# ── what reaches the exchange ────────────────────────────────────────────────


async def test_passes_resource_and_audience_through_and_the_test_data_space():
    ex, clock = Exchange(), Clock()
    p = make(
        ex,
        clock,
        resource="https://mcp.example/servers/s1",
        audience="knoxcall:gateway",
        sandbox=True,
    )
    await p.get_access_token()

    body = ex.body(0)
    assert body["resource"] == "https://mcp.example/servers/s1"
    assert body["audience"] == "knoxcall:gateway"
    assert body["subject_token_type"] == "urn:ietf:params:oauth:token-type:id_token"
    # sandbox must reach the HOST, not just the payload.
    assert ex.requests[0].url.host == "sandbox-acme.knoxcall.com"


async def test_resource_is_omitted_when_not_asked_for():
    # Sending resource="" would be refused invalid_target; sending nothing mints
    # an unconfined agent token. The provider must not turn one into the other.
    ex, clock = Exchange(), Clock()
    p = make(ex, clock)
    await p.get_access_token()
    assert "resource" not in ex.body(0)


async def test_live_and_test_do_not_share_a_cache_entry():
    ex, clock = Exchange(), Clock()
    live = make(ex, clock)
    test = make(ex, clock, sandbox=True)
    assert live._key != test._key
    store = live._store
    await live.get_access_token()
    # One shared store, two data spaces: the default key is what keeps them apart.
    test._store = store
    await test.get_access_token()
    assert ex.count == 2


async def test_the_token_is_redacted():
    ex, clock = Exchange(), Clock()
    p = make(ex, clock)
    token = await p.get_access_token()
    assert "kp_live" not in str(token)
    assert "kp_live" not in repr(token)
    assert "kp_live" not in f"{token}"
    assert token.expose().startswith("kp_live")
