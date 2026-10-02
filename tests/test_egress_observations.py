"""Uncovered-egress observations (PARITY §21.3) — the Python mirror of
``sdk/knoxcall-node/test/egress-observations.test.ts``.

Three layers, each captured at a real boundary, never by mocking the thing
under test: the classifier, driven by the CROSS-LANGUAGE fixture
``sdk/fixtures/egress-observation.json``; the reporter against an injected
report coroutine; and the seams (``install_intercept`` over httpx sync/async
and ``requests``, the explicit transports) with a fake client that records
exactly what ``wrap.report_egress_observations`` would serialise — so the
credential header's VALUE and the query string are asserted ABSENT.
"""

from __future__ import annotations

import asyncio
import json
import time
import warnings
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import pytest

from knoxcall import (
    EgressObservationReporter,
    KnoxWrapAsyncTransport,
    KnoxWrapTransport,
    credential_header_name,
    first_segment_looks_like_credential,
    is_credential_header_name,
    observation_first_segment,
    observation_for,
)
from knoxcall._egress_observations import CREDENTIAL_HEADER_ALLOWLIST, CREDENTIAL_HEADER_SUFFIXES
from knoxcall._intercept import normalise_host
from knoxcall._intercept_patch import install_intercept
from knoxcall._warn import KnoxCallSecurityWarning
from knoxcall.core import _SDK_VERSION
from knoxcall.errors import APIConnectionError, PermissionDeniedError
from knoxcall.resources.wrap import WrapResource

FIXTURE = json.loads((Path(__file__).resolve().parents[2] / "fixtures" / "egress-observation.json").read_text("utf-8"))


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KNOXCALL_INTERCEPT", raising=False)
    monkeypatch.delenv("KNOXCALL_OBSERVE_UNCOVERED", raising=False)


# ── 1. the classifier: shared fixtures ────────────────────────────────────────

def test_fixture_is_non_trivial_and_the_lists_are_the_fixtures_lists() -> None:
    assert len(FIXTURE["header_cases"]) > 20
    assert len(FIXTURE["cases"]) > 3
    assert list(CREDENTIAL_HEADER_ALLOWLIST) == FIXTURE["credential_headers"]["allowlist"]
    assert list(CREDENTIAL_HEADER_SUFFIXES) == FIXTURE["credential_headers"]["suffixes"]


@pytest.mark.parametrize("case", FIXTURE["header_cases"], ids=lambda c: repr(c["name"]))
def test_header_name_counts(case: dict[str, Any]) -> None:
    assert is_credential_header_name(case["name"]) is case["counts"]


@pytest.mark.parametrize("case", FIXTURE["pick_cases"], ids=lambda c: ",".join(c["headers"]) or "(none)")
def test_pick_among_several(case: dict[str, Any]) -> None:
    assert credential_header_name({h: "value" for h in case["headers"]}) == case["expect"]


@pytest.mark.parametrize("case", FIXTURE["first_segment_cases"], ids=lambda c: c["url"])
def test_first_segment(case: dict[str, Any]) -> None:
    assert observation_first_segment(case["url"]) == case["expect"]


@pytest.mark.parametrize("case", FIXTURE["segment_redaction_cases"], ids=lambda c: c["segment"][:40])
def test_segment_redaction(case: dict[str, Any]) -> None:
    assert first_segment_looks_like_credential(case["segment"]) is case["redacted"]


@pytest.mark.parametrize("case", FIXTURE["host_cases"], ids=lambda c: c["url"])
def test_host_normalisation(case: dict[str, Any]) -> None:
    assert normalise_host(urlsplit(case["url"]).hostname) == case["expect"]


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=lambda c: c["name"])
def test_cases(case: dict[str, Any]) -> None:
    got = observation_for(case["url"], case["method"], case["headers"])
    if case["expect"] is None:
        assert got is None
    else:
        assert got == case["expect"]
        for value in case["headers"].values():  # names, never values
            if value.strip():
                assert value not in json.dumps(got)


# ── 2. the reporter ───────────────────────────────────────────────────────────

def obs(i: Any, method: str = "GET", seg: str = "/v1", header: str = "authorization") -> dict[str, str]:
    return {"host": f"h{i}.example", "first_segment": seg, "method": method, "header_name": header}


def runner(coro: Any) -> Any:
    return asyncio.run(coro)


class Sink:
    def __init__(self, *, fail: BaseException | None = None, accepted_minus: int = 0) -> None:
        self.calls: list[list[dict[str, Any]]] = []
        self.fail = fail
        self.accepted_minus = accepted_minus

    async def report(self, observations: list[dict[str, Any]]) -> dict[str, Any]:
        if self.fail is not None:
            raise self.fail
        self.calls.append(observations)
        return {"accepted": len(observations) - self.accepted_minus, "dropped": self.accepted_minus, "reasons": {}}


def wait_for(pred: Any, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while not pred():
        if time.monotonic() > deadline:
            raise AssertionError("condition not met in time")
        time.sleep(0.01)


def test_reporter_aggregates_by_key_with_counts_and_iso_utc_timestamps() -> None:
    t = [1_700_000_000.0]
    sink = Sink()
    r = EgressObservationReporter(sink.report, runner=runner, now=lambda: t[0], rand=lambda: 0.5)
    r.record(obs(1))
    t[0] += 1
    r.record(obs(1))
    t[0] += 1
    r.record(obs(1))
    r.record(obs(1, method="POST"))
    r.record(obs(1, seg="/v2"))
    r.record(obs(1, header="x-api-key"))
    assert r.size == 4
    r.flush()
    assert len(sink.calls) == 1
    assert sink.calls[0][0] == {
        "host": "h1.example", "first_segment": "/v1", "method": "GET", "header_name": "authorization", "count": 3,
        "first_seen": "2023-11-14T22:13:20.000Z", "last_seen": "2023-11-14T22:13:22.000Z",
    }
    assert all(o["count"] > 0 for o in sink.calls[0])
    assert r.size == 0
    r.stop()


def test_reporter_flushes_at_200_keys_in_the_background_and_chunks_at_200_per_request() -> None:
    sink = Sink()
    r = EgressObservationReporter(sink.report, runner=runner, rand=lambda: 0.5)
    for i in range(199):
        r.record(obs(i))
    assert sink.calls == []
    r.record(obs(199))
    wait_for(lambda: len(sink.calls) == 1)
    assert len(sink.calls[0]) == 200
    r.stop()

    big = Sink()
    rb = EgressObservationReporter(big.report, runner=runner, flush_at_keys=10_000)
    for i in range(450):
        rb.record(obs(i))
    rb.flush()
    assert [len(c) for c in big.calls] == [200, 200, 50]
    rb.stop()


def test_reporter_timer_flush_on_a_daemon_thread() -> None:
    sink = Sink()
    r = EgressObservationReporter(sink.report, runner=runner, flush_interval=0.05, rand=lambda: 0.5)
    r.record(obs(1))
    assert sink.calls == []
    wait_for(lambda: len(sink.calls) == 1)
    assert r._timer is None  # not re-armed until the next record
    r.record(obs(2))
    wait_for(lambda: len(sink.calls) == 2)
    r.stop()


def test_reporter_caps_at_1000_keys_with_one_warning() -> None:
    sink = Sink()
    r = EgressObservationReporter(sink.report, runner=runner, flush_at_keys=10_000)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        for i in range(1_005):
            r.record(obs(i))
        r.record(obs(3))  # an EXISTING key still counts
    assert r.size == 1_000
    assert next(o for o in r.pending() if o["host"] == "h3.example")["count"] == 2
    assert [str(w.message) for w in caught if issubclass(w.category, KnoxCallSecurityWarning) and "1000" in str(w.message)] != []
    assert sum(1 for w in caught if issubclass(w.category, KnoxCallSecurityWarning)) == 1
    r.stop()


def test_reporter_403_stops_reporting_for_good_with_one_warning() -> None:
    sink = Sink(fail=PermissionDeniedError("insufficient scope", status=403))
    r = EgressObservationReporter(sink.report, runner=runner)
    r.record(obs(1))
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        r.flush()
        r.record(obs(2))
        r.flush()
        r.stop()
    assert r.forbidden is True
    assert r.size == 0
    msgs = [str(w.message) for w in caught if issubclass(w.category, KnoxCallSecurityWarning)]
    assert len(msgs) == 1 and "routes:read" in msgs[0]


def test_reporter_other_failure_drops_the_batch_with_one_warning_and_keeps_going() -> None:
    sink = Sink(fail=APIConnectionError("ECONNREFUSED"))
    r = EgressObservationReporter(sink.report, runner=runner)
    r.record(obs(1))
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        r.flush()
        assert r.size == 0  # dropped, not held for a retry
        assert r.forbidden is False
        sink.fail = None
        r.record(obs(2))
        r.flush()
        sink.fail = APIConnectionError("again")
        r.record(obs(3))
        r.flush()
    assert [o["host"] for c in sink.calls for o in c] == ["h2.example"]
    assert sum(1 for w in caught if issubclass(w.category, KnoxCallSecurityWarning)) == 1
    r.stop()


def test_reporter_on_flush_gets_the_servers_counts_and_a_throwing_hook_never_breaks_it() -> None:
    seen: list[dict[str, int]] = []

    def hook(info: dict[str, int]) -> None:
        seen.append(info)
        raise RuntimeError("hook bug")

    sink = Sink(accepted_minus=1)
    r = EgressObservationReporter(sink.report, runner=runner, on_flush=hook)
    r.record(obs(1))
    r.record(obs(2))
    r.flush()
    assert seen == [{"accepted": 1, "dropped": 1}]
    assert r.size == 0
    r.stop()


def test_reporter_stop_flushes_once_more_then_ignores_records() -> None:
    sink = Sink()
    r = EgressObservationReporter(sink.report, runner=runner)
    r.record(obs(1))
    r.stop()
    assert len(sink.calls) == 1
    r.record(obs(2))
    assert r.size == 0
    r.stop()  # idempotent


async def test_reporter_async_facade_loop_timer_and_astop() -> None:
    sink = Sink()
    r = EgressObservationReporter(sink.report, flush_interval=0.05, rand=lambda: 0.5)
    r.record(obs(1))  # inside a running loop: call_later on it
    assert r._loop_timer is not None
    await asyncio.sleep(0.2)
    assert len(sink.calls) == 1
    r.record(obs(2))
    await r.astop()
    assert len(sink.calls) == 2
    r.record(obs(3))
    assert r.size == 0


# ── 3. the seams ──────────────────────────────────────────────────────────────

def entry(host: str, slug: str, base: str = "/", **over: Any) -> dict[str, Any]:
    return {"host": host, "base_path": base, "slug": slug, "route_id": f"id-{slug}", "requires_clients": False, "allowed_methods": None, "updated_at": None, **over}


HUBSPOT_ROOT = entry("api.hubapi.com", "hubspot")


class FakeClient:
    """Records every data-plane call and every observation report (as the exact
    list the SDK would serialise), serving the manifest from ``routes``."""

    def __init__(self, *, routes: Any = (), report_error: BaseException | None = None) -> None:
        self.sandbox = False
        self.base_url = "https://api.test"
        self.proxy_base_url = "https://acme.test"
        self.environment = None
        self._routes = routes
        self.report_error = report_error
        self.manifest_calls = 0
        self.route_calls: list[dict[str, Any]] = []
        self.ephemeral_calls: list[dict[str, Any]] = []
        self.observation_calls: list[list[dict[str, Any]]] = []
        self.wrap = self  # the default report path is client.wrap.report_egress_observations

    async def fetch_manifest(self) -> dict[str, Any]:
        self.manifest_calls += 1
        routes = list(self._routes)
        return {"version": "sha256:" + (",".join(r["slug"] for r in routes) or "empty"), "ttl_seconds": 60, "environment": "production", "sandbox": False, "routes": routes}

    async def report_egress_observations(self, observations: list[dict[str, Any]], *, sdk: str | None = None) -> dict[str, Any]:
        if self.report_error is not None:
            raise self.report_error
        self.observation_calls.append(json.loads(json.dumps(observations)))
        return {"accepted": len(observations), "dropped": 0, "reasons": {}}

    async def call(self, route: str, *, method: str = "GET", path: str = "/", body: Any = None, headers: dict[str, str] | None = None, timeout: float | None = None, **extra: Any) -> httpx.Response:
        self.route_calls.append({"route": route, "method": method, "path": path})
        return httpx.Response(200, headers={"content-type": "application/json"}, json={"ok": True})

    async def ephemeral(self, upstream_url: str, *, method: str = "GET", body: Any = None, headers: dict[str, str] | None = None, mode: str | None = None, upstream_authorization: str | None = None, upstream_auth_secret: str | None = None, upstream_auth_scheme: str | None = None, timeout: float | None = None, **extra: Any) -> httpx.Response:
        self.ephemeral_calls.append({"url": upstream_url, "method": method})
        return httpx.Response(200, headers={"content-type": "application/json"}, json={"ok": True})

    @property
    def wire(self) -> str:
        return json.dumps(self.observation_calls)


class Canned:
    """Replaces the ORIGINAL httpx/urllib3 transports so an unmatched host answers here, never on the network."""

    def __init__(self) -> None:
        self.original: list[str] = []

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        canned = self

        def sync_handle(self_: Any, request: httpx.Request) -> httpx.Response:
            canned.original.append(str(request.url))
            return httpx.Response(200, text="ORIGINAL", request=request)

        async def async_handle(self_: Any, request: httpx.Request) -> httpx.Response:
            canned.original.append(str(request.url))
            return httpx.Response(200, text="ORIGINAL", request=request)

        monkeypatch.setattr(httpx.HTTPTransport, "handle_request", sync_handle)
        monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", async_handle)
        import io

        from urllib3.connectionpool import HTTPConnectionPool
        from urllib3.response import HTTPResponse

        def urlopen(self_: Any, method: str, url: str, body: Any = None, headers: Any = None, *a: Any, **kw: Any) -> Any:
            canned.original.append(f"{self_.scheme}://{self_.host}{url}")
            return HTTPResponse(body=io.BytesIO(b"ORIGINAL"), headers={"content-type": "text/plain"}, status=200, reason="OK", preload_content=False, request_method=method, request_url=url)

        monkeypatch.setattr(HTTPConnectionPool, "urlopen", urlopen)


def install(client: FakeClient, *, hosts: list[str] | None = None, stacks: list[str] | None = None, **opts: Any) -> Any:
    return install_intercept(
        client=client, runner=runner, stacks=stacks or ["httpx", "urllib3"], hosts=hosts or [], host_options={},
        require_context=False, transport_opts={"routes": "auto", "manifest_fetch": client.fetch_manifest, **opts},
    )


def test_intercept_records_a_direct_unlisted_credentialed_call_and_flushes_names_never_values(monkeypatch: pytest.MonkeyPatch) -> None:
    Canned().install(monkeypatch)
    client = FakeClient(routes=[HUBSPOT_ROOT])
    flushes: list[dict[str, int]] = []
    handle = install(client, hosts=["api.resend.com"], on_observation_flush=flushes.append)
    try:
        handle.ready()
        with httpx.Client() as http:  # an untouched httpx client on the default transport
            r = http.post("https://a.klaviyo.com/api/profiles/?x=1&token=leak-in-query", headers={"Authorization": "Klaviyo-API-Key pk_live_should_never_appear"}, content=b'{"email":"never-appears@example.com"}')
            assert r.text == "ORIGINAL"  # the application's request is untouched
            http.post("https://a.klaviyo.com/api/profiles/?x=2", headers={"authorization": "Klaviyo-API-Key pk_live_2"})
        import requests  # an untouched requests session on urllib3

        assert requests.get("https://b.example/v1/things?y=1", headers={"X-Vendor-Api-Key": "vk_never"}).text == "ORIGINAL"
        assert client.observation_calls == []  # nothing leaves the process on the request's own path
    finally:
        handle.uninstall()  # the final flush, synchronously through the runner
    assert len(client.observation_calls) == 1
    batch = client.observation_calls[0]
    assert [{k: o[k] for k in ("host", "first_segment", "method", "header_name", "count")} for o in batch] == [
        {"host": "a.klaviyo.com", "first_segment": "/api", "method": "POST", "header_name": "authorization", "count": 2},
        {"host": "b.example", "first_segment": "/v1", "method": "GET", "header_name": "x-vendor-api-key", "count": 1},
    ]
    assert batch[0]["first_seen"].endswith("Z") and batch[0]["last_seen"] >= batch[0]["first_seen"]
    for leak in ("pk_live", "x=1", "x=2", "leak-in-query", "never-appears", "profiles", "vk_never", "y=1", "things"):
        assert leak not in client.wire
    assert flushes == [{"accepted": 2, "dropped": 0}]


def test_intercept_records_nothing_for_uncredentialed_own_host_route_around_rerouted_or_kill_switched_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    Canned().install(monkeypatch)
    client = FakeClient(routes=[HUBSPOT_ROOT])
    handle = install(client, hosts=["api.resend.com", "api.stripe.com"], stacks=["httpx"])
    try:
        handle.ready()
        with httpx.Client() as http:
            http.get("https://unlisted.example/x", headers={"accept": "*/*", "x-request-id": "1"})  # no credential
            http.get("https://api.test/v1/routes", headers={"authorization": "Bearer kc_live_x"})  # own_host
            http.get("https://acme.knoxcall.com/x", headers={"authorization": "Bearer kc_live_x"})  # platform host
            http.post("https://api.stripe.com/v1/tokens", headers={"authorization": "Bearer sk_live_x"}, content=b"card")  # route_around
            http.get("https://api.hubapi.com/crm/v3/objects", headers={"authorization": "Bearer t"})  # route
            http.post("https://api.resend.com/emails", headers={"authorization": "Bearer re"}, content=b"{}")  # ephemeral
            monkeypatch.setenv("KNOXCALL_INTERCEPT", "off")
            http.get("https://unlisted.example/x", headers={"authorization": "Bearer u"})  # kill_switch
            monkeypatch.delenv("KNOXCALL_INTERCEPT")
        assert len(client.route_calls) == 1 and len(client.ephemeral_calls) == 1
    finally:
        handle.uninstall()
    assert client.observation_calls == []


async def test_intercept_async_httpx_records_and_the_flush_is_a_task_on_the_callers_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    Canned().install(monkeypatch)
    client = FakeClient(routes=[HUBSPOT_ROOT])
    handle = install_intercept(
        client=client, runner=None, stacks=["httpx"], hosts=[], host_options={}, require_context=False,
        transport_opts={"routes": "auto", "manifest_fetch": client.fetch_manifest},
    )
    try:
        await handle.aready()
        async with httpx.AsyncClient() as http:
            assert (await http.get("https://a.klaviyo.com/api/x?q=1", headers={"x-api-key": "k-never"})).text == "ORIGINAL"
            await http.get("https://api.hubapi.com/anything", headers={"authorization": "Bearer t"})  # route, not observed
        observer = handle._async.observer
        assert observer is not None and observer.size == 1
    finally:
        handle.uninstall()  # schedules the final flush on this loop
    await asyncio.sleep(0.05)
    assert [o["host"] for o in client.observation_calls[0]] == ["a.klaviyo.com"]
    assert "k-never" not in client.wire and "q=1" not in client.wire


def test_intercept_flushes_immediately_at_200_keys_in_the_background(monkeypatch: pytest.MonkeyPatch) -> None:
    Canned().install(monkeypatch)
    client = FakeClient()
    handle = install(client, stacks=["httpx"])
    try:
        handle.ready()
        with httpx.Client() as http:
            for i in range(200):
                http.get(f"https://h{i}.example/v1/x", headers={"authorization": "Bearer x"})
        wait_for(lambda: len(client.observation_calls) == 1)
        assert len(client.observation_calls[0]) == 200
    finally:
        handle.uninstall()


def test_intercept_opt_outs_option_env_and_kill_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    Canned().install(monkeypatch)

    def run(env: tuple[str, str] | None = None, **opts: Any) -> tuple[bool, int]:
        if env:
            monkeypatch.setenv(*env)
        client = FakeClient()
        handle = install(client, stacks=["httpx"], **opts)
        try:
            handle.ready()
            with httpx.Client() as http:
                assert http.get("https://h.example/v1/x", headers={"authorization": "Bearer x"}).text == "ORIGINAL"
            has_observer = handle._sync.observer is not None
        finally:
            handle.uninstall()
            if env:
                monkeypatch.delenv(env[0])
        return has_observer, len(client.observation_calls)

    assert run(observe_uncovered=False) == (False, 0)
    assert run(env=("KNOXCALL_OBSERVE_UNCOVERED", "off")) == (False, 0)
    assert run(env=("KNOXCALL_OBSERVE_UNCOVERED", "FALSE")) == (False, 0)
    assert run(env=("KNOXCALL_OBSERVE_UNCOVERED", "0")) == (False, 0)
    assert run(env=("KNOXCALL_INTERCEPT", "off")) == (True, 0)  # everything is direct; nothing is worth reporting
    assert run() == (True, 1)  # the control: on by default


def test_intercept_403_stops_reporting_for_the_handle_with_one_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    canned = Canned()
    canned.install(monkeypatch)
    client = FakeClient(report_error=PermissionDeniedError("insufficient scope", status=403))
    handle = install(client, stacks=["httpx"])
    try:
        handle.ready()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with httpx.Client() as http:
                for i in range(200):
                    http.get(f"https://h{i}.example/v1/x", headers={"authorization": "Bearer x"})
                observer = handle._sync.observer
                assert observer is not None
                wait_for(lambda: observer.forbidden)
                for i in range(200):
                    assert http.get(f"https://k{i}.example/v1/x", headers={"authorization": "Bearer x"}).text == "ORIGINAL"
            assert observer.size == 0
    finally:
        handle.uninstall()
    assert client.observation_calls == []
    msgs = [str(w.message) for w in caught if issubclass(w.category, KnoxCallSecurityWarning)]
    assert len(msgs) == 1 and "routes:read" in msgs[0]
    assert len(canned.original) == 400  # the application never noticed


def test_intercept_network_error_is_dropped_with_one_warning_and_never_surfaces(monkeypatch: pytest.MonkeyPatch) -> None:
    Canned().install(monkeypatch)
    client = FakeClient(report_error=APIConnectionError("ECONNREFUSED"))
    handle = install(client, stacks=["httpx"])
    try:
        handle.ready()
        observer = handle._sync.observer
        assert observer is not None
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with httpx.Client() as http:
                for i in range(200):
                    assert http.get(f"https://h{i}.example/v1/x", headers={"authorization": "Bearer x"}).text == "ORIGINAL"
                wait_for(lambda: observer._warned_failed)
                client.report_error = None
                http.get("https://later.example/v1/x", headers={"authorization": "Bearer x"})
    finally:
        handle.uninstall()
    assert [o["host"] for c in client.observation_calls for o in c] == ["later.example"]  # the failed batch was not retried
    assert sum(1 for w in caught if issubclass(w.category, KnoxCallSecurityWarning)) == 1


def test_explicit_transport_builds_the_reporter_only_with_routes_auto_and_never_observes_listed_hosts() -> None:
    client = FakeClient()
    off = KnoxWrapTransport(client, runner, direct_transport=httpx.MockTransport(lambda r: httpx.Response(200)), manifest_fetch=client.fetch_manifest)
    assert off.observer is None
    on = KnoxWrapTransport(client, runner, direct_transport=httpx.MockTransport(lambda r: httpx.Response(200)), manifest_fetch=client.fetch_manifest, routes="auto")
    assert on.observer is not None
    with httpx.Client(transport=on) as http:
        http.get("https://anything.example/v1/x", headers={"authorization": "Bearer x"})  # every host is listed → ephemeral
    assert len(client.ephemeral_calls) == 1
    assert on.observer.size == 0
    on.stop()
    assert client.observation_calls == []
    async_on = KnoxWrapAsyncTransport(client, manifest_fetch=client.fetch_manifest, routes="auto", observe_uncovered=False)
    assert async_on.observer is None


async def test_report_egress_observations_posts_sdk_and_observations_through_request() -> None:
    seen: list[dict[str, Any]] = []

    class Client:
        async def request(self, **kw: Any) -> dict[str, Any]:
            seen.append(kw)
            return {"data": {"accepted": 1, "dropped": 1, "reasons": {"unknown_host": 1}}, "meta": {"request_id": "o"}}

    observations = [{"host": "h.example", "first_segment": "/v1", "method": "GET", "header_name": "authorization", "count": 3, "first_seen": "2026-09-26T00:00:00.000Z", "last_seen": "2026-09-26T00:01:00.000Z"}]
    res = await WrapResource(Client()).report_egress_observations(observations)  # type: ignore[arg-type]
    assert res == {"accepted": 1, "dropped": 1, "reasons": {"unknown_host": 1}}
    assert seen[0]["method"] == "POST" and seen[0]["path"] == "/v1/wrap/egress-observations"
    # The value itself is pinned by tests/coverage/sdk-version-agreement.test.ts.
    assert seen[0]["body"] == {"sdk": f"python/{_SDK_VERSION}", "observations": observations}
    await WrapResource(Client()).report_egress_observations(observations, sdk="custom/9.9.9")  # type: ignore[arg-type]
    assert seen[1]["body"]["sdk"] == "custom/9.9.9"


async def test_intercept_aiohttp_arm_records_a_direct_unlisted_credentialed_call(monkeypatch: pytest.MonkeyPatch) -> None:
    """The opt-in aiohttp arm: a direct decision replays the ORIGINAL ``_request``
    (canned here) and is observed on the way — session default headers count."""
    import aiohttp

    original: list[str] = []

    class Marker:
        status = 200

        async def __aenter__(self) -> "Marker":
            return self

        async def __aexit__(self, *_: Any) -> None:
            return None

    async def canned(self_: Any, method: str, str_or_url: Any, **kw: Any) -> Any:
        original.append(str(str_or_url))
        return Marker()

    monkeypatch.setattr(aiohttp.ClientSession, "_request", canned)
    client = FakeClient(routes=[HUBSPOT_ROOT])
    handle = install_intercept(
        client=client, runner=None, stacks=["aiohttp"], hosts=[], host_options={}, require_context=False,
        transport_opts={"routes": "auto", "manifest_fetch": client.fetch_manifest},
    )
    try:
        await handle.aready()
        async with aiohttp.ClientSession(headers={"X-Session-Token": "session-never"}) as session:
            async with session.get("https://a.klaviyo.com/api/x?q=1", headers={"Authorization": "Bearer call-never"}) as r:
                assert r.status == 200
            async with session.post("https://b.example/v2/y") as r:  # the session default header is the credential
                assert r.status == 200
        async with aiohttp.ClientSession() as plain:
            async with plain.get("https://plain.example/z") as r:  # no credential anywhere
                assert r.status == 200
        observer = handle._async.observer
        assert observer is not None and observer.size == 2
        assert len(original) == 3
    finally:
        handle.uninstall()
    await asyncio.sleep(0.05)
    assert [(o["host"], o["first_segment"], o["method"], o["header_name"]) for o in client.observation_calls[0]] == [
        ("a.klaviyo.com", "/api", "GET", "authorization"),
        ("b.example", "/v2", "POST", "x-session-token"),
    ]
    for leak in ("call-never", "session-never", "q=1"):
        assert leak not in client.wire
