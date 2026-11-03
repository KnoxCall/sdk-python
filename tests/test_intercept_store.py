"""The SDK-side manifest store (route-aware-interception-plan.md §2.5), Python
idiom: LAZY refresh at the TTL, single-flight, stale-keep with backoff,
permission refusals as "no manifest" with one warning, rate-limited hints."""

from __future__ import annotations

import asyncio
import json
import warnings
from pathlib import Path
from typing import Any

import pytest

from knoxcall import InterceptManifestStore
from knoxcall.errors import APIConnectionError, PermissionDeniedError


def entry(host: str, slug: str, base: str = "/") -> dict[str, Any]:
    return {"host": host, "base_path": base, "slug": slug, "route_id": f"id-{slug}", "requires_clients": False, "allowed_methods": None, "updated_at": None}


def manifest(routes: list[dict[str, Any]], version: str | None = None) -> dict[str, Any]:
    return {"version": version or "v:" + ",".join(r["slug"] for r in routes), "ttl_seconds": 60, "environment": "production", "sandbox": False, "routes": routes}


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


async def test_first_ensure_fetches_once_and_reports_every_entry_as_added() -> None:
    calls = 0
    refreshes: list[dict[str, Any]] = []

    async def fetch() -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return manifest([entry("a.example", "a")])

    store = InterceptManifestStore(fetch, on_refresh=refreshes.append, now=Clock())
    assert store.stale()
    await store.aensure()
    await store.aensure()  # fresh: no second call
    assert calls == 1
    assert [r["slug"] for r in store.manifest["routes"]] == ["a"]
    assert store.version == "v:a"
    assert refreshes[0]["reason"] == "ttl"
    assert refreshes[0]["added"] == [entry("a.example", "a")]
    assert refreshes[0]["removed"] == []


async def test_stale_after_ttl_and_only_the_diff_is_reported() -> None:
    clock = Clock()
    routes = [entry("a.example", "a")]
    refreshes: list[dict[str, Any]] = []

    async def fetch() -> dict[str, Any]:
        return manifest(routes)

    store = InterceptManifestStore(fetch, on_refresh=refreshes.append, now=clock)
    await store.aensure()
    clock.t += 59
    assert not store.stale()
    routes = [entry("b.example", "b")]
    clock.t += 2
    assert store.stale()
    await store.aensure()
    assert [r["slug"] for r in store.manifest["routes"]] == ["b"]
    assert refreshes[-1]["added"] == [entry("b.example", "b")]
    assert refreshes[-1]["removed"] == [entry("a.example", "a")]


async def test_unchanged_version_fires_no_refresh_hook() -> None:
    clock = Clock()
    refreshes: list[dict[str, Any]] = []

    async def fetch() -> dict[str, Any]:
        return manifest([entry("a.example", "a")])

    store = InterceptManifestStore(fetch, on_refresh=refreshes.append, now=clock)
    await store.aensure()
    clock.t += 61
    await store.aensure()
    assert len(refreshes) == 1


async def test_transport_fault_keeps_last_good_manifest_and_backs_off_from_second_failure() -> None:
    clock = Clock()
    fail = False
    calls = 0
    errors: list[BaseException] = []

    async def fetch() -> dict[str, Any]:
        nonlocal calls
        calls += 1
        if fail:
            raise APIConnectionError("network error: ECONNRESET")
        return manifest([entry("a.example", "a")])

    store = InterceptManifestStore(fetch, on_error=errors.append, now=clock)
    await store.aensure()
    fail = True
    clock.t += 61
    await store.aensure()  # 2nd call, fails
    assert calls == 2
    assert len(store.manifest["routes"]) == 1  # stale-but-valid
    assert isinstance(store.last_error, APIConnectionError)
    assert len(errors) == 1
    # one transient failure keeps the TTL…
    clock.t += 61
    await store.aensure()
    assert calls == 3
    # …the second consecutive failure doubles it: nothing at +60, a call at +120
    clock.t += 61
    await store.aensure()
    assert calls == 3
    clock.t += 61
    await store.aensure()
    assert calls == 4


async def test_permission_refusal_is_no_manifest_warns_once_and_rechecks_slowly() -> None:
    clock = Clock()
    denied = True
    calls = 0

    async def fetch() -> dict[str, Any]:
        nonlocal calls
        calls += 1
        if denied:
            raise PermissionDeniedError("insufficient scope", status=403)
        return manifest([entry("a.example", "a")])

    store = InterceptManifestStore(fetch, now=clock)
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        await store.aensure()
        assert store.manifest is None
        assert store.permission_denied
        clock.t += 5 * 60
        await store.aensure()  # not yet re-checked
        assert calls == 1
        denied = False
        clock.t += 301
        await store.aensure()
        assert calls == 2
        assert not store.permission_denied
        assert len(store.manifest["routes"]) == 1
    routes_read = [x for x in w if "routes:read" in str(x.message)]
    assert len(routes_read) == 1


async def test_refresh_is_single_flight_and_rate_limited_force_bypasses_the_gap() -> None:
    clock = Clock()
    calls = 0
    gate = asyncio.Event()

    async def fetch() -> dict[str, Any]:
        nonlocal calls
        calls += 1
        await gate.wait()
        return manifest([entry("a.example", "a")])

    store = InterceptManifestStore(fetch, now=clock, min_refresh_gap=5.0)
    t1 = asyncio.create_task(store.arefresh("a", force=True))
    await asyncio.sleep(0)
    t2 = asyncio.create_task(store.arefresh("b", force=True))
    await asyncio.sleep(0)
    gate.set()
    await asyncio.gather(t1, t2)
    assert calls == 1  # shared in-flight
    await store.arefresh("hint")  # inside the gap → no call
    assert calls == 1
    clock.t += 6
    await store.arefresh("hint")
    assert calls == 2
    await store.arefresh("manual", force=True)
    assert calls == 3


async def test_hint_makes_the_next_request_refresh_rate_limited() -> None:
    clock = Clock()
    calls = 0

    async def fetch() -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return manifest([])

    store = InterceptManifestStore(fetch, now=clock)
    await store.aensure()
    store.hint()  # inside the 5 s gap of the refresh just done: ignored
    assert not store.stale()
    clock.t += 6
    store.hint()
    assert store.stale()
    await store.aensure()
    assert calls == 2


async def test_stop_drops_the_manifest_and_refuses_to_refresh() -> None:
    async def fetch() -> dict[str, Any]:
        return manifest([entry("a.example", "a")])

    store = InterceptManifestStore(fetch, now=Clock())
    await store.aensure()
    store.stop()
    assert store.manifest is None
    assert not store.stale()
    assert await store.arefresh("x", force=True) is None


async def test_first_failure_never_raises_out_of_ensure() -> None:
    async def fetch() -> dict[str, Any]:
        raise RuntimeError("boom")

    store = InterceptManifestStore(fetch, now=Clock())
    assert await store.aensure() is None
    assert isinstance(store.last_error, RuntimeError)


# ── the conditional poll (PARITY §21.1 "Conditional poll") ────────────────────
# Driven by the CROSS-LANGUAGE fixture sdk/fixtures/intercept-store-conditional.json;
# node (sdk/knoxcall-node/test/intercept-manifest-store.test.ts) is the reference.

CONDITIONAL = json.loads(
    (Path(__file__).resolve().parents[2] / "fixtures" / "intercept-store-conditional.json").read_text(encoding="utf-8")
)


def test_conditional_fixture_has_the_steps_this_suite_walks() -> None:
    steps = CONDITIONAL["steps"]
    assert len(steps) >= 4
    assert steps[0]["expect"]["fetch_if_none_match"] is None
    assert any(s["respond"]["status"] == 304 for s in steps)
    assert any(s.get("forced") for s in steps)


async def test_conditional_poll_walks_every_fixture_step() -> None:
    """The held version rides on every poll after the first (scheduled or
    forced); a 304 keeps the manifest, restarts the TTL clock and fires no
    hook; a 200 with a new version replaces it and fires the diff."""
    clock = Clock()
    sent: list[str | None] = []
    respond: dict[str, Any] = {}
    refreshes: list[dict[str, Any]] = []

    async def fetch(*, if_none_match: str | None = None) -> dict[str, Any] | None:
        sent.append(if_none_match)
        if respond["status"] == 304:
            return None
        return CONDITIONAL["manifests"][respond["manifest"]]

    store = InterceptManifestStore(fetch, on_refresh=refreshes.append, now=clock)
    for i, step in enumerate(CONDITIONAL["steps"]):
        respond = step["respond"]
        refreshes.clear()
        if i == 0:
            await store.aensure()
        elif step.get("forced"):
            await store.arefresh("route_refused", force=True)
        else:
            clock.t += 61  # one TTL after the previous answer
            assert store.stale(), step["name"]
            await store.aensure()
        assert len(sent) == i + 1, step["name"]
        assert sent[i] == step["expect"]["fetch_if_none_match"], step["name"]
        assert store.version == step["expect"]["version"], step["name"]
        assert store.manifest is not None and store.manifest["version"] == step["expect"]["version"], step["name"]
        assert store.last_error is None, step["name"]
        assert not store.stale(), step["name"]  # every answer, 304 included, restarts the clock
        if step["expect"]["refresh_fired"]:
            assert len(refreshes) == 1, step["name"]
            assert refreshes[0]["version"] == step["expect"]["version"], step["name"]
            assert [e["slug"] for e in refreshes[0]["added"]] == step["expect"]["added"], step["name"]
            assert [e["slug"] for e in refreshes[0]["removed"]] == step["expect"]["removed"], step["name"]
        else:
            assert refreshes == [], step["name"]


async def test_a_304_clears_the_backoff_a_run_of_faults_built_up() -> None:
    clock = Clock()
    mode = "ok"

    async def fetch(*, if_none_match: str | None = None) -> dict[str, Any] | None:
        if mode == "fault":
            raise APIConnectionError("network error: ECONNRESET")
        if mode == "not_modified":
            return None
        return manifest([entry("a.example", "a")])

    store = InterceptManifestStore(fetch, now=clock)
    await store.aensure()
    mode = "fault"
    clock.t += 61
    await store.aensure()  # fault #1 → next at TTL
    clock.t += 61
    await store.aensure()  # fault #2 → next at 2×TTL
    clock.t += 61
    assert not store.stale()
    clock.t += 60
    mode = "not_modified"
    await store.aensure()  # a 304 after the 2×TTL wait
    assert [r["slug"] for r in store.manifest["routes"]] == ["a"]
    assert store.last_error is None
    clock.t += 61  # back to one TTL, not 4×
    assert store.stale()


async def test_after_a_permission_refusal_the_recovery_poll_is_unconditional_again() -> None:
    clock = Clock()
    denied = False
    sent: list[str | None] = []

    async def fetch(*, if_none_match: str | None = None) -> dict[str, Any] | None:
        sent.append(if_none_match)
        if denied:
            raise PermissionDeniedError("insufficient scope", status=403)
        return manifest([entry("a.example", "a")])

    store = InterceptManifestStore(fetch, now=clock)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        await store.aensure()
        denied = True
        await store.arefresh("manual", force=True)
        assert sent == [None, "v:a"]
        assert store.version is None
        denied = False
        await store.arefresh("manual", force=True)
    assert sent[2] is None
    assert store.version == "v:a"


async def test_a_zero_argument_fetch_keeps_polling_unconditionally_and_kwargs_is_conditional() -> None:
    """The seam tolerates a fetch that cannot take the version (a test or user
    seam from before this feature) and detects ``**kwargs`` as accepting it."""
    clock = Clock()
    zero_calls = 0

    async def zero() -> dict[str, Any]:
        nonlocal zero_calls
        zero_calls += 1
        return manifest([entry("a.example", "a")])

    store = InterceptManifestStore(zero, now=clock)
    await store.aensure()
    clock.t += 61
    await store.aensure()
    assert zero_calls == 2 and store.version == "v:a"

    seen: list[dict[str, Any]] = []

    async def kw(**kwargs: Any) -> dict[str, Any] | None:
        seen.append(kwargs)
        return None if kwargs.get("if_none_match") == "v:a" else manifest([entry("a.example", "a")])

    store2 = InterceptManifestStore(kw, now=clock)
    await store2.aensure()
    clock.t += 61
    await store2.aensure()
    assert seen == [{}, {"if_none_match": "v:a"}]
    assert store2.version == "v:a"
