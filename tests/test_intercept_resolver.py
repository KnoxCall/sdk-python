"""The route-aware decision table, driven by the CROSS-LANGUAGE fixtures in
``sdk/fixtures/intercept-resolver.json`` (route-aware-interception-plan.md §2.2).
Node is the reference; this is the Python mirror running the same cases."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from knoxcall import resolve_intercept
from knoxcall._intercept import entries_for_host, is_platform_host, normalise_host, rebase_path
from knoxcall.wrap_transport import DEFAULT_ROUTE_AROUND

FIXTURE = json.loads((Path(__file__).resolve().parents[2] / "fixtures" / "intercept-resolver.json").read_text(encoding="utf-8"))
CASES = FIXTURE["cases"]


def test_fixture_is_non_trivial() -> None:
    assert len(CASES) > 15
    assert len(FIXTURE["manifest"]["routes"]) > 3


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_shared_fixture_case(case: dict) -> None:
    manifest = FIXTURE["manifest"] if "manifest" not in case else case["manifest"]
    hosts = "all" if case["hosts"] == "all" else frozenset(normalise_host(h) for h in case["hosts"])
    d = resolve_intercept(
        url=case["url"],
        method=case["method"],
        hosts=hosts,
        manifest=manifest,
        own_hosts=frozenset(normalise_host(h) for h in FIXTURE["own_hosts"]),
        route_around=DEFAULT_ROUTE_AROUND,
        kill_switch=case["kill_switch"],
        require_context=case["require_context"],
        in_context=case["in_context"],
    )
    exp = case["expect"]
    assert d.mode == exp["mode"], case["url"]
    assert d.reason == exp["reason"], case["url"]
    if "slug" in exp:
        assert d.slug == exp["slug"]
    if "path" in exp:
        assert d.path == exp["path"]
    if exp["mode"] != "route":
        assert d.slug is None and d.path is None


def test_rebase_path_is_segment_aware() -> None:
    assert rebase_path("/crm/v3/objects", "/crm/v3") == "/objects"
    assert rebase_path("/crm/v3", "/crm/v3") == "/"
    assert rebase_path("/crm/v30/x", "/crm/v3") is None
    assert rebase_path("/anything", "/") == "/anything"
    assert rebase_path("", "/") == "/"
    assert rebase_path("x", "/") == "/x"


def test_normalise_host() -> None:
    assert normalise_host(" API.Example. ") == "api.example"
    assert normalise_host("[::1]") == "::1"
    assert normalise_host(None) == ""


def test_is_platform_host() -> None:
    assert is_platform_host("knoxcall.com")
    assert is_platform_host("acme.knoxcall.com")
    assert is_platform_host("x.wrap.knoxcall.com")
    assert not is_platform_host("knoxcall.com.evil.example")
    assert not is_platform_host("notknoxcall.com")


def test_entries_for_host_orders_longest_base_then_slug() -> None:
    m = {
        "routes": [
            {"host": "h.example", "base_path": "/", "slug": "z"},
            {"host": "h.example", "base_path": "/a/b", "slug": "deep"},
            {"host": "H.EXAMPLE.", "base_path": "/", "slug": "a"},
            {"host": "other.example", "base_path": "/", "slug": "o"},
        ]
    }
    assert [e["slug"] for e in entries_for_host(m, "h.example")] == ["deep", "a", "z"]
    assert entries_for_host(None, "h.example") == []


def test_port_in_request_url_never_affects_host_match() -> None:
    m = {"routes": [{"host": "h.example", "base_path": "/", "slug": "h"}]}
    d = resolve_intercept(
        url="https://h.example:8443/x?y=1", method="GET", hosts=frozenset(), manifest=m, own_hosts=frozenset(),
        route_around=[], kill_switch=False, require_context=False, in_context=False,
    )
    assert (d.mode, d.slug, d.path) == ("route", "h", "/x?y=1")
