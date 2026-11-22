"""The route-mode refusal predicate, driven by the CROSS-LANGUAGE fixtures in
``sdk/fixtures/route-refusal.json`` (PARITY §21.1, "Refusal-driven refresh").
Node is the reference; this file consumes the same cases unchanged."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from knoxcall.wrap_transport import _is_route_refusal

FIXTURE = json.loads((Path(__file__).resolve().parents[2] / "fixtures" / "route-refusal.json").read_text(encoding="utf-8"))
CASES: list[dict[str, Any]] = FIXTURE["cases"]


def test_fixture_has_cases_in_both_directions() -> None:
    assert {c["expect"]["refusal"] for c in CASES} == {True, False}
    assert len(CASES) >= 10


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_route_refusal_predicate(case: dict[str, Any]) -> None:
    resp = httpx.Response(case["status"], headers=case["headers"], content=case["body"].encode("utf-8"))
    assert _is_route_refusal(resp) is case["expect"]["refusal"]
    # The caller's body is untouched by the decision.
    assert resp.text == case["body"]
