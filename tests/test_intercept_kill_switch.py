"""The KNOXCALL_INTERCEPT off-grammar, driven by the CROSS-LANGUAGE fixture in
``sdk/fixtures/intercept-kill-switch.json`` (PARITY §21.1).

Five SDKs hand-write this predicate and already agree character for character.
A sixth spelling accepted here would be a kill switch that works in four SDKs
and silently does nothing in the fifth -- the worst shape a kill switch can
have, because the operator believes interception is off."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from knoxcall._intercept import intercept_kill_switch

FIXTURE = json.loads(
    (Path(__file__).resolve().parents[2] / "fixtures" / "intercept-kill-switch.json").read_text(encoding="utf-8")
)


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=[c["name"] for c in FIXTURE["cases"]])
def test_kill_switch_grammar(monkeypatch: pytest.MonkeyPatch, case: dict) -> None:
    if case["value"] is None:
        monkeypatch.delenv("KNOXCALL_INTERCEPT", raising=False)
    else:
        monkeypatch.setenv("KNOXCALL_INTERCEPT", case["value"])
    assert intercept_kill_switch() is case["expect"]


def test_the_fixture_is_not_vacuous() -> None:
    outcomes = {c["expect"] for c in FIXTURE["cases"]}
    assert outcomes == {True, False}, "the table must contain both verdicts"
