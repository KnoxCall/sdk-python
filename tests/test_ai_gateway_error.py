"""AIGW-163 — the AI DATA plane's typed refusal.

The SDK deliberately does not make the data-plane call for you: you point an
existing Anthropic or OpenAI client at the agent's ``agent_url``. So what the
SDK owes you is the ability to TYPE what that client hands back — a
``{error, error_description, code}`` body, which is NOT the Management API's
``{"error": {"type", "message", "request_id"}}`` and must not be mistaken for it.
"""

from __future__ import annotations

from knoxcall import (
    AIGatewayError,
    KnoxCallError,
    ai_gateway_error_from,
    is_ai_gateway_error_body,
)

REFUSAL = {
    "error": "budget_exceeded",
    "error_description": "Daily budget exceeded: $50.0031 >= $50",
    "code": "budget_exceeded",
    "utilization_pct": 100.006,
}


def test_returns_typed_class_with_code_description_and_retry_after() -> None:
    err = ai_gateway_error_from(
        429,
        REFUSAL,
        {"Retry-After": "3600", "X-Request-Id": "0d5b2a9e-1f3c-4a7d-8e2b-6c9a1f4d7e35"},
    )
    assert isinstance(err, AIGatewayError)
    assert err.code == "budget_exceeded"
    assert err.status == 429
    assert err.error_description == "Daily budget exceeded: $50.0031 >= $50"
    assert err.retry_after == 3600
    assert err.request_id == "0d5b2a9e-1f3c-4a7d-8e2b-6c9a1f4d7e35"
    assert str(err) == "Daily budget exceeded: $50.0031 >= $50"


def test_is_a_knoxcall_error_so_existing_excepts_still_catch_it() -> None:
    # PARITY §1: every new typed error is re-parented into the hierarchy.
    err = ai_gateway_error_from(
        403,
        {
            "error": "model_not_allowed",
            "error_description": "not on the allowlist",
            "code": "model_not_allowed",
        },
    )
    assert isinstance(err, KnoxCallError)


def test_retry_after_is_none_when_absent_or_not_whole_seconds() -> None:
    # Absent is meaningful: the gateway sends no header rather than a guess, so
    # None must not become 0 (an immediate retry against a spent cap).
    assert ai_gateway_error_from(429, REFUSAL).retry_after is None
    assert ai_gateway_error_from(429, REFUSAL, {"Retry-After": ""}).retry_after is None
    # An HTTP-date Retry-After is legal but is not delta-seconds.
    assert (
        ai_gateway_error_from(
            429, REFUSAL, {"Retry-After": "Wed, 09 Sep 2026 00:00:00 GMT"}
        ).retry_after
        is None
    )


def test_returns_none_for_the_management_envelope() -> None:
    # The nested shape every other /v1 resource answers. Typing it as an AI
    # refusal would put a control-plane not_found in the same except as a
    # data-plane budget refusal.
    assert (
        ai_gateway_error_from(404, {"error": {"type": "not_found", "message": "Gateway not found."}})
        is None
    )


def test_returns_none_for_an_rfc_6749_oauth_error() -> None:
    assert (
        ai_gateway_error_from(
            400, {"error": "invalid_grant", "error_description": "bad subject token"}
        )
        is None
    )


def test_returns_none_when_error_and_code_disagree() -> None:
    # The pre-AIGW-163 auth shape. Quietly accepting it would make `code` mean
    # two things again.
    assert (
        ai_gateway_error_from(
            401, {"error": "Unauthorized", "code": "expired", "reason": "Token has expired"}
        )
        is None
    )


def test_returns_none_for_a_non_dict_body() -> None:
    assert ai_gateway_error_from(502, "<html>502 Bad Gateway</html>") is None
    assert ai_gateway_error_from(502, None) is None


def test_keeps_the_raw_body() -> None:
    assert ai_gateway_error_from(429, REFUSAL).body["utilization_pct"] == 100.006


def test_discriminator_alone() -> None:
    assert is_ai_gateway_error_body(REFUSAL) is True
    assert is_ai_gateway_error_body({"error": "x", "code": "x"}) is False  # no description
    assert is_ai_gateway_error_body({"error": "x", "error_description": "y"}) is False  # no code
