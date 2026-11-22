"""construct_event / construct_webhook_event — verify-and-parse matrix.

Mirrors the server's hmac-formats: legacy, stripe, github, slack, aws-sns,
custom. All HMAC-SHA256, constant-time compare, typed error on ANY failure.
"""

from __future__ import annotations
import base64
import datetime
import hashlib
import hmac as _hmac
import inspect
import json
import time

import pytest

from knoxcall import (
    KnoxCall,
    KnoxCallAsync,
    KnoxCallError,
    WebhookSignatureVerificationError,
    construct_webhook_event,
)
from knoxcall.resources.webhooks import WebhooksResource

SECRET = "whsec_test_secret"


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def _event_body(event: str = "request.success", **overrides) -> bytes:
    envelope = {
        "event": event,
        "timestamp": _now_iso(),
        "webhook_id": "9c5e8f22-0000-4000-8000-000000000001",
        "webhook_name": "order-events",
        "data": {
            "route_id": "r_1",
            "route_name": "stripe",
            "environment": "production",
            "request": {"method": "POST", "path": "/v1/charges", "ip": "10.0.0.1"},
            "response": {"status": 200, "latency_ms": 42},
        },
    }
    envelope.update(overrides)
    return json.dumps(envelope).encode()


def _hex(body: bytes, secret: str = SECRET) -> str:
    return _hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


# ── legacy (default) ──────────────────────────────────────────────────────────


def test_legacy_valid_event_returns_typed_fields():
    body = _event_body()
    headers = {"X-Webhook-Signature": f"sha256={_hex(body)}"}
    event = construct_webhook_event(body, headers, SECRET)
    assert event["event"] == "request.success"
    assert event["webhook_name"] == "order-events"
    assert event["data"]["route_id"] == "r_1"
    assert event["data"]["response"]["status"] == 200


def test_legacy_accepts_str_body_and_case_insensitive_headers():
    body = _event_body()
    headers = {"X-WEBHOOK-SIGNATURE": f"sha256={_hex(body)}"}
    event = construct_webhook_event(body.decode(), headers, SECRET)
    assert event["event"] == "request.success"


def test_wrong_secret_raises_typed_error_without_echoing_material():
    body = _event_body()
    sig = _hex(body, "the-wrong-secret")
    with pytest.raises(WebhookSignatureVerificationError) as exc:
        construct_webhook_event(body, {"X-Webhook-Signature": f"sha256={sig}"}, SECRET)
    assert isinstance(exc.value, KnoxCallError)  # part of the SDK hierarchy
    assert sig not in str(exc.value)
    assert SECRET not in str(exc.value)


def test_missing_header_raises():
    with pytest.raises(WebhookSignatureVerificationError, match="missing"):
        construct_webhook_event(_event_body(), {}, SECRET)


def test_legacy_stale_envelope_timestamp_rejected_and_none_disables():
    stale = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)
    ).isoformat()
    body = _event_body(timestamp=stale)
    headers = {"X-Webhook-Signature": f"sha256={_hex(body)}"}
    with pytest.raises(WebhookSignatureVerificationError, match="tolerance"):
        construct_webhook_event(body, headers, SECRET)
    # Explicitly disabling tolerance skips the envelope-timestamp check.
    event = construct_webhook_event(body, headers, SECRET, tolerance_seconds=None)
    assert event["event"] == "request.success"


def test_body_not_json_raises_even_with_valid_signature():
    body = b"definitely not json"
    headers = {"X-Webhook-Signature": f"sha256={_hex(body)}"}
    with pytest.raises(WebhookSignatureVerificationError, match="JSON"):
        construct_webhook_event(body, headers, SECRET)


def test_unknown_event_type_still_parses():
    body = _event_body(event="something.brand_new")
    headers = {"X-Webhook-Signature": f"sha256={_hex(body)}"}
    event = construct_webhook_event(body, headers, SECRET)
    assert event["event"] == "something.brand_new"


def test_audit_event_shape():
    body = json.dumps({
        "event": "audit.event",
        "timestamp": _now_iso(),
        "data": {
            "id": "a_1", "action": "secret.created", "resource_type": "secret",
            "resource_id": "s_1", "details": {}, "ip_address": None,
        },
    }).encode()
    headers = {"X-Webhook-Signature": f"sha256={_hex(body)}"}
    event = construct_webhook_event(body, headers, SECRET)
    assert event["event"] == "audit.event"
    assert "webhook_id" not in event
    assert event["data"]["action"] == "secret.created"


# ── stripe ────────────────────────────────────────────────────────────────────


def _stripe_header(body: bytes, ts: int, *, secret: str = SECRET, extra_v1: list[str] | None = None) -> str:
    sig = _hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    parts = [f"t={ts}"] + [f"v1={v}" for v in (extra_v1 or [])] + [f"v1={sig}"]
    return ",".join(parts)


def test_stripe_round_trip():
    body = _event_body()
    ts = int(time.time())
    headers = {"Stripe-Signature": _stripe_header(body, ts)}
    event = construct_webhook_event(body, headers, SECRET, format="stripe")
    assert event["event"] == "request.success"


def test_stripe_multiple_v1_any_match_passes():
    body = _event_body()
    ts = int(time.time())
    headers = {"Stripe-Signature": _stripe_header(body, ts, extra_v1=["deadbeef" * 8])}
    event = construct_webhook_event(body, headers, SECRET, format="stripe")
    assert event["event"] == "request.success"


def test_stripe_stale_timestamp_rejected():
    body = _event_body()
    ts = int(time.time()) - 4000
    headers = {"Stripe-Signature": _stripe_header(body, ts)}
    with pytest.raises(WebhookSignatureVerificationError, match="tolerance"):
        construct_webhook_event(body, headers, SECRET, format="stripe")
    # Disabled tolerance lets a stale-but-authentic delivery through.
    event = construct_webhook_event(body, headers, SECRET, format="stripe", tolerance_seconds=None)
    assert event["event"] == "request.success"


def test_stripe_bad_signature_rejected():
    body = _event_body()
    ts = int(time.time())
    headers = {"Stripe-Signature": _stripe_header(body, ts, secret="wrong")}
    with pytest.raises(WebhookSignatureVerificationError):
        construct_webhook_event(body, headers, SECRET, format="stripe")


def test_stripe_malformed_header_rejected():
    with pytest.raises(WebhookSignatureVerificationError, match="malformed"):
        construct_webhook_event(_event_body(), {"Stripe-Signature": "nonsense"}, SECRET, format="stripe")


# ── slack ─────────────────────────────────────────────────────────────────────


def test_slack_round_trip_and_stale_ts():
    body = _event_body()
    ts = int(time.time())
    sig = _hmac.new(SECRET.encode(), f"v0:{ts}:".encode() + body, hashlib.sha256).hexdigest()
    headers = {"X-Slack-Signature": f"v0={sig}", "X-Slack-Request-Timestamp": str(ts)}
    event = construct_webhook_event(body, headers, SECRET, format="slack")
    assert event["event"] == "request.success"

    old_ts = ts - 4000
    old_sig = _hmac.new(SECRET.encode(), f"v0:{old_ts}:".encode() + body, hashlib.sha256).hexdigest()
    stale_headers = {"X-Slack-Signature": f"v0={old_sig}", "X-Slack-Request-Timestamp": str(old_ts)}
    with pytest.raises(WebhookSignatureVerificationError, match="tolerance"):
        construct_webhook_event(body, stale_headers, SECRET, format="slack")


def test_slack_missing_timestamp_header_raises():
    body = _event_body()
    headers = {"X-Slack-Signature": "v0=" + "0" * 64}
    with pytest.raises(WebhookSignatureVerificationError, match="x-slack-request-timestamp"):
        construct_webhook_event(body, headers, SECRET, format="slack")


# ── github / aws-sns / custom ─────────────────────────────────────────────────


def test_github_format():
    body = _event_body()
    headers = {"X-Hub-Signature-256": f"sha256={_hex(body)}"}
    event = construct_webhook_event(body, headers, SECRET, format="github")
    assert event["event"] == "request.success"


def test_aws_sns_base64_format():
    body = _event_body()
    sig = base64.b64encode(_hmac.new(SECRET.encode(), body, hashlib.sha256).digest()).decode()
    headers = {"x-amz-sns-signature": sig}
    event = construct_webhook_event(body, headers, SECRET, format="aws-sns")
    assert event["event"] == "request.success"


def test_custom_header_name():
    body = _event_body()
    headers = {"X-Acme-Signature": f"sha256={_hex(body)}"}
    event = construct_webhook_event(
        body, headers, SECRET, format="custom", header_name="X-Acme-Signature"
    )
    assert event["event"] == "request.success"


def test_custom_without_header_name_raises():
    with pytest.raises(WebhookSignatureVerificationError, match="header_name"):
        construct_webhook_event(_event_body(), {}, SECRET, format="custom")


def test_unknown_format_raises():
    with pytest.raises(WebhookSignatureVerificationError, match="unknown"):
        construct_webhook_event(_event_body(), {}, SECRET, format="md5")


# ── implementation + surface parity ───────────────────────────────────────────


def test_constant_time_compare_used():
    src = inspect.getsource(construct_webhook_event)
    assert "compare_digest" in src
    # No direct equality on the recomputed signature anywhere.
    assert "expected ==" not in src and "== expected" not in src


def test_helper_exposed_on_resource_client_and_sync_facade():
    body = _event_body()
    headers = {"X-Webhook-Signature": f"sha256={_hex(body)}"}
    # Static on the webhooks resource (usable without an instance) …
    assert WebhooksResource.construct_event(body, headers, SECRET)["event"] == "request.success"
    # … on the async client class …
    assert KnoxCallAsync.construct_event(body, headers, SECRET)["event"] == "request.success"
    # … and on the sync facade without touching the network.
    import knoxcall.client as _client_mod
    assert _client_mod._KnoxCallSync.construct_event(body, headers, SECRET)["event"] == "request.success"
    assert _client_mod._SyncWebhooks.construct_event(body, headers, SECRET)["event"] == "request.success"
    assert callable(KnoxCall)  # factory import exercised
