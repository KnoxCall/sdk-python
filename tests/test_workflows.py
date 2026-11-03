"""Workflows resource — parity with node src/resources/workflows.ts.

Mocks return the REAL server envelope: single objects as ``{data, meta}``,
paginated lists as ``{data:[...], meta:{total,page,per_page,total_pages,...}}``.
"""

from __future__ import annotations
import json

import httpx
import pytest

from knoxcall import KnoxCall, KnoxCallAsync
from knoxcall.auth.bootstrap import AccessToken
from knoxcall.errors import ValidationError

_BOOTSTRAP = AccessToken(access_token="kc_live_x")


def _meta(**extra) -> dict:
    return {"request_id": "req_00000000-0000-0000-0000-000000000000", **extra}


def _success(data, **meta_extra) -> httpx.Response:
    return httpx.Response(200, json={"data": data, "meta": _meta(**meta_extra)})


def _page(items, *, total, page, per_page) -> httpx.Response:
    total_pages = max(1, -(-total // per_page)) if total else 0
    return httpx.Response(200, json={
        "data": items,
        "meta": _meta(total=total, page=page, per_page=per_page, total_pages=total_pages),
    })


def _async_client(handler, **extra) -> KnoxCallAsync:
    return KnoxCallAsync(
        tenant="acme",
        base_url="https://api.example.test",
        bootstrap=_BOOTSTRAP,
        http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        **extra,
    )


def _wf(**over) -> dict:
    base = {
        "id": "wf_1", "name": "nightly", "description": None, "definition": {},
        "environment": None, "enabled": True, "version": 1, "sandbox": False,
        "timeout_seconds": None, "published_at": None,
        "created_at": "2026-08-04T00:00:00Z", "updated_at": "2026-08-04T00:00:00Z",
    }
    base.update(over)
    return base


async def test_create_get_execute_cancel_hit_the_right_paths():
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.method, req.url.path))
        if req.method == "POST" and req.url.path == "/v1/workflows":
            return _success(_wf())
        if req.method == "GET" and req.url.path == "/v1/workflows/wf_1":
            return _success(_wf())
        if req.method == "POST" and req.url.path == "/v1/workflows/wf_1/execute":
            body = json.loads(req.content)
            assert body == {"input": {"since": "2026-08-01"}}
            return _success({"id": "ex_1", "workflow_id": "wf_1", "status": "queued"})
        if req.method == "POST" and req.url.path == "/v1/workflows/executions/ex_1/cancel":
            return _success({"id": "ex_1", "status": "cancelling"})
        return httpx.Response(404, json={"error": "nope"})

    async with _async_client(handler) as client:
        created = await client.workflows.create(name="nightly", definition={})
        assert created["id"] == "wf_1"
        got = await client.workflows.get("wf_1")
        assert got["name"] == "nightly"
        run = await client.workflows.execute("wf_1", {"since": "2026-08-01"})
        assert run["status"] == "queued"
        cancelled = await client.workflows.cancel_execution("ex_1")
        assert cancelled["status"] == "cancelling"

    assert ("POST", "/v1/workflows") in seen
    assert ("POST", "/v1/workflows/wf_1/execute") in seen
    assert ("POST", "/v1/workflows/executions/ex_1/cancel") in seen


async def test_list_unwraps_page_and_iterate_walks_pages():
    def handler(req: httpx.Request) -> httpx.Response:
        page = int(req.url.params.get("page", "1"))
        if page == 1:
            return _page([_wf(id="wf_1")], total=2, page=1, per_page=1)
        return _page([_wf(id="wf_2")], total=2, page=2, per_page=1)

    async with _async_client(handler) as client:
        first = await client.workflows.list(per_page=1)
        assert first["meta"]["total"] == 2
        assert first["data"][0]["id"] == "wf_1"
        seen = [w["id"] async for w in client.workflows.iterate(per_page=1)]
        assert seen == ["wf_1", "wf_2"]


def test_sync_facade_exposes_workflows():
    def handler(req: httpx.Request) -> httpx.Response:
        return _success(_wf())

    client = KnoxCall(
        tenant="acme", base_url="https://api.example.test", bootstrap=_BOOTSTRAP,
        http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        wf = client.workflows.get("wf_1")
        assert wf["id"] == "wf_1"
    finally:
        client.close()


async def test_create_surfaces_enabled_false_when_the_server_withholds_the_switch():
    """PARITY §11 Workflows — an unpublishable definition may never be live.

    CREATE keeps the caller's data and withholds the switch: the row is created
    ``enabled: false`` and the response says so. It is a normal 200, not an
    error, and it is the one place in ``/v1`` where a boolean you sent comes
    back different — so the SDK must report the SERVER's value, never echo the
    requested one back from the request body.
    """

    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "POST" and req.url.path == "/v1/workflows":
            assert json.loads(req.content)["enabled"] is True
            return _success(_wf(enabled=False))
        return httpx.Response(404, json={"error": {"type": "not_found", "message": "x"}})

    async with _async_client(handler) as client:
        created = await client.workflows.create(name="nightly", definition={}, enabled=True)
        assert created["enabled"] is False


async def test_update_raises_the_typed_422_and_does_not_retry_it():
    """The other half of the same rule: UPDATE refuses where CREATE withholds.

    ``enabled: true`` on a workflow whose STORED definition cannot publish is a
    422 ``invalid_definition``. It is a CLIENT error — retrying it unchanged
    burns the tenant's rate limit and can never succeed.
    """
    attempts = []

    def handler(req: httpx.Request) -> httpx.Response:
        attempts.append((req.method, req.url.path))
        return httpx.Response(422, json={"error": {
            "type": "invalid_definition",
            "message": 'This workflow cannot be enabled: node "n1": HTTP method is required',
            "request_id": "req_1",
        }})

    async with _async_client(handler) as client:
        with pytest.raises(ValidationError):
            await client.workflows.update("wf_1", enabled=True)

    assert attempts == [("PATCH", "/v1/workflows/wf_1")]
