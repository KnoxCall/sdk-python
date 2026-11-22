"""Workflows resource — mirrors workflows.ts.

Wraps the ``/v1/workflows`` management surface: workflow CRUD (paginated list +
iterate), execute (queue a run), and executions (paginated list + iterate, get,
cancel). Mutating methods carry an auto-generated ULID idempotency key like
every other resource.
"""

from __future__ import annotations
from typing import Any, AsyncIterator, TYPE_CHECKING
from urllib.parse import quote

from .._envelope import unwrap
from ..types import (
    Workflow,
    WorkflowCancelResult,
    WorkflowDeleteResult,
    WorkflowExecution,
    WorkflowExecutionPage,
    WorkflowPage,
    WorkflowRun,
)

if TYPE_CHECKING:
    from ..core import APIClient


class WorkflowsResource:
    def __init__(self, client: "APIClient") -> None:
        self._client = client

    # ── Workflow CRUD ─────────────────────────────────────────────────────────

    async def list(
        self, *, page: int | None = None, per_page: int | None = None
    ) -> WorkflowPage:
        """List workflows (paginated — server default 20/page, cap 100)."""
        query: dict[str, Any] = {}
        if page is not None:
            query["page"] = page
        if per_page is not None:
            query["per_page"] = per_page
        return await self._client.request(
            method="GET", path="/v1/workflows", query=query or None
        )

    async def iterate(
        self, *, page: int = 1, per_page: int | None = None
    ) -> AsyncIterator[Workflow]:
        """Yield every workflow, walking pages until ``meta.total_pages``."""
        current = page
        while True:
            result = await self.list(page=current, per_page=per_page)
            data = result.get("data") or []
            for w in data:
                yield w
            meta = result.get("meta") or {}
            if not data or current >= int(meta.get("total_pages") or 0):
                return
            current += 1

    async def get(self, workflow_id: str) -> Workflow:
        """Fetch one workflow by id."""
        return unwrap(await self._client.request(
            method="GET", path=f"/v1/workflows/{quote(workflow_id, safe='')}"
        ))

    async def create(
        self,
        *,
        name: str,
        definition: Any,
        description: str | None = None,
        trigger_config: Any = None,
        environment: str | None = None,
        enabled: bool | None = None,
        idempotency_key: str | None = None,
    ) -> Workflow:
        """Create a workflow."""
        body: dict[str, Any] = {"name": name, "definition": definition}
        if description is not None:
            body["description"] = description
        if trigger_config is not None:
            body["trigger_config"] = trigger_config
        if environment is not None:
            body["environment"] = environment
        if enabled is not None:
            body["enabled"] = enabled
        return unwrap(await self._client.request(
            method="POST", path="/v1/workflows", body=body, idempotency_key=idempotency_key
        ))

    async def update(
        self,
        workflow_id: str,
        *,
        name: str | None = None,
        definition: Any = None,
        description: str | None = None,
        trigger_config: Any = None,
        environment: str | None = None,
        enabled: bool | None = None,
        idempotency_key: str | None = None,
    ) -> Workflow:
        """Update a workflow."""
        body: dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if definition is not None:
            body["definition"] = definition
        if description is not None:
            body["description"] = description
        if trigger_config is not None:
            body["trigger_config"] = trigger_config
        if environment is not None:
            body["environment"] = environment
        if enabled is not None:
            body["enabled"] = enabled
        return unwrap(await self._client.request(
            method="PATCH",
            path=f"/v1/workflows/{quote(workflow_id, safe='')}",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def delete(
        self, workflow_id: str, *, idempotency_key: str | None = None
    ) -> WorkflowDeleteResult:
        """Delete a workflow. Returns ``{id, deleted: True}``."""
        return unwrap(await self._client.request(
            method="DELETE",
            path=f"/v1/workflows/{quote(workflow_id, safe='')}",
            idempotency_key=idempotency_key,
        ))

    async def execute(
        self,
        workflow_id: str,
        input: Any = None,
        *,
        idempotency_key: str | None = None,
    ) -> WorkflowRun:
        """Execute a workflow. Queues a run and returns the execution ack.

        Idempotent: an auto-generated key (stable across retries) or an
        explicit ``idempotency_key`` makes a replay return the same execution.
        """
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/workflows/{quote(workflow_id, safe='')}/execute",
            body={"input": input},
            idempotency_key=idempotency_key,
        ))

    # ── Executions ────────────────────────────────────────────────────────────

    async def list_executions(
        self,
        workflow_id: str,
        *,
        page: int | None = None,
        per_page: int | None = None,
    ) -> WorkflowExecutionPage:
        """List a workflow's executions (paginated) — polling-trigger source."""
        query: dict[str, Any] = {}
        if page is not None:
            query["page"] = page
        if per_page is not None:
            query["per_page"] = per_page
        return await self._client.request(
            method="GET",
            path=f"/v1/workflows/{quote(workflow_id, safe='')}/executions",
            query=query or None,
        )

    async def iterate_executions(
        self,
        workflow_id: str,
        *,
        page: int = 1,
        per_page: int | None = None,
    ) -> AsyncIterator[WorkflowExecution]:
        """Yield a workflow's executions, walking pages until ``meta.total_pages``."""
        current = page
        while True:
            result = await self.list_executions(workflow_id, page=current, per_page=per_page)
            data = result.get("data") or []
            for e in data:
                yield e
            meta = result.get("meta") or {}
            if not data or current >= int(meta.get("total_pages") or 0):
                return
            current += 1

    async def get_execution(self, execution_id: str) -> WorkflowExecution:
        """Fetch one execution (with composed step details)."""
        return unwrap(await self._client.request(
            method="GET",
            path=f"/v1/workflows/executions/{quote(execution_id, safe='')}",
        ))

    async def cancel_execution(
        self, execution_id: str, *, idempotency_key: str | None = None
    ) -> WorkflowCancelResult:
        """Cancel a running execution."""
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/workflows/executions/{quote(execution_id, safe='')}/cancel",
            idempotency_key=idempotency_key,
        ))
