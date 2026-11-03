"""Dynamic DB Credentials resource — mirrors dyn-db-credentials.ts."""

from __future__ import annotations
from typing import Any, TYPE_CHECKING
from urllib.parse import quote

from .._envelope import unwrap
from ..types import (
    DbConnection,
    DbConnectionCreateResult,
    DbLeaseList,
    DbRole,
    DbRoleCreateResult,
    DbUpdateResult,
    LeaseRevokeResult,
    MintedDbCredential,
    NameDeleteResult,
    RotateSshKeyResult,
)

if TYPE_CHECKING:
    from ..core import APIClient


class DynamicDbResource:
    def __init__(self, client: "APIClient") -> None:
        self._client = client

    # ── Connection management ─────────────────────────────────────────────────

    async def list(self) -> list[DbConnection]:
        """List DB connections (bare array — not paginated)."""
        return unwrap(await self._client.request(method="GET", path="/v1/dyn-db-credentials"))

    async def get(self, name: str) -> DbConnection:
        return unwrap(await self._client.request(
            method="GET", path=f"/v1/dyn-db-credentials/{quote(name, safe='')}"
        ))

    async def create(
        self,
        *,
        name: str,
        engine: str,
        host: str | None = None,
        port: int | None = None,
        database_name: str | None = None,
        admin_username: str | None = None,
        admin_password: str | None = None,
        execution_mode: str = "direct",
        agent_id: str | None = None,
        ssh_host: str | None = None,
        ssh_port: int | None = None,
        ssh_username: str | None = None,
        ssh_private_key: str | None = None,
        ssh_passphrase: str | None = None,
        ssh_host_fingerprint: str | None = None,
        iam_region: str | None = None,
        iam_db_user: str | None = None,
        default_ttl_seconds: int | None = None,
        max_ttl_seconds: int | None = None,
        connect_options: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> DbConnectionCreateResult:
        """Register a database connection.

        ``engine``: ``"postgres"`` | ``"mysql"`` | ``"mssql"`` | ``"mongodb"``
        ``execution_mode``: ``"direct"`` | ``"agent"`` | ``"ssh_tunnel"`` | ``"iam"``
        """
        body: dict[str, Any] = {"name": name, "engine": engine, "execution_mode": execution_mode}
        for k, v in [
            ("host", host), ("port", port), ("database_name", database_name),
            ("admin_username", admin_username), ("admin_password", admin_password),
            ("agent_id", agent_id), ("ssh_host", ssh_host), ("ssh_port", ssh_port),
            ("ssh_username", ssh_username), ("ssh_private_key", ssh_private_key),
            ("ssh_passphrase", ssh_passphrase), ("ssh_host_fingerprint", ssh_host_fingerprint),
            ("iam_region", iam_region), ("iam_db_user", iam_db_user),
            ("default_ttl_seconds", default_ttl_seconds), ("max_ttl_seconds", max_ttl_seconds),
            ("connect_options", connect_options),
        ]:
            if v is not None:
                body[k] = v
        return unwrap(await self._client.request(
            method="POST", path="/v1/dyn-db-credentials", body=body, idempotency_key=idempotency_key
        ))

    async def update(
        self,
        name: str,
        *,
        host: str | None = None,
        port: int | None = None,
        database_name: str | None = None,
        admin_username: str | None = None,
        admin_password: str | None = None,
        default_ttl_seconds: int | None = None,
        max_ttl_seconds: int | None = None,
        connect_options: dict[str, Any] | None = None,
        agent_id: str | None = None,
        enabled: bool | None = None,
        idempotency_key: str | None = None,
    ) -> DbUpdateResult:
        body: dict[str, Any] = {}
        for k, v in [
            ("host", host), ("port", port), ("database_name", database_name),
            ("admin_username", admin_username), ("admin_password", admin_password),
            ("default_ttl_seconds", default_ttl_seconds), ("max_ttl_seconds", max_ttl_seconds),
            ("connect_options", connect_options), ("agent_id", agent_id), ("enabled", enabled),
        ]:
            if v is not None:
                body[k] = v
        return unwrap(await self._client.request(
            method="PATCH",
            path=f"/v1/dyn-db-credentials/{quote(name, safe='')}",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def delete(self, name: str, *, idempotency_key: str | None = None) -> NameDeleteResult:
        return unwrap(await self._client.request(
            method="DELETE",
            path=f"/v1/dyn-db-credentials/{quote(name, safe='')}",
            idempotency_key=idempotency_key,
        ))

    async def rotate_ssh_key(
        self,
        name: str,
        *,
        ssh_private_key: str,
        ssh_passphrase: str | None = None,
        ssh_host_fingerprint: str | None = None,
        idempotency_key: str | None = None,
    ) -> RotateSshKeyResult:
        body: dict[str, Any] = {"ssh_private_key": ssh_private_key}
        if ssh_passphrase is not None:
            body["ssh_passphrase"] = ssh_passphrase
        if ssh_host_fingerprint is not None:
            body["ssh_host_fingerprint"] = ssh_host_fingerprint
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/dyn-db-credentials/{quote(name, safe='')}/rotate-ssh-key",
            body=body,
            idempotency_key=idempotency_key,
        ))

    # ── Roles ─────────────────────────────────────────────────────────────────

    async def list_roles(self, connection_name: str) -> list[DbRole]:
        """List roles on a connection (bare array — not paginated)."""
        return unwrap(await self._client.request(
            method="GET",
            path=f"/v1/dyn-db-credentials/{quote(connection_name, safe='')}/roles",
        ))

    async def create_role(
        self,
        connection_name: str,
        *,
        name: str,
        template: str | None = None,
        creation_sql: str | None = None,
        revocation_sql: str | None = None,
        default_ttl_seconds: int | None = None,
        max_ttl_seconds: int | None = None,
        idempotency_key: str | None = None,
    ) -> DbRoleCreateResult:
        body: dict[str, Any] = {"name": name}
        for k, v in [
            ("template", template), ("creation_sql", creation_sql),
            ("revocation_sql", revocation_sql), ("default_ttl_seconds", default_ttl_seconds),
            ("max_ttl_seconds", max_ttl_seconds),
        ]:
            if v is not None:
                body[k] = v
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/dyn-db-credentials/{quote(connection_name, safe='')}/roles",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def update_role(
        self,
        connection_name: str,
        role: str,
        *,
        creation_sql: str | None = None,
        revocation_sql: str | None = None,
        default_ttl_seconds: int | None = None,
        max_ttl_seconds: int | None = None,
        idempotency_key: str | None = None,
    ) -> DbUpdateResult:
        body: dict[str, Any] = {}
        for k, v in [
            ("creation_sql", creation_sql), ("revocation_sql", revocation_sql),
            ("default_ttl_seconds", default_ttl_seconds), ("max_ttl_seconds", max_ttl_seconds),
        ]:
            if v is not None:
                body[k] = v
        return unwrap(await self._client.request(
            method="PATCH",
            path=f"/v1/dyn-db-credentials/{quote(connection_name, safe='')}/roles/{quote(role, safe='')}",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def delete_role(
        self,
        connection_name: str,
        role: str,
        *,
        idempotency_key: str | None = None,
    ) -> NameDeleteResult:
        return unwrap(await self._client.request(
            method="DELETE",
            path=f"/v1/dyn-db-credentials/{quote(connection_name, safe='')}/roles/{quote(role, safe='')}",
            idempotency_key=idempotency_key,
        ))

    # ── Credential minting + lease management ─────────────────────────────────

    async def mint(
        self,
        connection_name: str,
        role: str,
        *,
        ttl_seconds: int | None = None,
        idempotency_key: str | None = None,
    ) -> MintedDbCredential:
        """Mint a short-lived credential. Returns ``username``, ``password``, ``expires_at``, ``lease_id``."""
        body: dict[str, Any] = {}
        if ttl_seconds is not None:
            body["ttl_seconds"] = ttl_seconds
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/dyn-db-credentials/{quote(connection_name, safe='')}/creds/{quote(role, safe='')}",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def list_leases(
        self,
        *,
        limit: int | None = None,
        offset: int | None = None,
        connection: str | None = None,
    ) -> DbLeaseList:
        """List LIVE leases — those whose ``status`` is ``active``,
        ``renewing`` or ``errored``, i.e. every lease whose database user may
        still exist on your server. Expired and revoked leases have had their
        user dropped and are neither listed nor counted in ``total``.
        ``connection`` is an exact match on the connection’s name, scoped to the
        caller’s Live/Test space.

        ``errored`` is included deliberately: renewal was abandoned after five
        consecutive failures, so nothing is refreshing or expiring that lease.
        It is also the set counted by the ``409 … has N active credential
        lease(s)`` a connection or role delete returns, so anything blocking a
        delete is listed here and can be revoked.

        Unlike the page/per_page envelope everywhere else, this endpoint’s
        pagination genuinely is limit/offset INSIDE ``data``."""
        query: dict[str, Any] = {}
        if limit is not None:
            query["limit"] = limit
        if offset is not None:
            query["offset"] = offset
        if connection is not None:
            query["connection"] = connection
        return unwrap(await self._client.request(
            method="GET",
            path="/v1/dyn-db-credentials/leases",
            query=query or None,
        ))

    async def revoke_lease(
        self, lease_id: int | str, *, idempotency_key: str | None = None
    ) -> LeaseRevokeResult:
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/dyn-db-credentials/leases/{quote(str(lease_id), safe='')}/revoke",
            body={},
            idempotency_key=idempotency_key,
        ))
