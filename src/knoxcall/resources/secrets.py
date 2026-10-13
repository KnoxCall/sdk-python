"""Secrets resource — mirrors secrets.ts."""

from __future__ import annotations
from typing import Any, AsyncIterator, Literal, TYPE_CHECKING
from urllib.parse import quote

from .._envelope import unwrap
from ..types import (
    Secret,
    SecretCreateResult,
    SecretOAuthToken,
    SecretPage,
    SecretUpdateResult,
    SecretValueResult,
)

if TYPE_CHECKING:
    from ..core import APIClient

SecretType = Literal["api_key", "oauth2_token", "certificate", "basic_auth", "custom"]


class SecretsResource:
    def __init__(self, client: "APIClient") -> None:
        self._client = client

    async def list(self, *, page: int | None = None, per_page: int | None = None) -> SecretPage:
        query: dict[str, Any] = {}
        if page is not None:
            query["page"] = page
        if per_page is not None:
            query["per_page"] = per_page
        return await self._client.request(method="GET", path="/v1/secrets", query=query or None)

    async def iterate(
        self, *, page: int = 1, per_page: int | None = None
    ) -> AsyncIterator[Secret]:
        current = page
        while True:
            result = await self.list(page=current, per_page=per_page)
            data = result.get("data") or []
            for s in data:
                yield s
            meta = result.get("meta") or {}
            if not data or current >= int(meta.get("total_pages") or 0):
                return
            current += 1

    async def get(self, secret_id: str) -> Secret:
        """Fetch one secret's metadata. The value is never returned.

        The result carries ``environments`` — one
        :class:`~knoxcall.types.SecretEnvironmentVersion` per environment
        holding a value, ordered by environment name. Use
        ``environments[i]["value_version"]`` to detect a rotation performed
        outside your tooling.
        """
        return unwrap(await self._client.request(
            method="GET", path=f"/v1/secrets/{quote(secret_id, safe='')}"
        ))

    async def create(
        self,
        *,
        name: str,
        secret_type: SecretType,
        value: str,
        description: str | None = None,
        environment: str | None = None,
        idempotency_key: str | None = None,
    ) -> SecretCreateResult:
        body: dict[str, Any] = {"name": name, "secret_type": secret_type, "value": value}
        if description is not None:
            body["description"] = description
        if environment is not None:
            body["environment"] = environment
        return unwrap(await self._client.request(
            method="POST", path="/v1/secrets", body=body, idempotency_key=idempotency_key
        ))

    async def create_oauth2(
        self,
        *,
        name: str,
        provider: str,
        client_id: str,
        client_secret: str | None = None,
        mtls_certificate_id: str | None = None,
        scopes: list[str] | None = None,
        auth_url: str | None = None,
        token_url: str | None = None,
        grant_type: str | None = None,
        username: str | None = None,
        password: str | None = None,
        collection_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> SecretCreateResult:
        """Create an OAuth2-provider secret (the proxy injects the provider's
        access token into upstream requests). Requires ``provider`` + ``client_id``
        and — for most grant types — either ``client_secret`` or
        ``mtls_certificate_id``. The base :meth:`create` cannot carry these fields.
        """
        body: dict[str, Any] = {"name": name, "provider": provider, "client_id": client_id}
        for k, v in (
            ("client_secret", client_secret),
            ("mtls_certificate_id", mtls_certificate_id),
            ("scopes", scopes),
            ("auth_url", auth_url),
            ("token_url", token_url),
            ("grant_type", grant_type),
            ("username", username),
            ("password", password),
            ("collection_id", collection_id),
        ):
            if v is not None:
                body[k] = v
        return unwrap(await self._client.request(
            method="POST", path="/v1/secrets/oauth2", body=body, idempotency_key=idempotency_key
        ))

    async def create_certificate(
        self,
        *,
        name: str,
        certificate_content: str,
        private_key: str | None = None,
        passphrase: str | None = None,
        certificate_type: str | None = None,
        collection_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> SecretCreateResult:
        """Create a certificate / mTLS secret. Requires ``certificate_content``."""
        body: dict[str, Any] = {"name": name, "certificate_content": certificate_content}
        for k, v in (
            ("private_key", private_key),
            ("passphrase", passphrase),
            ("certificate_type", certificate_type),
            ("collection_id", collection_id),
        ):
            if v is not None:
                body[k] = v
        return unwrap(await self._client.request(
            method="POST", path="/v1/secrets/certificate", body=body, idempotency_key=idempotency_key
        ))

    async def update(
        self,
        secret_id: str,
        *,
        name: str | None = None,
        description: str | None = None,
        expires_at: str | None = None,
        strict_expiry_enforcement: bool | None = None,
        idempotency_key: str | None = None,
    ) -> SecretUpdateResult:
        body: dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if description is not None:
            body["description"] = description
        if expires_at is not None:
            body["expires_at"] = expires_at
        if strict_expiry_enforcement is not None:
            body["strict_expiry_enforcement"] = strict_expiry_enforcement
        return unwrap(await self._client.request(
            method="PATCH",
            path=f"/v1/secrets/{quote(secret_id, safe='')}",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def set_value(
        self,
        secret_id: str,
        *,
        value: str,
        environment: str | None = None,
        idempotency_key: str | None = None,
    ) -> SecretValueResult:
        """Rotate the secret value without changing other metadata.

        The result's ``value_version`` is the environment's version AFTER this
        write — 1 when this call stored the environment's first value,
        otherwise the previous version plus one. Compare it later against
        :meth:`get`'s ``environments[i]["value_version"]`` to detect a rotation
        performed outside your tooling.
        """
        body: dict[str, Any] = {"value": value}
        if environment is not None:
            body["environment"] = environment
        return unwrap(await self._client.request(
            method="PUT",
            path=f"/v1/secrets/{quote(secret_id, safe='')}/value",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def get_oauth_token(
        self, secret_id: str, *, environment: str | None = None
    ) -> SecretOAuthToken:
        """Get the current access token for an OAuth2 secret (auto-refreshes if expired)."""
        query: dict[str, Any] = {}
        if environment is not None:
            query["environment"] = environment
        return unwrap(await self._client.request(
            method="GET",
            path=f"/v1/secrets/{quote(secret_id, safe='')}/oauth2/token",
            query=query or None,
        ))

    async def delete(self, secret_id: str, *, idempotency_key: str | None = None) -> None:
        await self._client.request(
            method="DELETE",
            path=f"/v1/secrets/{quote(secret_id, safe='')}",
            idempotency_key=idempotency_key,
        )
