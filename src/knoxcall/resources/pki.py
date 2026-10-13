"""PKI resource — mirrors pki.ts (customer-facing CA, cert issuance, CRL)."""

from __future__ import annotations
from typing import Any, TYPE_CHECKING
from urllib.parse import quote

from .._envelope import unwrap
from ..types import (
    CARole,
    CARoot,
    CreateRootResult,
    IssuedCertificate,
    RevokeCertResult,
    RotateIntermediateResult,
)

if TYPE_CHECKING:
    from ..core import APIClient


class PkiResource:
    def __init__(self, client: "APIClient") -> None:
        self._client = client

    # ── CA roots ──────────────────────────────────────────────────────────────

    async def list_roots(self) -> list[CARoot]:
        """List CA roots (bare array — not paginated)."""
        return unwrap(await self._client.request(method="GET", path="/v1/pki/roots"))

    async def create_root(
        self,
        *,
        name: str,
        subject: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> CreateRootResult:
        """Create a CA root. ``subject`` must include ``common_name`` at minimum."""
        return unwrap(await self._client.request(
            method="POST",
            path="/v1/pki/roots",
            body={"name": name, "subject": subject},
            idempotency_key=idempotency_key,
        ))

    async def get_root_cert(self, name: str) -> str:
        """Return the CA root certificate as a PEM string (raw text — no JSON wrapper)."""
        return await self._client.request(
            method="GET", path=f"/v1/pki/roots/{quote(name, safe='')}/cert"
        )

    async def rotate_intermediate(
        self, name: str, *, idempotency_key: str | None = None
    ) -> RotateIntermediateResult:
        """Rotate the intermediate certificate under a root CA."""
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/pki/roots/{quote(name, safe='')}/rotate-intermediate",
            body={},
            idempotency_key=idempotency_key,
        ))

    async def get_crl(self, name: str) -> str:
        """Return the Certificate Revocation List (raw text — no JSON wrapper)."""
        return await self._client.request(
            method="GET", path=f"/v1/pki/roots/{quote(name, safe='')}/crl"
        )

    # ── Roles ─────────────────────────────────────────────────────────────────

    async def list_roles(self, root_name: str) -> list[CARole]:
        """List roles under a root (bare array — not paginated)."""
        return unwrap(await self._client.request(
            method="GET", path=f"/v1/pki/roots/{quote(root_name, safe='')}/roles"
        ))

    async def create_role(
        self,
        root_name: str,
        *,
        role_name: str,
        allowed_domains: list[str] | None = None,
        allow_subdomains: bool | None = None,
        allow_wildcards: bool | None = None,
        max_ttl_seconds: int | None = None,
        default_ttl_seconds: int | None = None,
        idempotency_key: str | None = None,
    ) -> CARole:
        body: dict[str, Any] = {"role_name": role_name}
        if allowed_domains is not None:
            body["allowed_domains"] = allowed_domains
        if allow_subdomains is not None:
            body["allow_subdomains"] = allow_subdomains
        if allow_wildcards is not None:
            body["allow_wildcards"] = allow_wildcards
        if max_ttl_seconds is not None:
            body["max_ttl_seconds"] = max_ttl_seconds
        if default_ttl_seconds is not None:
            body["default_ttl_seconds"] = default_ttl_seconds
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/pki/roots/{quote(root_name, safe='')}/roles",
            body=body,
            idempotency_key=idempotency_key,
        ))

    # ── Certificate lifecycle ─────────────────────────────────────────────────

    async def issue_cert(
        self,
        root_name: str,
        role: str,
        *,
        subject: dict[str, Any],
        san_dns: list[str] | None = None,
        san_ip: list[str] | None = None,
        ttl_seconds: int | None = None,
        idempotency_key: str | None = None,
    ) -> IssuedCertificate:
        """Issue a leaf certificate. Returns ``cert_pem``, ``private_key_pem``,
        ``ca_chain_pem``, ``serial_hex``, ``not_before``, ``not_after``."""
        body: dict[str, Any] = {"subject": subject}
        if san_dns is not None:
            body["san_dns"] = san_dns
        if san_ip is not None:
            body["san_ip"] = san_ip
        if ttl_seconds is not None:
            body["ttl_seconds"] = ttl_seconds
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/pki/roots/{quote(root_name, safe='')}/issue/{quote(role, safe='')}",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def revoke_cert(
        self,
        root_name: str,
        *,
        serial_hex: str,
        reason: str | None = None,
        idempotency_key: str | None = None,
    ) -> RevokeCertResult:
        body: dict[str, Any] = {"serial_hex": serial_hex}
        if reason is not None:
            body["reason"] = reason
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/pki/roots/{quote(root_name, safe='')}/revoke",
            body=body,
            idempotency_key=idempotency_key,
        ))
