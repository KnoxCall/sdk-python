"""OAuth 2.1 client management resource — /v1/oauth-clients.

These endpoints bypass the standard ``success()`` wrapper server-side: the
list has no pagination (and no meta), and create/rotate-secret carry a
top-level ``warning`` string which the SDK attaches to the returned object.
"""

from __future__ import annotations
from typing import Any, Literal, TYPE_CHECKING
from urllib.parse import quote

from .._envelope import unwrap
from ..types import (
    OAuthClient,
    OAuthClientCreateResult,
    OAuthClientDetail,
    OAuthClientRevokeResult,
    OAuthClientRotateSecretResult,
    OAuthClientUpdateResult,
)

if TYPE_CHECKING:
    from ..core import APIClient

GrantType = Literal[
    "client_credentials",
    "authorization_code",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:token-exchange",
    "urn:ietf:params:oauth:grant-type:device_code",
]
# The only accepted access-token format. The RFC 9068 "jwt" format was
# withdrawn: no KnoxCall resource server accepted it, and the server now
# refuses any other value with 400.
TokenFormat = Literal["opaque"]


def _attach_warning(resp: Any) -> Any:
    """Unwrap ``data`` and fold the server's top-level ``warning`` (present on
    create / rotate-secret) into the returned object."""
    data = unwrap(resp)
    if isinstance(resp, dict) and isinstance(data, dict) and resp.get("warning") is not None:
        data = {**data, "warning": resp["warning"]}
    return data


class OAuthClientsResource:
    def __init__(self, client: "APIClient") -> None:
        self._client = client

    async def list(self) -> list[OAuthClient]:
        """List OAuth clients (bare array — this endpoint has no pagination)."""
        return unwrap(await self._client.request(method="GET", path="/v1/oauth-clients"))

    async def get(self, oauth_client_id: str) -> OAuthClientDetail:
        return unwrap(await self._client.request(
            method="GET", path=f"/v1/oauth-clients/{quote(oauth_client_id, safe='')}"
        ))

    async def create(
        self,
        *,
        name: str,
        type: Literal["confidential", "public"] = "confidential",
        grant_types: list[GrantType] | None = None,
        allowed_scopes: list[str] | None = None,
        redirect_uris: list[str] | None = None,
        require_dpop: bool = False,
        require_pkce: Literal[True] = True,
        token_format: TokenFormat = "opaque",
        idempotency_key: str | None = None,
    ) -> OAuthClientCreateResult:
        """Create an OAuth client. ``client_secret`` is returned once — save it
        immediately (``None`` for public clients)."""
        body: dict[str, Any] = {
            "name": name,
            "type": type,
            "grant_types": grant_types or ["client_credentials"],
            "allowed_scopes": allowed_scopes or [],
            "require_dpop": require_dpop,
            "require_pkce": require_pkce,
            "token_format": token_format,
        }
        if redirect_uris is not None:
            body["redirect_uris"] = redirect_uris
        return _attach_warning(await self._client.request(
            method="POST", path="/v1/oauth-clients", body=body, idempotency_key=idempotency_key
        ))

    async def update(
        self,
        oauth_client_id: str,
        *,
        name: str | None = None,
        allowed_scopes: list[str] | None = None,
        redirect_uris: list[str] | None = None,
        require_dpop: bool | None = None,
        require_pkce: Literal[True] | None = None,
        active: bool | None = None,
        token_format: TokenFormat | None = None,
        consent_html_template: str | None = None,
        step_up_scopes: list[str] | None = None,
        idempotency_key: str | None = None,
    ) -> OAuthClientUpdateResult:
        body: dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if allowed_scopes is not None:
            body["allowed_scopes"] = allowed_scopes
        if redirect_uris is not None:
            body["redirect_uris"] = redirect_uris
        if require_dpop is not None:
            body["require_dpop"] = require_dpop
        if require_pkce is not None:
            body["require_pkce"] = require_pkce
        if active is not None:
            body["active"] = active
        if token_format is not None:
            body["token_format"] = token_format
        if consent_html_template is not None:
            body["consent_html_template"] = consent_html_template
        if step_up_scopes is not None:
            body["step_up_scopes"] = step_up_scopes
        return unwrap(await self._client.request(
            method="PATCH",
            path=f"/v1/oauth-clients/{quote(oauth_client_id, safe='')}",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def rotate_secret(
        self, oauth_client_id: str, *, idempotency_key: str | None = None
    ) -> OAuthClientRotateSecretResult:
        """Rotate the client_secret. Returns the new secret EXACTLY ONCE — persist it immediately.

        Rotation is containment: every access and refresh token the OLD secret
        minted is revoked in the same transaction as the re-key, so they stop
        working immediately rather than at their TTL. A rotation whose
        revocation cannot complete is refused and the old secret keeps working —
        you never hold a new secret for a client whose old tokens are still live.
        """
        return _attach_warning(await self._client.request(
            method="POST",
            path=f"/v1/oauth-clients/{quote(oauth_client_id, safe='')}/rotate-secret",
            idempotency_key=idempotency_key,
        ))

    async def revoke(
        self, oauth_client_id: str, *, idempotency_key: str | None = None
    ) -> OAuthClientRevokeResult:
        """Revoke the client and cascade-revoke all its active tokens."""
        return unwrap(await self._client.request(
            method="DELETE",
            path=f"/v1/oauth-clients/{quote(oauth_client_id, safe='')}",
            idempotency_key=idempotency_key,
        ))
