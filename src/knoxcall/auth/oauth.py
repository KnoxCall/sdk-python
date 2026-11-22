"""OAuth 2.1 client — calls KnoxCall's /oauth/token endpoint."""

from __future__ import annotations
import base64
import time
from typing import Any

import httpx

from ..errors import error_from_response, KnoxCallError
from ..redacted import Redacted
from .bootstrap import (
    Bootstrap,
    AccessToken,
    ClientCredentials,
    OIDCTokenExchange,
    StoredCredentials,
)
from .credentials_file import fetch_stored_token, resolve_credentials_path, resolve_profile
from .dpop import DpopKeyPair
from .dpop_nonce import DpopNonceStore, is_use_dpop_nonce
from .token_store import CachedToken


def _read(res: httpx.Response) -> tuple[Any, dict[str, str]]:
    """The parsed body and lower-cased headers of a token-endpoint response."""
    try:
        body: Any = res.json()
    except ValueError:
        body = res.text or None
    return body, {k.lower(): v for k, v in res.headers.items()}


async def fetch_token(
    *,
    token_endpoint: str,
    bootstrap: Bootstrap,
    scope: list[str] | None = None,
    dpop: DpopKeyPair | None = None,
    nonces: DpopNonceStore | None = None,
    http: httpx.AsyncClient | None = None,
) -> CachedToken:
    if isinstance(bootstrap, AccessToken):
        return CachedToken(
            access_token=Redacted(bootstrap.access_token),
            expires_at=time.time() + 3600,
            scope=scope or [],
            token_type="DPoP" if dpop else "Bearer",
            cnf_jkt=dpop.thumbprint() if dpop else None,
        )

    if isinstance(bootstrap, StoredCredentials):
        # Tokens come from the `knoxcall login` credentials file. The file is
        # the cross-process cache and refresh authority (single-use rotated
        # refresh tokens); scope/DPoP posture is whatever login negotiated.
        return await fetch_stored_token(
            path=resolve_credentials_path(bootstrap.path),
            profile=resolve_profile(bootstrap.profile),
            token_endpoint=token_endpoint,
            http=http,
            nonces=nonces,
        )

    def _proof(nonce: str | None) -> str | None:
        return dpop.sign(method="POST", url=token_endpoint, nonce=nonce) if dpop else None

    dpop_proof = _proof(nonces.get(token_endpoint) if nonces is not None else None)

    if isinstance(bootstrap, ClientCredentials):
        form: dict[str, str] = {"grant_type": "client_credentials"}
        if scope:
            form["scope"] = " ".join(scope)
        basic = base64.b64encode(f"{bootstrap.client_id}:{bootstrap.client_secret}".encode()).decode()
        headers: dict[str, str] = {
            "Authorization": f"Basic {basic}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
    elif isinstance(bootstrap, OIDCTokenExchange):
        form = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
            "subject_token": bootstrap.subject_token,
            "audience": "knoxcall:api",
        }
        if scope:
            form["scope"] = " ".join(scope)
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
    else:
        raise KnoxCallError(f"unsupported bootstrap: {type(bootstrap).__name__}")

    if dpop_proof:
        headers["DPoP"] = dpop_proof

    own_client = http is None
    client = http or httpx.AsyncClient()
    try:
        res = await client.post(token_endpoint, data=form, headers=headers)
        body, resp_headers = _read(res)
        if nonces is not None:
            nonces.remember(token_endpoint, resp_headers)
        # ONE re-sign with the server's nonce (RFC 9449 section 8, PARITY 7.1 /
        # 4.3). The authorization server answers 400 with the OAuth body
        # `{"error": "use_dpop_nonce"}` where a resource server answers 401 with
        # the WWW-Authenticate challenge, which is why the predicate is shared
        # rather than written twice. Retried here, inside the mint, so a caller
        # never sees a mint fail for a stale nonce; never looped.
        if dpop is not None and nonces is not None:
            err = error_from_response(res.status_code, body, resp_headers) if res.status_code >= 400 else None
            if err is not None and is_use_dpop_nonce(status=err.status, code=err.code, headers=resp_headers):
                retry_headers = dict(headers)
                retry_proof = _proof(nonces.get(token_endpoint))
                if retry_proof:
                    retry_headers["DPoP"] = retry_proof
                res = await client.post(token_endpoint, data=form, headers=retry_headers)
                body, resp_headers = _read(res)
                nonces.remember(token_endpoint, resp_headers)
    finally:
        if own_client:
            await client.aclose()

    if res.status_code >= 400:
        raise error_from_response(res.status_code, body, resp_headers)
    if not isinstance(body, dict) or not body.get("access_token"):
        # e.g. an HTML page from an edge proxy with a 200 status
        raise KnoxCallError(
            f"token endpoint returned an unexpected response (status {res.status_code})",
            status=res.status_code,
            headers=resp_headers,
            body=body,
        )

    token_type = "DPoP" if body.get("token_type") == "DPoP" else "Bearer"
    if token_type == "DPoP" and dpop is None:
        raise KnoxCallError(
            "server issued a DPoP-bound token but this client holds no DPoP "
            'keypair — construct the client with dpop="always"'
        )

    try:
        expires_in = float(body.get("expires_in", 3600))
    except (TypeError, ValueError):
        expires_in = 3600.0
    scope_str: str = body.get("scope", "")
    return CachedToken(
        access_token=Redacted(body["access_token"]),
        refresh_token=Redacted(body["refresh_token"]) if body.get("refresh_token") else None,
        expires_at=time.time() + expires_in,
        lifetime=expires_in,
        scope=scope_str.split() if scope_str else (scope or []),
        token_type=token_type,
        cnf_jkt=dpop.thumbprint() if dpop else None,
        tenant=body.get("tenant") or None,  # extension member, used for tenant auto-discovery
    )
