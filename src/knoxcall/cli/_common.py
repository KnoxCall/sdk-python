"""Shared CLI plumbing — errors, token-endpoint POSTs, profile persistence."""

from __future__ import annotations
import time
from typing import Any

import httpx

from ..auth.credentials_file import CredentialsFileLock, format_expiry, write_profile

#: Reserved alias accepted by /oauth/authorize and the device endpoints; the
#: server lazily provisions the tenant's real CLI client and returns its id
#: as the `client_id` extension member on the token response.
CLI_CLIENT_ID = "knoxcall-cli"


class CLIError(Exception):
    """Expected CLI failure — printed as a one-line message, never a traceback."""


def post_form(
    url: str,
    form: dict[str, str],
    http: httpx.Client | None = None,
) -> tuple[int, dict[str, Any]]:
    """POST a urlencoded form; return (status, parsed-JSON-or-empty-dict).

    Connection failures raise CLIError with a human message. HTTP error
    statuses are returned, not raised — device polling needs the error codes.
    """
    own_client = http is None
    client = http or httpx.Client(timeout=30.0)
    try:
        res = client.post(url, data=form, headers={"Accept": "application/json"})
    except httpx.HTTPError as e:
        raise CLIError(f"could not reach {url}: {e}") from e
    finally:
        if own_client:
            client.close()
    try:
        body: Any = res.json()
    except ValueError:
        body = None
    return res.status_code, body if isinstance(body, dict) else {}


def token_error_message(status: int, body: dict[str, Any]) -> str:
    detail = body.get("error_description") or body.get("error") or f"HTTP {status}"
    return f"sign-in failed: {detail}"


def persist_login(
    *,
    path: str,
    profile: str,
    base_url: str,
    token_body: dict[str, Any],
    fallback_tenant: str | None = None,
) -> dict[str, Any]:
    """Store a successful token response as a credentials-file profile.

    Persists the `tenant` and `client_id` extension members — refreshes must
    use the REAL per-tenant client id, not the `knoxcall-cli` alias.
    """
    try:
        expires_in = float(token_body.get("expires_in", 3600))
    except (TypeError, ValueError):
        expires_in = 3600.0
    record = {
        "tenant": token_body.get("tenant") or fallback_tenant,
        "base_url": base_url,
        "client_id": token_body.get("client_id") or CLI_CLIENT_ID,
        "refresh_token": token_body.get("refresh_token"),
        "access_token": token_body.get("access_token"),
        "access_token_expires_at": format_expiry(time.time() + expires_in),
        "scope": token_body.get("scope", ""),
    }
    with CredentialsFileLock(path):
        write_profile(path, profile, record)
    return record
