"""Platform auto-detection — mirrors bootstrap.ts."""

from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import Literal

import httpx

from ..errors import NotAuthenticatedError
from .credentials_file import profile_available, resolve_credentials_path, resolve_profile

_PROBE_TIMEOUT = 0.25  # 250ms

# Credential fields use repr=False so a traceback (or a tool that captures
# frame locals, e.g. Sentry) never prints the secret. The `type` discriminator
# defaults per class, so callers never need to spell it out.


@dataclass
class AccessToken:
    access_token: str = field(repr=False)
    type: Literal["access_token"] = "access_token"


@dataclass
class OIDCTokenExchange:
    subject_token: str = field(repr=False)
    issuer: str
    type: Literal["oidc_token_exchange"] = "oidc_token_exchange"


@dataclass
class ClientCredentials:
    client_id: str
    client_secret: str = field(repr=False)
    type: Literal["client_credentials"] = "client_credentials"


@dataclass
class StoredCredentials:
    """Credentials file written by ``knoxcall login``.

    Holds no secrets itself — tokens are read from the file (path/profile
    resolved from ``KNOXCALL_CREDENTIALS_FILE`` / ``KNOXCALL_PROFILE`` when
    not given) at token-fetch time and wrapped in ``Redacted`` immediately.
    """

    path: str | None = None
    profile: str | None = None
    type: Literal["stored_credentials"] = "stored_credentials"


Bootstrap = AccessToken | OIDCTokenExchange | ClientCredentials | StoredCredentials

# Deprecated aliases — the pre-release names. Remove before 2.0.
AccessTokenBootstrap = AccessToken
OidcTokenExchangeBootstrap = OIDCTokenExchange
ClientCredentialsBootstrap = ClientCredentials


async def _try_gha_oidc() -> Bootstrap | None:
    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not token:
        return None
    try:
        async with httpx.AsyncClient(timeout=_PROBE_TIMEOUT) as c:
            r = await c.get(
                f"{url}&audience=knoxcall:api",
                headers={"Authorization": f"Bearer {token}", "User-Agent": "knoxcall-sdk"},
            )
        if r.status_code != 200:
            return None
        value = r.json().get("value")
        if not value:
            return None
        return OIDCTokenExchange(
            subject_token=value,
            issuer="https://token.actions.githubusercontent.com",
        )
    except Exception:
        return None


async def _try_gcp() -> Bootstrap | None:
    try:
        async with httpx.AsyncClient(timeout=_PROBE_TIMEOUT) as c:
            r = await c.get(
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity",
                params={"audience": "knoxcall:api"},
                headers={"Metadata-Flavor": "Google"},
            )
        if r.status_code != 200:
            return None
        return OIDCTokenExchange(
            subject_token=r.text.strip(),
            issuer="https://accounts.google.com",
        )
    except Exception:
        return None


def _try_aws_irsa() -> Bootstrap | None:
    path = os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE")
    if not path:
        return None
    try:
        with open(path, encoding="utf8") as f:
            token = f.read().strip()
        if not token:
            return None
        return OIDCTokenExchange(
            subject_token=token,
            issuer="https://sts.amazonaws.com",
        )
    except Exception:
        return None


async def _try_azure_mi() -> Bootstrap | None:
    endpoint = os.environ.get("IDENTITY_ENDPOINT")
    header = os.environ.get("IDENTITY_HEADER")
    if not endpoint or not header:
        return None
    try:
        async with httpx.AsyncClient(timeout=_PROBE_TIMEOUT) as c:
            r = await c.get(
                endpoint,
                params={"api-version": "2019-08-01", "resource": "knoxcall:api"},
                headers={"X-IDENTITY-HEADER": header},
            )
        if r.status_code != 200:
            return None
        return OIDCTokenExchange(
            subject_token=r.json()["access_token"],
            issuer="https://login.microsoftonline.com",
        )
    except Exception:
        return None


def _try_vercel() -> Bootstrap | None:
    t = os.environ.get("VERCEL_OIDC_TOKEN")
    if not t:
        return None
    return OIDCTokenExchange(subject_token=t, issuer="https://oidc.vercel.com")


def _try_circle() -> Bootstrap | None:
    t = os.environ.get("CIRCLE_OIDC_TOKEN_V2")
    if not t:
        return None
    return OIDCTokenExchange(subject_token=t, issuer="https://oidc.circleci.com")


def _try_env_creds() -> Bootstrap | None:
    cid = os.environ.get("KNOXCALL_CLIENT_ID")
    sec = os.environ.get("KNOXCALL_CLIENT_SECRET")
    if not cid or not sec:
        return None
    return ClientCredentials(client_id=cid, client_secret=sec)


def _try_env_access_token() -> Bootstrap | None:
    # Two spellings, one behavior; ACCESS_TOKEN wins when both are set.
    t = os.environ.get("KNOXCALL_ACCESS_TOKEN") or os.environ.get("KNOXCALL_API_KEY")
    if not t:
        return None
    return AccessToken(access_token=t)


def _try_credentials_file() -> Bootstrap | None:
    """Slot 2: the file written by ``knoxcall login``.

    Present = file exists AND the selected profile parses; anything
    missing/malformed skips the provider silently (the chain continues).
    """
    try:
        if profile_available(resolve_credentials_path(), resolve_profile()):
            return StoredCredentials()
    except Exception:
        return None
    return None


async def auto_detect_bootstrap() -> Bootstrap:
    """Detect credentials from the environment.

    Priority order: pre-acquired token → credentials file (`knoxcall login`)
    → cloud OIDC → env client_credentials. Raises NotAuthenticatedError (a
    BootstrapError subclass) if nothing matches, so callers can branch on
    "not logged in — offer login()" vs a genuine misconfiguration.
    """
    direct = _try_env_access_token()
    if direct:
        return direct

    stored = _try_credentials_file()
    if stored:
        return stored

    gha = await _try_gha_oidc()
    if gha:
        return gha

    gcp = await _try_gcp()
    if gcp:
        return gcp

    aws = _try_aws_irsa()
    if aws:
        return aws

    azure = await _try_azure_mi()
    if azure:
        return azure

    vercel = _try_vercel()
    if vercel:
        return vercel

    circle = _try_circle()
    if circle:
        return circle

    env = _try_env_creds()
    if env:
        return env

    raise NotAuthenticatedError(
        "Could not detect KnoxCall credentials. Run `knoxcall login`, set "
        "KNOXCALL_CLIENT_ID + KNOXCALL_CLIENT_SECRET (or KNOXCALL_API_KEY / "
        "KNOXCALL_ACCESS_TOKEN) env vars, or run on a supported cloud "
        "platform. See https://docs.knoxcall.com/api-reference/authentication"
    )
