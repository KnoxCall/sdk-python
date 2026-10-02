"""APIClient — async request pipeline. Mirrors core.ts."""

from __future__ import annotations
import asyncio
import datetime as _dt
import decimal
import json
import os
import random
import re
import time
import uuid as _uuid
from typing import Any, Callable, Literal
from urllib.parse import urlparse

import httpx

from ._warn import is_insecure_remote_url, warn_security
from .auth.bootstrap import (
    AccessToken,
    Bootstrap,
    ClientCredentials,
    StoredCredentials,
    auto_detect_bootstrap,
)
from .auth.credentials_file import read_profile, resolve_credentials_path, resolve_profile
from .auth.dpop import DpopKeyPair
from .auth.oauth import fetch_token
from .auth.token_store import CachedToken, MemoryTokenStore, TokenStore
from .errors import (
    APIConnectionError,
    APIConnectionTimeoutError,
    BootstrapError,
    KnoxCallError,
    RateLimitError,
    ServerError,
    error_from_response,
)
from .ulid import ulid

_DEFAULT_API_VERSION = "2026-08-05"
_SDK_VERSION = "1.1.0"
_REFRESH_AHEAD_SECONDS = 5 * 60
_RETRYABLE_STATUSES = {408, 429, 500, 502, 503, 504}
# Honor a server Retry-After up to this long; beyond it, fail fast so callers
# can apply their own scheduling instead of blocking a worker.
_RETRY_AFTER_CAP_SECONDS = 30.0


class _NotModified:
    """The value ``request()`` returns for a ``304 Not Modified`` when the caller
    opted in with ``allow_not_modified`` (a conditional GET carrying
    ``If-None-Match``). Internal: the one consumer is
    ``wrap.intercept_manifest(if_none_match=)``, which maps it to ``None``.
    Without the opt-in a 304 keeps its old behaviour (an empty body parsed as
    ``None``), so nothing else changes."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "NOT_MODIFIED"


NOT_MODIFIED = _NotModified()
# A cached token inside the refresh-ahead window is still usable this long
# before real expiry; used as a fallback when the token endpoint is down.
_STALE_TOKEN_MIN_REMAINING_SECONDS = 10.0

_PROXY_HOSTS = {"api.knoxcall.com", "api-staging.knoxcall.com"}
_SANDBOX_HOSTS = {"sandbox.knoxcall.com", "sandbox-staging.knoxcall.com"}

# Where the data plane lives under a proxy base (PARITY §5).
#
# On a KnoxCall CLOUD tenant host the proxy is served ONLY under ``/api``
# (``https://{slug}.knoxcall.com/api/<upstream path>``: server.ts strips the
# prefix, and every other path on that host is the dashboard). ``call()``
# therefore places the upstream path under ``/api`` whenever the base names
# such a host and carries no path of its own — the derived plain/sandbox shapes
# and an explicit override alike, any port. Every other base is used verbatim:
# self-hosted mounts the proxy at ``/``, and a base that already carries a path
# IS the entry point (the agent bundle spells the same base as
# ``…knoxcall.com/api``). Until 2026-09-25 nothing added the prefix, so the
# documented ``path="/users"`` answered the dashboard HTML on every tenant
# host; the live smokes hid it by hard-coding ``path="/api/get"``.
_NON_TENANT_LABELS = frozenset({"api", "sandbox", "api-staging", "sandbox-staging", "www", "staging", "admin"})
_CLOUD_TENANT_HOST_RE = re.compile(r"^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.knoxcall\.com$")


def data_plane_path_prefix(proxy_base_url: str) -> str:
    """``"/api"`` when ``proxy_base_url`` names a cloud tenant host with no path of its own, else ``""``."""
    try:
        parsed = urlparse(proxy_base_url)
    except ValueError:
        return ""
    if parsed.path not in ("", "/"):
        return ""
    m = _CLOUD_TENANT_HOST_RE.match((parsed.hostname or "").lower())
    if m is None or m.group(1) in _NON_TENANT_LABELS:
        return ""
    return "/api"

# Auth-bearing headers the proxy data plane consumes to identify the caller.
# The SDK's own credential is the SOLE authority on the data plane, so any
# caller-supplied copy is stripped from call()/ephemeral() headers before the
# SDK sets its own — otherwise an integrator forwarding untrusted end-user
# headers could inject an alternate proxy identity (x-knoxcall-agent-*) or, on
# the legacy-key path, a Bearer Authorization the proxy would honor over the
# SDK's own x-knoxcall-key.
_PROXY_AUTH_HEADERS = (
    "authorization",
    "dpop",
    "x-knoxcall-key",
    "x-knoxcall-agent-id",
    "x-knoxcall-agent-token",
)

# Markers the SDK owns on the data plane (PARITY §21.2). Not auth — the server
# treats them as informational — but a caller-supplied copy is stripped the
# same way, so an app cannot relabel its own calls as interceptor traffic
# through the headers dict. The interceptors set the marker through
# ``call(..., _origin=SDK_INTERCEPT_ORIGIN)``, never through ``headers``.
_SDK_MARKER_HEADERS = ("x-knoxcall-origin",)

# The one value ``call()``'s internal ``_origin`` accepts: the route-aware
# interceptors' reroute marker, sent as ``x-knoxcall-origin: sdk-intercept`` so
# the API Log can show which Route calls the SDK rerouted from a third-party
# SDK and which were direct. Internal — nothing public sets it.
SDK_INTERCEPT_ORIGIN = "sdk-intercept"


def _default_base_url(sandbox: bool = False) -> str:
    env = os.environ.get("KNOXCALL_BASE_URL")
    if env:
        return env
    return "https://sandbox.knoxcall.com" if sandbox else "https://api.knoxcall.com"


# A tenant slug becomes a data-plane hostname (https://<slug>.knoxcall.com), so
# it must be a bare DNS label. A slug adopted from a token response,
# /v1/account, or the credentials file that isn't (e.g. "evil.com#") would
# otherwise misdirect the tenant's bearer token to an attacker-controlled host.
_TENANT_SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


def _assert_tenant_slug(tenant: str) -> str:
    if not _TENANT_SLUG_RE.match(tenant):
        raise BootstrapError(
            f"invalid tenant slug {tenant!r} — expected a DNS label; "
            "refusing to derive a data-plane host from it"
        )
    return tenant


def _default_proxy_base_url(tenant: str | None, base_url: str) -> tuple[str | None, str | None]:
    """Derive (proxy_base_url, proxy_shape) from the management base URL.

    ``proxy_shape`` ("plain" | "sandbox" | None) records which tenant
    subdomain shape to build once the tenant is discovered lazily.
    """
    env_override = os.environ.get("KNOXCALL_PROXY_BASE_URL")
    if env_override:
        return env_override.rstrip("/"), None
    # For known production/staging API hosts derive the tenant proxy subdomain
    # (None when the tenant is not yet known — resolved lazily via discovery).
    # Sandbox hosts use the Stripe-style isolated test data plane
    # (sandbox-{tenant}.knoxcall.com). For local dev / self-hosted, fall back
    # to the same host (proxy runs on the same port).
    host = urlparse(base_url).hostname
    if host in _SANDBOX_HOSTS:
        return (f"https://sandbox-{_assert_tenant_slug(tenant)}.knoxcall.com" if tenant else None), "sandbox"
    if host in _PROXY_HOSTS:
        return (f"https://{_assert_tenant_slug(tenant)}.knoxcall.com" if tenant else None), "plain"
    return base_url, None


def _resolve_flat_credentials(
    bootstrap: Bootstrap | None,
    client_id: str | None,
    client_secret: str | None,
    access_token: str | None,
    api_key: str | None,
) -> Bootstrap | None:
    """Fold the flat constructor options into a Bootstrap, enforcing mutual
    exclusion. Returns None when nothing explicit was passed, preserving the
    lazy env/platform auto-detection path."""
    flat = [n for n, v in (
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("access_token", access_token),
        ("api_key", api_key),
    ) if v is not None]
    if bootstrap is not None and flat:
        raise BootstrapError(f"bootstrap= cannot be combined with {', '.join(flat)}")
    if access_token is not None and api_key is not None:
        raise BootstrapError("pass either access_token or api_key, not both (they are two spellings of the same credential)")
    token = access_token if access_token is not None else api_key
    if token is not None and (client_id is not None or client_secret is not None):
        raise BootstrapError("a token credential cannot be combined with client_id/client_secret")
    if (client_id is None) != (client_secret is None):
        raise BootstrapError("client_id and client_secret must be provided together")

    if bootstrap is not None:
        return bootstrap
    if token is not None:
        return AccessToken(access_token=token)
    if client_id is not None and client_secret is not None:
        return ClientCredentials(client_id=client_id, client_secret=client_secret)
    return None


def _credential_identity(bootstrap: Bootstrap | None) -> str:
    """Stable token-cache key component for clients constructed without a
    tenant. Uses the credential's identity so shared stores (Redis) still
    deduplicate; falls back to a per-instance nonce for lazy auto-detect."""
    if isinstance(bootstrap, ClientCredentials):
        return f"cid:{bootstrap.client_id}"
    if isinstance(bootstrap, AccessToken):
        import hashlib
        return "tok:" + hashlib.sha256(bootstrap.access_token.encode()).hexdigest()[:16]
    if isinstance(bootstrap, StoredCredentials):
        return f"file:{resolve_credentials_path(bootstrap.path)}:{resolve_profile(bootstrap.profile)}"
    return "anon:" + ulid()


def _default_json_default(obj: Any) -> Any:
    """json.dumps fallback covering the types ORMs and ERPs commonly hand us."""
    if isinstance(obj, (_dt.datetime, _dt.date, _dt.time)):
        return obj.isoformat()
    if isinstance(obj, _dt.timedelta):
        return obj.total_seconds()
    if isinstance(obj, decimal.Decimal):
        return float(obj)
    if isinstance(obj, _uuid.UUID):
        return str(obj)
    if isinstance(obj, (set, frozenset)):
        return list(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


class APIClient:
    """Async API client. Subclassed by KnoxCallAsync; sync wrapper in client.py."""

    def __init__(
        self,
        *,
        tenant: str | None = None,
        environment: str | None = None,
        scope: list[str] | None = None,
        base_url: str | None = None,
        proxy_base_url: str | None = None,
        sandbox: bool = False,
        bootstrap: Bootstrap | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        access_token: str | None = None,
        api_key: str | None = None,
        token_store: TokenStore | None = None,
        dpop: str = "auto",  # "auto" | "always" | "never"
        retry_max_attempts: int = 3,
        retry_base_delay: float = 0.1,
        retry_max_delay: float = 5.0,
        timeout: float = 30.0,
        api_version: str | None = None,
        user_agent: str | None = None,
        http: httpx.AsyncClient | None = None,
        json_default: Callable[[Any], Any] | None = None,
    ) -> None:
        # Tenant is optional: when absent it is discovered from the first
        # token response (or /v1/account for pre-acquired tokens). Only the
        # data-plane hostname needs it client-side; management calls resolve
        # the tenant server-side from the credential.
        tenant = tenant or os.environ.get("KNOXCALL_TENANT") or None
        bootstrap = _resolve_flat_credentials(bootstrap, client_id, client_secret, access_token, api_key)
        if dpop not in ("auto", "always", "never"):
            raise KnoxCallError(f'dpop must be "auto", "always", or "never" (got {dpop!r})')
        self.tenant = tenant
        # Sandbox / test mode: defaults base_url to sandbox.knoxcall.com and
        # the data plane to sandbox-{tenant}.knoxcall.com (Stripe-style
        # isolated test environment). Ignored when an explicit base_url is
        # provided; the KNOXCALL_BASE_URL env var also wins.
        self.sandbox = sandbox is True
        self.base_url = (base_url or _default_base_url(self.sandbox)).rstrip("/")
        # Explicit tenant/base_url (constructor, env, or sandbox=True) always
        # beat values seeded from the `knoxcall login` credentials file.
        self._base_url_explicit = (
            base_url is not None or bool(os.environ.get("KNOXCALL_BASE_URL")) or self.sandbox
        )
        self._proxy_explicit = proxy_base_url is not None
        if proxy_base_url:
            proxy: str | None = proxy_base_url
            proxy_shape: str | None = None
        else:
            proxy, proxy_shape = _default_proxy_base_url(tenant, self.base_url)
        self._proxy_base_url = proxy.rstrip("/") if proxy else None
        self._proxy_shape = proxy_shape
        if isinstance(bootstrap, StoredCredentials):
            self._seed_from_stored_credentials(bootstrap)
        # Plaintext http:// to a non-loopback host sends credentials and access
        # tokens in the clear — warn (don't block: http://localhost is normal dev).
        if is_insecure_remote_url(self.base_url):
            warn_security(
                f"KnoxCall base URL {self.base_url} uses plaintext http:// to a non-loopback "
                "host — credentials and access tokens will be sent unencrypted. Use https:// "
                "(plain http:// is only safe for localhost)."
            )
        if is_insecure_remote_url(self._proxy_base_url):
            warn_security(
                f"KnoxCall proxy base URL {self._proxy_base_url} uses plaintext http:// to a "
                "non-loopback host — proxied requests and the SDK credential will be sent "
                "unencrypted. Use https:// (plain http:// is only safe for localhost)."
            )
        self.api_version = api_version or _DEFAULT_API_VERSION
        self.user_agent = user_agent or f"knoxcall-sdk-python/{_SDK_VERSION}"
        self.scope = scope or []
        # Default environment for data-plane calls; per-call and bound-route
        # values win, and None means the server picks the tenant default.
        self.environment = environment or os.environ.get("KNOXCALL_ENVIRONMENT")
        self._store = token_store or MemoryTokenStore()
        self._cache_key = f"{self.tenant or _credential_identity(bootstrap)}:{' '.join(sorted(self.scope))}"
        self._retry_max_attempts = retry_max_attempts
        self._retry_base_delay = retry_base_delay
        self._retry_max_delay = retry_max_delay
        self._timeout = timeout
        self._bootstrap = bootstrap
        self._dpop_mode = dpop
        self._dpop: DpopKeyPair | None = DpopKeyPair.generate() if dpop == "always" else None
        self._json_default = json_default or _default_json_default
        self._http = http
        self._own_http = http is None

    async def __aenter__(self) -> "APIClient":
        if self._own_http and self._http is None:
            self._http = httpx.AsyncClient(timeout=self._timeout)
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._own_http and self._http is not None:
            await self._http.aclose()

    async def _http_client(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=self._timeout)
            self._own_http = True
        return self._http

    async def _resolve_bootstrap(self) -> Bootstrap:
        if self._bootstrap is not None:
            return self._bootstrap
        detected = await auto_detect_bootstrap()
        if isinstance(detected, StoredCredentials):
            self._seed_from_stored_credentials(detected)
        self._bootstrap = detected
        return self._bootstrap

    def _seed_from_stored_credentials(self, stored: StoredCredentials) -> None:
        """Seed tenant/base_url from the credentials file when the caller did
        not set them explicitly (explicit constructor/env values always win).
        Malformed/missing file → no-op (the chain already vetted presence)."""
        record = read_profile(
            resolve_credentials_path(stored.path), resolve_profile(stored.profile)
        )
        if not record:
            return
        if self.tenant is None and record.get("tenant"):
            self.tenant = str(record["tenant"])
        if not self._base_url_explicit and record.get("base_url"):
            self.base_url = str(record["base_url"]).rstrip("/")
        if not self._proxy_explicit:
            # Re-derive the data plane from the (possibly updated) tenant and
            # base_url; the KNOXCALL_PROXY_BASE_URL env override still wins
            # inside _default_proxy_base_url.
            proxy, proxy_shape = _default_proxy_base_url(self.tenant, self.base_url)
            self._proxy_base_url = proxy.rstrip("/") if proxy else None
            self._proxy_shape = proxy_shape

    async def authenticate(self) -> None:
        await self._get_or_refresh_token()

    async def sign_out(self) -> None:
        await self._store.delete(self._cache_key)

    @staticmethod
    def _refresh_ahead(cached: CachedToken) -> float:
        # For short-lived tokens a fixed 5-minute window would mean "always
        # expired", forcing a token fetch per request; never use more than
        # half the token's lifetime as the refresh-ahead window.
        if cached.lifetime:
            return min(_REFRESH_AHEAD_SECONDS, cached.lifetime / 2)
        return _REFRESH_AHEAD_SECONDS

    async def _fetch_token(self, bootstrap: Bootstrap) -> CachedToken:
        try:
            return await fetch_token(
                token_endpoint=f"{self.base_url}/oauth/token",
                bootstrap=bootstrap,
                scope=self.scope,
                dpop=self._dpop,
                http=await self._http_client(),
            )
        except KnoxCallError as e:
            # In "auto" mode, upgrade to DPoP when the OAuth client record
            # requires it instead of failing every token request.
            if self._dpop_mode == "auto" and self._dpop is None and e.code == "invalid_dpop_proof":
                self._dpop = DpopKeyPair.generate()
                return await fetch_token(
                    token_endpoint=f"{self.base_url}/oauth/token",
                    bootstrap=bootstrap,
                    scope=self.scope,
                    dpop=self._dpop,
                    http=await self._http_client(),
                )
            raise

    async def _get_or_refresh_token(self) -> CachedToken:
        cached = await self._store.get(self._cache_key)
        if cached and cached.expires_at - time.time() > self._refresh_ahead(cached):
            return self._adopt_tenant(cached)

        async def refresh() -> CachedToken:
            again = await self._store.get(self._cache_key)
            if again and again.expires_at - time.time() > self._refresh_ahead(again):
                return again
            bootstrap = await self._resolve_bootstrap()
            fresh = await self._fetch_token(bootstrap)
            await self._store.set(self._cache_key, fresh)
            return fresh

        try:
            return self._adopt_tenant(await self._store.with_lock(self._cache_key, refresh))
        except (KnoxCallError, httpx.HTTPError):
            # Token endpoint unreachable or erroring during the refresh-ahead
            # window: a cached token that hasn't actually expired is still
            # good — use it rather than failing the caller's request.
            stale = await self._store.get(self._cache_key)
            if stale and stale.expires_at - time.time() > _STALE_TOKEN_MIN_REMAINING_SECONDS:
                return self._adopt_tenant(stale)
            raise

    def _adopt_tenant(self, cached: CachedToken) -> CachedToken:
        """Learn the tenant from a token response when constructed without one."""
        if self.tenant is None and cached.tenant:
            self.tenant = cached.tenant
        return cached

    async def _ensure_proxy_base_url(self) -> str:
        """Resolve the data-plane base URL, discovering the tenant if needed.

        Tenant discovery: the token response carries the slug; pre-acquired
        tokens (and older servers) fall back to one GET /v1/account.
        """
        if self._proxy_base_url is not None:
            return self._proxy_base_url
        if self.tenant is None:
            await self._get_or_refresh_token()  # may adopt from the response
        if self.tenant is None:
            account = await self.request(method="GET", path="/v1/account")
            data = account.get("data") if isinstance(account, dict) else None
            slug = data.get("slug") if isinstance(data, dict) else None
            if not slug:
                raise BootstrapError(
                    "could not discover the tenant from the credential — pass "
                    "tenant=... or set the KNOXCALL_TENANT environment variable"
                )
            self.tenant = slug
        self._proxy_base_url = (
            f"https://sandbox-{_assert_tenant_slug(self.tenant)}.knoxcall.com"
            if self._proxy_shape == "sandbox"
            else f"https://{_assert_tenant_slug(self.tenant)}.knoxcall.com"
        )
        return self._proxy_base_url

    def _encode_body(self, body: Any, headers: httpx.Headers) -> bytes | str | None:
        """Serialize a request body, defaulting Content-Type to JSON.

        ``bytes``/``str`` pass through untouched (pre-serialized payloads);
        anything else is JSON-encoded with the client's ``json_default`` hook,
        which handles datetime/date/time/timedelta/Decimal/UUID/set out of
        the box.
        """
        if body is None:
            return None
        if "content-type" not in headers:
            headers["Content-Type"] = "application/json"
        if isinstance(body, (bytes, bytearray)):
            return bytes(body)
        if isinstance(body, str):
            return body
        return json.dumps(body, default=self._json_default)

    def _auth_headers(
        self,
        headers: httpx.Headers,
        cached: CachedToken,
        *,
        method: str,
        url: str,
        legacy_key_as_header: bool = False,
    ) -> None:
        """Attach Authorization (and a fresh DPoP proof when bound) in place.

        ``legacy_key_as_header`` is set on data-plane call() requests: the
        proxy's OAuth detection matches the ``kc_`` token prefix only, so a
        legacy ``tk_``/``AKE`` credential must travel as ``x-knoxcall-key``
        (Bearer would fall through to the legacy path and 401).
        """
        token = cached.access_token.expose()
        if legacy_key_as_header and cached.token_type == "Bearer" and not token.startswith("kc_"):
            headers["x-knoxcall-key"] = token
            return
        headers["Authorization"] = f"{cached.token_type} {token}"
        if cached.token_type == "DPoP" and self._dpop is not None:
            proof_url = url.split("#", 1)[0].split("?", 1)[0]
            headers["DPoP"] = self._dpop.sign(
                method=method.upper(),
                url=proof_url,
                access_token=cached.access_token.expose(),
            )

    async def request(
        self,
        *,
        method: str,
        path: str,
        query: dict[str, Any] | None = None,
        body: Any = None,
        headers: dict[str, str] | None = None,
        idempotency_key: str | None = None,
        allow_not_modified: bool = False,
    ) -> Any:
        """Management-API request. ``allow_not_modified=True`` treats a ``304``
        as success with no body and returns ``NOT_MODIFIED`` instead of parsing
        the empty body; auth, the one transparent re-auth on 401 and the retry
        policy are unchanged, and ``headers`` (the ``If-None-Match``) ride on
        every attempt."""
        is_mutating = method.upper() not in ("GET", "HEAD")
        idem_key = idempotency_key if idempotency_key else (ulid() if is_mutating else None)

        last_err: Exception | None = None
        reauth_done = False
        for attempt in range(1, self._retry_max_attempts + 1):
            try:
                return await self._attempt(
                    method=method,
                    path=path,
                    query=query,
                    body=body,
                    headers=headers,
                    idempotency_key=idem_key,
                    allow_not_modified=allow_not_modified,
                )
            except KnoxCallError as e:
                last_err = e
                # One transparent re-auth: _attempt purged the cached token on
                # 401, so the immediate retry runs with freshly minted creds.
                if e.status == 401 and not reauth_done and attempt < self._retry_max_attempts:
                    reauth_done = True
                    continue
                if not self._should_retry(e, attempt):
                    raise
                await asyncio.sleep(self._retry_delay(e, attempt))
            except httpx.TimeoutException as e:
                last_err = APIConnectionTimeoutError(str(e))
                if attempt >= self._retry_max_attempts:
                    raise last_err from e
                await asyncio.sleep(self._backoff_delay(attempt))
            except httpx.HTTPError as e:
                last_err = APIConnectionError(str(e))
                if attempt >= self._retry_max_attempts:
                    raise last_err from e
                await asyncio.sleep(self._backoff_delay(attempt))
        if last_err:
            raise last_err
        raise KnoxCallError("request loop exited unexpectedly")

    def _should_retry(self, err: KnoxCallError, attempt: int) -> bool:
        if attempt >= self._retry_max_attempts:
            return False
        if isinstance(err, APIConnectionError):
            return True
        if err.status and err.status in _RETRYABLE_STATUSES:
            return True
        return False

    def _retry_delay(self, err: KnoxCallError, attempt: int) -> float:
        # A 429's Retry-After, and a 503's (`dependency_unavailable` — the
        # server says how long the dependency needs). Both capped: beyond the
        # cap the caller's own scheduling beats a blocked worker.
        if isinstance(err, (RateLimitError, ServerError)) and err.retry_after:
            return min(float(err.retry_after), _RETRY_AFTER_CAP_SECONDS)
        return self._backoff_delay(attempt)

    def _backoff_delay(self, attempt: int) -> float:
        # Half-jitter: random within [exp/2, exp] so a retry never fires
        # immediately but herds still spread out.
        exp = self._retry_base_delay * (2 ** (attempt - 1))
        return min(self._retry_max_delay, exp * (0.5 + random.random() / 2))

    async def _attempt(
        self,
        *,
        method: str,
        path: str,
        query: dict[str, Any] | None,
        body: Any,
        headers: dict[str, str] | None,
        idempotency_key: str | None,
        allow_not_modified: bool = False,
    ) -> Any:
        cached = await self._get_or_refresh_token()

        url = f"{self.base_url}{path if path.startswith('/') else '/' + path}"

        req_headers = httpx.Headers(headers or {})
        if "accept" not in req_headers:
            req_headers["Accept"] = "application/json"
        if "user-agent" not in req_headers:
            req_headers["User-Agent"] = self.user_agent
        if "x-knoxcall-api-version" not in req_headers:
            req_headers["KnoxCall-Version"] = self.api_version

        self._auth_headers(req_headers, cached, method=method, url=url)

        if idempotency_key:
            req_headers["X-Idempotency-Key"] = idempotency_key

        content = self._encode_body(body, req_headers)

        http = await self._http_client()
        res = await http.request(
            method,
            url,
            params=query,
            content=content,
            headers=req_headers,
        )

        resp_headers = {k.lower(): v for k, v in res.headers.items()}
        try:
            parsed = res.json()
        except ValueError:
            parsed = res.text if res.text else None

        if res.status_code == 401:
            await self._store.delete(self._cache_key)
            raise error_from_response(res.status_code, parsed, resp_headers)
        if res.status_code >= 400:
            raise error_from_response(res.status_code, parsed, resp_headers)
        if res.status_code == 304 and allow_not_modified:
            # A conditional GET the server answered "unchanged": success, no body.
            return NOT_MODIFIED
        return parsed

    @staticmethod
    def verify_signature(
        *,
        raw_body: str | bytes,
        signature: str,
        secret: str,
        timestamp: int | None = None,
        tolerance_seconds: int | None = None,
    ) -> bool:
        """Verify an incoming KnoxCall webhook signature (HMAC-SHA256, constant-time).

        Pass ``timestamp`` + ``tolerance_seconds`` to reject replays.
        """
        from .resources.webhooks import verify_webhook_signature as _verify
        return _verify(
            raw_body=raw_body,
            signature=signature,
            secret=secret,
            timestamp=timestamp,
            tolerance_seconds=tolerance_seconds,
        )

    @staticmethod
    def construct_event(
        raw_body: str | bytes,
        headers: Any,
        secret: str,
        *,
        format: str = "legacy",
        tolerance_seconds: int | None = 300,
        header_name: str | None = None,
    ) -> Any:
        """Verify a webhook delivery AND return the typed event.

        See :func:`knoxcall.construct_webhook_event`. Raises
        ``WebhookSignatureVerificationError`` on any failure.
        """
        from .resources.webhooks import construct_webhook_event as _construct
        return _construct(
            raw_body,
            headers,
            secret,
            format=format,
            tolerance_seconds=tolerance_seconds,
            header_name=header_name,
        )

    def _proxy_transport_retryable(self, err: httpx.HTTPError, method: str, attempt: int) -> bool:
        if attempt >= self._retry_max_attempts:
            return False
        # The connection was never established, so the request was never
        # sent — always safe to retry, even for mutating methods.
        if isinstance(err, (httpx.ConnectError, httpx.ConnectTimeout)):
            return True
        # Anything later (read timeout, idle-keepalive reset, …) may have
        # reached the upstream; only replay methods that are safe to repeat.
        return method in ("GET", "HEAD")

    async def _proxy_send(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str] | None,
        sdk_headers: dict[str, str],
        query: dict[str, Any] | None = None,
        body: Any = None,
        timeout: float | None = None,
        legacy_key_as_header: bool = False,
    ) -> httpx.Response:
        """Shared data-plane sender for call()/ephemeral().

        Proxied responses are returned raw (the upstream's status belongs to
        the caller), but transport failures are mapped to KnoxCallError
        subclasses and retried when safe, and a 401 triggers one token
        purge + re-mint so a revoked token can't wedge a long-lived client.
        """
        method = method.upper()
        reauth_done = False
        attempt = 0
        while True:
            attempt += 1
            cached = await self._get_or_refresh_token()

            req_headers = httpx.Headers(headers or {})
            # The SDK credential is the sole data-plane auth authority: drop any
            # caller-supplied proxy-auth headers before we set our own, so SDK
            # auth always wins (agent identity / legacy-key path included).
            for _h in _PROXY_AUTH_HEADERS + _SDK_MARKER_HEADERS:
                if _h in req_headers:
                    del req_headers[_h]
            if "user-agent" not in req_headers:
                req_headers["User-Agent"] = self.user_agent
            # Explicit keyword arguments always win over the headers dict.
            for k, v in sdk_headers.items():
                req_headers[k] = v
            self._auth_headers(
                req_headers, cached, method=method, url=url,
                legacy_key_as_header=legacy_key_as_header,
            )

            content = self._encode_body(body, req_headers)

            http = await self._http_client()
            try:
                res = await http.request(
                    method,
                    url,
                    params=query,
                    content=content,
                    headers=req_headers,
                    timeout=timeout if timeout is not None else httpx.USE_CLIENT_DEFAULT,
                )
            except httpx.TimeoutException as e:
                if self._proxy_transport_retryable(e, method, attempt):
                    await asyncio.sleep(self._backoff_delay(attempt))
                    continue
                raise APIConnectionTimeoutError(str(e)) from e
            except httpx.HTTPError as e:
                if self._proxy_transport_retryable(e, method, attempt):
                    await asyncio.sleep(self._backoff_delay(attempt))
                    continue
                raise APIConnectionError(str(e)) from e

            # An upstream that answered is not a KnoxCall refusal, whichever header
            # names it: the ephemeral proxy says `X-Knox-Destination-Status`, the
            # route data plane's response block says `X-Knox-Upstream-Status`. Only a
            # KnoxCall-originated 401 spends the one token re-mint.
            gateway_originated = not res.headers.get("x-knox-destination-status") and not res.headers.get(
                "x-knox-upstream-status"
            )
            if res.status_code == 401 and not reauth_done and gateway_originated:
                await self._store.delete(self._cache_key)
                reauth_done = True
                continue
            return res

    async def call(
        self,
        route: str,
        *,
        method: str = "GET",
        path: str = "/",
        body: Any = None,
        headers: dict[str, str] | None = None,
        environment: str | None = None,
        query: dict[str, Any] | None = None,
        timeout: float | None = None,
        _origin: str | None = None,
    ) -> httpx.Response:
        """Make a proxied request through a KnoxCall route.

        ``route`` is the route's **slug** (preferred — write-once, never
        breaks on rename), its **UUID** (also works), or its bare name
        (legacy). Returns the raw httpx.Response so callers have full access
        to status, headers, and body (.json(), .text, .content).

        Connection-level failures raise ``APIConnectionError`` /
        ``APIConnectionTimeoutError``; safe-to-repeat failures are retried
        with backoff, and a rejected token is re-minted once automatically.

            resp = await client.call("payments-stripe", path="/v1/customers")
            customers = resp.json()

        ``_origin`` is internal: the route-aware interceptors pass
        :data:`SDK_INTERCEPT_ORIGIN` so the request carries
        ``x-knoxcall-origin: sdk-intercept`` (PARITY §21.2). A direct call
        sends nothing — absence IS "direct" on the server.
        """
        sdk_headers = {"x-knoxcall-route": route}
        if environment is None:
            environment = self.environment
        if environment is not None:
            sdk_headers["x-knoxcall-environment"] = environment
        if _origin is not None:
            if _origin != SDK_INTERCEPT_ORIGIN:
                raise ValueError(f"unknown call origin {_origin!r}; the only marker is {SDK_INTERCEPT_ORIGIN!r}")
            sdk_headers["x-knoxcall-origin"] = SDK_INTERCEPT_ORIGIN

        proxy_base = await self._ensure_proxy_base_url()
        # ``path`` is the UPSTREAM path; the entry point is the SDK's to add (PARITY §5).
        url = f"{proxy_base}{data_plane_path_prefix(proxy_base)}{path if path.startswith('/') else '/' + path}"
        return await self._proxy_send(
            method=method,
            url=url,
            headers=headers,
            sdk_headers=sdk_headers,
            query=query,
            body=body,
            timeout=timeout,
            legacy_key_as_header=True,
        )

    def route(
        self,
        route: str,
        *,
        environment: str | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> "BoundRoute":
        """Bind a route (and optional call defaults) once, then make plain
        HTTP-verb calls against it. Reference the route by slug (preferred),
        UUID (works), or bare name (legacy)::

            printnode = client.route("ops-printnode", environment="production")
            computers = (await printnode.get("/computers")).json()
            await printnode.post("/printjobs", body=payload)
        """
        return BoundRoute(self, route, environment=environment, headers=headers, timeout=timeout)

    async def ephemeral(
        self,
        upstream_url: str,
        *,
        method: str = "GET",
        body: Any = None,
        headers: dict[str, str] | None = None,
        encrypted: str | None = None,
        timeout_ms: int | None = None,
        mode: Literal["transparent"] | None = None,
        upstream_authorization: str | None = None,
        upstream_auth_secret: str | None = None,
        upstream_auth_scheme: str | None = None,
        timeout: float | None = None,
    ) -> httpx.Response:
        """Make a one-shot proxied request via the Ephemeral Proxy.

        The proxy resolves ``{{ token: "..." }}`` template expressions in the
        request body on the wire — upstream never receives raw token values.

        ``timeout_ms`` bounds the server-side upstream call; ``timeout``
        overrides the local HTTP timeout for this request (set it higher
        than ``timeout_ms`` or the local timeout fires first).

        ``mode="transparent"`` forwards the request body and ``Content-Type``
        byte-verbatim and skips ``{{ token }}`` templating — the mode a wrapped
        third-party SDK (Stripe, form-urlencoded, …) needs. Omit it for the
        default JSON+template behaviour. ``upstream_authorization`` is an opaque
        string mapped to the *upstream* ``Authorization`` header server-side
        (the provider's own credential); it is never logged or stored and does
        not affect the SDK's own KnoxCall auth. ``upstream_auth_secret`` names
        an escrowed wrap credential the server resolves, decrypts and injects as
        the upstream ``Authorization`` header, host-pinned (mutually exclusive on
        the wire with ``upstream_authorization``; the server rejects both at
        once). ``upstream_auth_scheme`` sets the auth scheme for that resolved
        secret (server default ``Bearer``; ``"none"`` sends the raw value).

            resp = await client.ephemeral("https://stripe.com/v1/charges",
                                          method="POST",
                                          body={"card": "{{ token: 'tok_abc123' }}"})
        """
        sdk_headers = {"X-Knox-Proxy-URL": upstream_url}
        if encrypted is not None:
            sdk_headers["X-Knox-Encrypted"] = encrypted
        if timeout_ms is not None:
            sdk_headers["X-Knox-Timeout-Ms"] = str(timeout_ms)
        if mode == "transparent":
            sdk_headers["X-Knox-Proxy-Mode"] = "transparent"
        if upstream_authorization is not None:
            sdk_headers["X-Knox-Upstream-Authorization"] = upstream_authorization
        if upstream_auth_secret is not None:
            sdk_headers["X-Knox-Upstream-Auth-Secret"] = upstream_auth_secret
        if upstream_auth_scheme is not None:
            sdk_headers["X-Knox-Upstream-Auth-Scheme"] = upstream_auth_scheme

        return await self._proxy_send(
            method=method,
            url=f"{self.base_url}/v1/proxy",
            headers=headers,
            sdk_headers=sdk_headers,
            body=body,
            timeout=timeout,
        )


class BoundRoute:
    """A route with bound call defaults — see ``APIClient.route()``.

    Holds only the client reference, route id, and defaults (never a token
    or any pipeline state), so retries and 401 re-mint behave exactly as on
    ``call()``. Per-call values win over bound defaults; headers merge
    per-key with per-call winning.
    """

    __slots__ = ("_client", "_route", "_environment", "_headers", "_timeout")

    def __init__(
        self,
        client: APIClient,
        route: str,
        *,
        environment: str | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> None:
        self._client = client
        self._route = route
        self._environment = environment
        self._headers = dict(headers) if headers else {}
        self._timeout = timeout

    async def request(
        self,
        method: str,
        path: str = "/",
        *,
        body: Any = None,
        headers: dict[str, str] | None = None,
        environment: str | None = None,
        query: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> httpx.Response:
        merged_headers = {**self._headers, **(headers or {})}
        return await self._client.call(
            self._route,
            method=method,
            path=path,
            body=body,
            headers=merged_headers or None,
            environment=environment if environment is not None else self._environment,
            query=query,
            timeout=timeout if timeout is not None else self._timeout,
        )

    async def get(self, path: str = "/", **kw: Any) -> httpx.Response:
        return await self.request("GET", path, **kw)

    async def post(self, path: str = "/", **kw: Any) -> httpx.Response:
        return await self.request("POST", path, **kw)

    async def put(self, path: str = "/", **kw: Any) -> httpx.Response:
        return await self.request("PUT", path, **kw)

    async def patch(self, path: str = "/", **kw: Any) -> httpx.Response:
        return await self.request("PATCH", path, **kw)

    async def delete(self, path: str = "/", **kw: Any) -> httpx.Response:
        return await self.request("DELETE", path, **kw)
