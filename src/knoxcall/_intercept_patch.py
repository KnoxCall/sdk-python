"""The process-wide interceptor — ``knox.wrap.intercept()`` (route-aware-
interception-plan.md PR3, decision D7).

Python's generic seams, patched at CLASS level so every client built after
(and before) install is reached without wiring:

- ``httpx.HTTPTransport.handle_request`` and
  ``httpx.AsyncHTTPTransport.handle_async_request`` — every ``httpx.Client`` /
  ``AsyncClient`` on the default transport (OpenAI, Anthropic, most modern SDKs);
- ``urllib3.connectionpool.HTTPConnectionPool.urlopen`` — ``requests`` (via its
  ``HTTPAdapter``), OpenAPI-generated clients such as ``hubspot-api-client``,
  ``botocore``, and anything else that bottoms out in urllib3;
- ``aiohttp.ClientSession._request`` — OPT-IN (``stacks=["aiohttp"]``, on
  ``KnoxCallAsync`` only, aiohttp >= 3.13): every ``session.get()`` / ``.post()`` /
  ``.request()`` and ``async with session.get(...)`` on any session — aiobotocore,
  slack_sdk's async client, azure-core's aiohttp transport, python-telegram-bot.
  The translation lives in ``_intercept_aiohttp.py``.

A matched request is handed to a :class:`KnoxWrapTransport` (sync) or
:class:`KnoxWrapAsyncTransport`, which decides route / ephemeral / direct with
the manifest (PARITY §21.1). NOT reached: an explicitly injected custom
transport, raw ``http.client``, ``pycurl``, and — on the aiohttp stack — a
WebSocket handshake (``ws_connect``), which goes direct.

Anti-recursion, two layers: KnoxCall's own hosts never match (the SDK's own
manifest poll and proxy sends pass straight through), and a context variable
marks the reroute's own scope so a route-around / direct call to a MATCHED host
falls through to the original transport instead of looping.

┌─ READ THIS ─────────────────────────────────────────────────────────────┐
│ This is a CONVENIENCE, not a security boundary. It patches process-     │
│ global classes, composes with APM agents in install order, and is not a │
│ boundary against hostile in-process code. ROUTE mode is the custody     │
│ path — the key never enters the process; transit is not.                │
└──────────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import contextvars
import io
from contextlib import contextmanager
from typing import Any, Awaitable, Callable, Iterator, Mapping

import httpx

from ._intercept import SUPPRESS, intercept_kill_switch, is_platform_host, normalise_host
from .wrap_transport import KnoxWrapAsyncTransport, KnoxWrapTransport, build_observer

_ROUTED: contextvars.ContextVar[bool] = contextvars.ContextVar("knoxcall_routed", default=False)
_SUPPRESS = SUPPRESS  # one flag, shared with the uncovered-egress reporter (PARITY §21.3)


def _aiohttp_headers(session: Any, call_headers: Any) -> dict[str, str]:
    """The header NAMES an aiohttp call will send: the session's defaults under
    the call's own. Best-effort — only names matter to the observer."""
    out: dict[str, str] = {}
    for source in (getattr(session, "_default_headers", None), call_headers):
        if source is None:
            continue
        try:
            items = source.items() if hasattr(source, "items") else source
            for k, v in items:
                out[str(k)] = str(v)
        except Exception:  # noqa: BLE001 — an odd headers object is not worth a failure on the app's request
            continue
    return out

# Cross-module marker so a double install is detectable even if two copies of
# this module are loaded.
_INSTALLED_ATTR = "__knoxcall_intercept_installed__"


@contextmanager
def routed() -> Iterator[None]:
    """Mark the CALL SITE: with ``require_context=True`` only egress performed
    inside this block (and what it awaits/calls) is intercepted."""
    token = _ROUTED.set(True)
    try:
        yield
    finally:
        _ROUTED.reset(token)


def in_routed_context() -> bool:
    return _ROUTED.get()


class InterceptHandle:
    """What :func:`install_intercept` returns: uninstall + the route-aware controls."""

    def __init__(
        self,
        *,
        restorers: list[Callable[[], None]],
        sync_transport: KnoxWrapTransport | None,
        async_transport: KnoxWrapAsyncTransport | None,
        runner: Callable[[Awaitable[Any]], Any] | None,
    ) -> None:
        self._restorers = restorers
        self._sync = sync_transport
        self._async = async_transport
        self._runner = runner
        self._installed = True

    @property
    def installed(self) -> bool:
        return self._installed

    def uninstall(self) -> None:
        """Restore the originals (never clobbering a later patcher) and drop the manifest."""
        if not self._installed:
            return
        self._installed = False
        for r in self._restorers:
            r()
        for t in (self._sync, self._async):
            if t is not None:
                t.stop()

    def manifest(self) -> Mapping[str, Any] | None:
        for t in (self._sync, self._async):
            if t is not None:
                return t.manifest()
        return None

    def ready(self) -> None:
        """Load the manifest once, synchronously (needs the sync facade's runner)."""
        if self._sync is not None:
            self._sync.ready()
        elif self._async is not None and self._runner is not None:
            self._runner(self._async.ready())

    async def aready(self) -> None:
        """Load the manifest once (async)."""
        if self._async is not None:
            await self._async.ready()
        elif self._sync is not None:
            self._sync.ready()

    def refresh(self) -> None:
        """Refresh the manifest now, synchronously (needs the sync facade's runner)."""
        if self._sync is not None:
            self._sync.refresh()
        elif self._async is not None and self._runner is not None:
            self._runner(self._async.arefresh())

    async def arefresh(self) -> None:
        if self._async is not None:
            await self._async.arefresh()
        elif self._sync is not None:
            self._sync.refresh()


def _matcher(
    listed: frozenset[str],
    own_hosts: Callable[[], frozenset[str]],
    manifest: Callable[[], Mapping[str, Any] | None],
    routes: str,
) -> Callable[[str], bool]:
    def match(host: str) -> bool:
        if not host or is_platform_host(host) or host in own_hosts():
            return False
        if host in listed:
            return True
        if routes != "auto":
            return False
        m = manifest()
        return bool(m) and any(normalise_host(str(e.get("host", ""))) == host for e in m.get("routes", []))

    return match


def install_intercept(
    *,
    client: Any,
    runner: Callable[[Awaitable[Any]], Any] | None,
    stacks: list[str],
    hosts: Any,
    host_options: Mapping[str, Mapping[str, Any]],
    require_context: bool,
    transport_opts: dict[str, Any],
) -> InterceptHandle:
    """Patch the requested stacks. ``runner`` is the sync facade's bridge; without
    it only the async stacks can be patched (there is no way to drive the SDK's
    async I/O from a synchronous httpx/urllib3 call). The reverse holds for
    ``aiohttp``: it awaits the SDK's async I/O on the CALLER's event loop, and the
    sync facade's I/O lives on its own background loop thread, so that stack is
    refused with the sync client — install it from ``KnoxCallAsync``."""
    stacks = list(stacks) if stacks else ["httpx", "urllib3"]
    unknown = [s for s in stacks if s not in ("httpx", "urllib3", "aiohttp")]
    if unknown:
        raise ValueError(f"unknown intercept stack(s): {unknown!r} (known: 'httpx', 'urllib3', 'aiohttp')")
    if runner is None and "urllib3" in stacks:
        raise TypeError("the 'urllib3' stack needs the sync client (KnoxCall), whose runner drives the SDK's async I/O")
    if runner is not None and "aiohttp" in stacks:
        raise TypeError(
            "the 'aiohttp' stack awaits the SDK's async I/O on the caller's event loop; the sync client (KnoxCall) "
            "runs its I/O on a background loop thread, so install it from KnoxCallAsync: "
            "KnoxCallAsync(...).wrap.intercept(stacks=['aiohttp'])"
        )

    listed = frozenset(normalise_host(h) for h in hosts if normalise_host(h))
    routes = transport_opts.get("routes", "auto")
    if not listed and routes == "off":
        raise TypeError("intercept requires `hosts` when routes='off' — there would be nothing to intercept.")

    base_opts = dict(transport_opts)
    base_opts.update(
        hosts=listed,
        host_options=host_options,
        require_context=require_context,
        in_context=in_routed_context,
        # Uncovered-egress observations (PARITY §21.3): ONE reporter per
        # handle, shared by every transport built below, so the sync and async
        # arms aggregate into one buffer and one 403 stops them all.
        observer=build_observer(client, runner, transport_opts),
    )

    # One store shared by every transport so a manifest loaded on one side is
    # the truth on the others. The aiohttp arm rides its own async transport (a
    # different direct leg) over this one's store.
    async_t: KnoxWrapAsyncTransport | None = None
    sync_t: KnoxWrapTransport | None = None
    if "httpx" in stacks or "aiohttp" in stacks:
        async_t = KnoxWrapAsyncTransport(client, **base_opts)
        if runner is not None:
            sync_t = KnoxWrapTransport(client, runner, **{**base_opts, "store": async_t.store})
    elif runner is not None:
        sync_t = KnoxWrapTransport(client, runner, **base_opts)

    def own_hosts() -> frozenset[str]:
        t = sync_t or async_t
        return t._own_hosts() if t is not None else frozenset()

    def current_manifest() -> Mapping[str, Any] | None:
        t = sync_t or async_t
        return t.manifest() if t is not None else None

    match = _matcher(listed, own_hosts, current_manifest, routes)

    def enabled() -> bool:
        return not intercept_kill_switch() and not _SUPPRESS.get()

    restorers: list[Callable[[], None]] = []

    def _refuse_double(cls: Any, attr: str, label: str) -> None:
        if getattr(getattr(cls, attr), _INSTALLED_ATTR, False):
            for r in restorers:
                r()
            raise RuntimeError(f"A KnoxCall {label} interceptor is already installed; uninstall it before installing another.")

    if "httpx" in stacks:
        # ── async httpx ──
        _refuse_double(httpx.AsyncHTTPTransport, "handle_async_request", "httpx")
        orig_async = httpx.AsyncHTTPTransport.handle_async_request

        async def patched_async(self: Any, request: httpx.Request) -> httpx.Response:
            host = normalise_host(request.url.host)
            if not enabled() or not match(host) or (require_context and not _ROUTED.get()):
                # Observed AFTER the decision, BEFORE the direct send; never
                # for the SDK's own traffic; can never throw into the request.
                if not _SUPPRESS.get():
                    async_t.observe_direct(str(request.url), request.method, request.headers)  # type: ignore[union-attr]
                return await orig_async(self, request)
            token = _SUPPRESS.set(True)
            try:
                return await async_t.handle_async_request(request)  # type: ignore[union-attr]
            finally:
                _SUPPRESS.reset(token)

        setattr(patched_async, _INSTALLED_ATTR, True)
        httpx.AsyncHTTPTransport.handle_async_request = patched_async  # type: ignore[method-assign]

        def _restore_async() -> None:
            if httpx.AsyncHTTPTransport.handle_async_request is patched_async:
                httpx.AsyncHTTPTransport.handle_async_request = orig_async  # type: ignore[method-assign]

        restorers.append(_restore_async)

        if sync_t is not None:
            # ── sync httpx ──
            _refuse_double(httpx.HTTPTransport, "handle_request", "httpx")
            orig_sync = httpx.HTTPTransport.handle_request

            def patched_sync(self: Any, request: httpx.Request) -> httpx.Response:
                host = normalise_host(request.url.host)
                if not enabled() or not match(host) or (require_context and not _ROUTED.get()):
                    if not _SUPPRESS.get():
                        sync_t.observe_direct(str(request.url), request.method, request.headers)  # type: ignore[union-attr]
                    return orig_sync(self, request)
                token = _SUPPRESS.set(True)
                try:
                    return sync_t.handle_request(request)  # type: ignore[union-attr]
                finally:
                    _SUPPRESS.reset(token)

            setattr(patched_sync, _INSTALLED_ATTR, True)
            httpx.HTTPTransport.handle_request = patched_sync  # type: ignore[method-assign]

            def _restore_sync() -> None:
                if httpx.HTTPTransport.handle_request is patched_sync:
                    httpx.HTTPTransport.handle_request = orig_sync  # type: ignore[method-assign]

            restorers.append(_restore_sync)

    if "urllib3" in stacks:
        try:
            import urllib3
            from urllib3.connectionpool import HTTPConnectionPool
            from urllib3.response import HTTPResponse as U3Response
        except ImportError as e:  # pragma: no cover — only when urllib3 is absent
            for r in restorers:
                r()
            raise RuntimeError("the 'urllib3' intercept stack needs urllib3 installed") from e

        _refuse_double(HTTPConnectionPool, "urlopen", "urllib3")
        orig_urlopen = HTTPConnectionPool.urlopen
        transport = sync_t
        assert transport is not None

        def patched_urlopen(self: Any, method: str, url: str, body: Any = None, headers: Any = None, *args: Any, **kwargs: Any) -> Any:
            host = normalise_host(getattr(self, "host", ""))
            scheme = getattr(self, "scheme", "http") or "http"
            port = getattr(self, "port", None)
            default_port = 443 if scheme == "https" else 80
            netloc = self.host if (port is None or port == default_port) else f"{self.host}:{port}"
            full = url if url.startswith(("http://", "https://")) else f"{scheme}://{netloc}{url if url.startswith('/') else '/' + url}"
            if not enabled() or not match(host) or (require_context and not _ROUTED.get()):
                if not _SUPPRESS.get():
                    transport.observe_direct(full, method, headers)
                return orig_urlopen(self, method, url, body, headers, *args, **kwargs)
            hdrs = dict(headers or {})
            content = body if isinstance(body, (bytes, bytearray)) else (body.encode("utf-8") if isinstance(body, str) else (body.read() if hasattr(body, "read") else body))
            request = httpx.Request(method, full, headers=hdrs, content=content)
            token = _SUPPRESS.set(True)
            try:
                resp = transport.handle_request(request)
            finally:
                _SUPPRESS.reset(token)
            return U3Response(
                body=io.BytesIO(resp.content),
                headers=list(resp.headers.multi_items()),
                status=resp.status_code,
                reason=resp.reason_phrase or None,
                preload_content=False,
                decode_content=False,
                request_method=method,
                request_url=full,
            )

        setattr(patched_urlopen, _INSTALLED_ATTR, True)
        HTTPConnectionPool.urlopen = patched_urlopen  # type: ignore[method-assign]

        def _restore_urlopen() -> None:
            if HTTPConnectionPool.urlopen is patched_urlopen:
                HTTPConnectionPool.urlopen = orig_urlopen  # type: ignore[method-assign]

        restorers.append(_restore_urlopen)
        del urllib3  # imported for the availability check only

    if "aiohttp" in stacks:
        # Opt-in. The translation (request → httpx.Request, httpx.Response → a real
        # aiohttp.ClientResponse) is in _intercept_aiohttp.py; the decision table
        # is the shared async pipeline, unchanged. Import, floor and the response
        # recipe are all checked HERE, so a session that cannot be served refuses
        # at install rather than mid-request.
        from ._intercept_aiohttp import (
            AiohttpCall,
            AiohttpDirect,
            build_request,
            finish_response,
            is_upgrade,
            load_aiohttp,
            resolve_url,
            self_check,
        )

        try:
            aiohttp = load_aiohttp()
            self_check(aiohttp)
        except Exception:
            for r in restorers:
                r()
            raise

        ClientSession = aiohttp.ClientSession
        _refuse_double(ClientSession, "_request", "aiohttp")
        orig_request = ClientSession._request
        assert async_t is not None
        # Its own transport so a DIRECT decision inside the pipeline (route-around,
        # the unavailable="direct" fallback, a re-decision after a refusal) replays
        # the ORIGINAL aiohttp call — never an httpx send of a buffered copy.
        aio_t = KnoxWrapAsyncTransport(client, direct_transport=AiohttpDirect(), **{**base_opts, "store": async_t.store})

        async def patched_request(self: Any, method: str, str_or_url: Any, **kwargs: Any) -> Any:
            url = resolve_url(self, str_or_url)
            host = normalise_host(url.host) if url is not None else ""
            if (
                url is None
                or getattr(self, "closed", False)
                or not enabled()
                or not match(host)
                or (require_context and not _ROUTED.get())
                or is_upgrade(kwargs.get("headers"))
            ):
                if url is not None and not _SUPPRESS.get():
                    aio_t.observe_direct(str(url), method, _aiohttp_headers(self, kwargs.get("headers")))
                return await orig_request(self, method, str_or_url, **kwargs)
            call = AiohttpCall(orig=orig_request, session=self, method=method, str_or_url=str_or_url, kwargs=kwargs)
            request = await build_request(aiohttp, call, url)
            token = _SUPPRESS.set(True)
            try:
                resp = await aio_t.handle_async_request(request)
            finally:
                _SUPPRESS.reset(token)
            if call.response is not None:  # a DIRECT decision ran the original call
                return call.response
            return await finish_response(aiohttp, call, request, resp)

        setattr(patched_request, _INSTALLED_ATTR, True)
        ClientSession._request = patched_request  # type: ignore[method-assign]

        def _restore_request() -> None:
            if ClientSession._request is patched_request:
                ClientSession._request = orig_request  # type: ignore[method-assign]

        restorers.append(_restore_request)
        restorers.append(aio_t.stop)

    return InterceptHandle(restorers=restorers, sync_transport=sync_t, async_transport=async_t, runner=runner)
