"""The ``aiohttp`` arm of ``knox.wrap.intercept()`` — opt-in ``stacks=["aiohttp"]``
(route-aware-interception-plan.md D7, PARITY §21.1). Imported lazily by
``_intercept_patch.install_intercept``; nothing here runs unless the stack is asked for.

``aiohttp.ClientSession._request`` is the one seam every ``session.get()`` /
``.post()`` / ``.request()`` and every ``async with session.get(...)`` passes through
(the public verbs wrap its coroutine in ``_RequestContextManager``), so it is patched
at class level like the other stacks. A matched call is translated to an
:class:`httpx.Request`, decided and sent by the SAME :class:`KnoxWrapAsyncTransport`
pipeline the async httpx stack rides, and the pipeline's :class:`httpx.Response` is
handed back as a real :class:`aiohttp.ClientResponse` (below). Every DIRECT outcome
— an unmatched host, the kill switch, outside ``routed()``, a route-around rule, the
``unavailable="direct"`` fallback, a re-decision after a refusal — runs the ORIGINAL
``_request`` with the caller's original arguments, so a direct request is aiohttp's
own: streaming, redirect-following, untouched.

THE RESPONSE. ``aiohttp.ClientResponse`` has no public constructor for a response
that never touched a socket. The alternatives were a duck-typed stand-in (loses
``isinstance``, ``request_info``, ``history``, ``cookies``, ``content_type``,
``get_encoding()``, ``content.iter_chunked()`` — things aiobotocore, azure-core and
slack_sdk read) or a subclass that skips ``__init__`` (touches MORE private state).
So the arm builds a genuine ``ClientResponse`` the way aiohttp's own test suite
builds one: the constructor (keyword arguments filtered by the installed signature —
3.14 added ``stream_writer``), then ``status`` / ``reason`` / ``version`` /
``_headers`` / ``_raw_headers`` / ``content`` set to what ``start()`` would have set,
the body already fed into a ``StreamReader`` at EOF. Everything a caller then does
is aiohttp's own code: ``read()`` / ``text()`` / ``json()``, ``ok`` /
``raise_for_status()`` (a real ``ClientResponseError``), ``release()`` / ``close()`` /
``wait_for_close()``, ``async with``, ``content.iter_chunked()``, ``headers`` /
``raw_headers`` / ``cookies`` / ``content_type`` / ``charset`` / ``get_encoding()`` /
``request_info`` / ``history`` / ``url``. The recipe writes three private
attributes (``_headers``, ``_raw_headers`` — unchanged since aiohttp 3.0 — and
``_raw_cookie_headers``, what ``cookies`` reads since 3.14) and is PROVED at
install time: :func:`self_check` builds and reads one such response against the
installed aiohttp — body, JSON, text, headers, a cookie, ``raise_for_status`` — and
refuses the stack with a clear ``RuntimeError`` if the recipe no longer holds.
Never a surprise mid-request.

BODIES are buffered — the pipeline needs bytes in memory and a refusal-driven resend
needs them replayable, exactly what the httpx arms' ``aread()`` does to a streaming
body. ``json=`` goes through the session's own serializer; ``data=`` through
aiohttp's own payload registry (``bytes``, ``str``, a mapping → form-urlencoded,
``FormData`` including multipart, a file object, a sync or async iterable) and
``Payload.as_bytes()`` — which is why the arm needs aiohttp >= 3.13. A ``data``
value the registry does not know is refused with the ``TypeError`` aiohttp itself
raises, before anything is sent.

NOT MIRRORED, by design: a WebSocket handshake (``ws_connect`` sends ``Upgrade``,
which no data-plane hop can complete) goes direct; client middlewares and
``TraceConfig`` hooks do not run for an intercepted call (they wrap the connection
aiohttp did not make); a 3xx is returned as the upstream's answer, not followed;
``proxy=`` / ``ssl=`` / ``server_hostname=`` describe that unmade connection and are
ignored; the body arrives decoded (``auto_decompress`` is moot).
"""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass, field
from http.cookies import Morsel, SimpleCookie
from typing import Any, Awaitable, Callable, Iterable, Mapping

import httpx

AIOHTTP_FLOOR = "3.13"
INSTALL_HINT = "pip install 'aiohttp>=3.13'"

# Key under which the intercepted call rides on ``httpx.Request.extensions`` so the
# pipeline's direct transport can replay it.
CALL_EXT = "knoxcall_aiohttp_call"


def load_aiohttp() -> Any:
    """Import aiohttp on demand. Absent → ``ImportError`` naming the install; present
    but below the floor (no ``Payload.as_bytes``) → ``RuntimeError`` naming it."""
    try:
        import aiohttp
        from aiohttp import payload as aio_payload
    except ImportError as e:
        raise ImportError(
            f"the 'aiohttp' intercept stack needs aiohttp installed: {INSTALL_HINT}"
        ) from e
    if not hasattr(aio_payload.Payload, "as_bytes"):
        raise RuntimeError(
            f"the 'aiohttp' intercept stack needs aiohttp >= {AIOHTTP_FLOOR} (Payload.as_bytes buffers the "
            f"request body for the pipeline); found {getattr(aiohttp, '__version__', '?')} — {INSTALL_HINT}"
        )
    return aiohttp


@dataclass
class AiohttpCall:
    """One intercepted ``_request`` call: the original callable and arguments, so a
    DIRECT decision inside the pipeline replays it untouched; ``response`` is the
    aiohttp response that replay produced, when it ran."""

    orig: Callable[..., Awaitable[Any]]
    session: Any
    method: str
    str_or_url: Any
    kwargs: dict[str, Any] = field(default_factory=dict)
    url: Any = None  # the yarl URL the intercepted request was built from
    response: Any = None


class AiohttpDirect(httpx.AsyncBaseTransport):
    """The pipeline's direct transport for this arm. It runs the ORIGINAL
    ``ClientSession._request`` with the caller's original arguments and parks the
    aiohttp response on the call record; the ``httpx.Response`` it returns is a
    placeholder the arm never hands to the caller."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        call: AiohttpCall = request.extensions[CALL_EXT]
        call.response = await call.orig(call.session, call.method, call.str_or_url, **call.kwargs)
        status = getattr(call.response, "status", None)
        return httpx.Response(int(status) if isinstance(status, int) else 200, request=request)


# ── request side ───────────────────────────────────────────────────────────────


def resolve_url(session: Any, str_or_url: Any) -> Any:
    """The absolute ``yarl.URL`` aiohttp would request (a session ``base_url`` is
    honoured), or ``None`` when aiohttp itself would refuse it — the original call
    then raises aiohttp's own error."""
    from yarl import URL

    build = getattr(session, "_build_url", None)
    try:
        url = build(str_or_url) if callable(build) else URL(str_or_url)
    except Exception:
        return None
    if not isinstance(url, URL) or url.scheme not in ("http", "https") or not url.host:
        return None
    return url


def is_upgrade(headers: Any) -> bool:
    """A WebSocket handshake (``ws_connect``) carries ``Upgrade``; it can only be
    completed by the connection aiohttp makes itself."""
    if not headers:
        return False
    items: Iterable[Any] = headers.items() if isinstance(headers, Mapping) else headers
    try:
        return any(str(k).lower() == "upgrade" for k, _v in items)
    except (TypeError, ValueError):
        return False


def _merge_headers(session: Any, headers: Any) -> Any:
    """Session default headers overlaid with the call's — the same rule as
    ``ClientSession._prepare_headers`` (a repeated call header is ADDED, the first
    one REPLACES the default)."""
    from multidict import CIMultiDict, MultiDict, MultiDictProxy

    result = CIMultiDict(getattr(session, "headers", None) or {})
    if headers:
        if not isinstance(headers, (MultiDictProxy, MultiDict)):
            headers = CIMultiDict(headers)
        added: set[str] = set()
        for key, value in headers.items():
            if key in added:
                result.add(key, value)
            else:
                result[key] = value
                added.add(key)
    return result


def _cookie_header(session: Any, url: Any, existing: str | None, call_cookies: Any) -> str | None:
    """The ``Cookie`` header aiohttp would send: the jar's cookies for the URL plus
    the call's own, merged over any header already set (``ClientRequest.update_cookies``)."""
    c: SimpleCookie = SimpleCookie()
    if existing:
        c.load(existing)
    jar = getattr(session, "cookie_jar", None)
    if jar is not None:
        for name, morsel in jar.filter_cookies(url).items():
            c[name] = morsel
    if call_cookies:
        items = call_cookies.items() if isinstance(call_cookies, Mapping) else call_cookies
        for name, value in items:
            if isinstance(value, Morsel):
                m: Morsel = Morsel()
                m.set(value.key, value.value, value.coded_value)
                c[name] = m
            else:
                c[name] = value
    return c.output(header="", sep=";").strip() if c else None


def _timeout_seconds(aiohttp: Any, session: Any, kwargs: Mapping[str, Any]) -> float | None:
    """One local timeout for the KnoxCall hop, from the call's ``timeout=`` or the
    session's (``total`` first, then ``sock_read``) — the aiohttp twin of
    ``_timeout_from``."""
    sentinel = getattr(getattr(aiohttp, "helpers", None), "sentinel", object())
    t = kwargs.get("timeout", sentinel)
    if t is sentinel:
        t = getattr(session, "timeout", None)
    if t is None:
        return None
    if not isinstance(t, aiohttp.ClientTimeout):
        return float(t)
    for v in (t.total, t.sock_read):
        if isinstance(v, (int, float)) and v > 0:
            return float(v)
    return None


async def build_request(aiohttp: Any, call: AiohttpCall, url: Any) -> httpx.Request:
    """Translate the intercepted call into the ``httpx.Request`` the pipeline decides
    on: URL with ``params`` applied, headers as aiohttp would have sent them (session
    defaults, ``auth``, cookies, aiohttp's auto headers unless skipped), and the body
    BUFFERED through aiohttp's own payload registry."""
    from aiohttp import BasicAuth, FormData, hdrs
    from aiohttp import payload as aio_payload

    session, kwargs = call.session, call.kwargs
    hs = _merge_headers(session, kwargs.get("headers"))
    skip = {str(h).lower() for h in (getattr(session, "skip_auto_headers", None) or ())}
    skip |= {str(h).lower() for h in (kwargs.get("skip_auto_headers") or ())}

    # Credentials in the URL and the ``auth`` argument — aiohttp's own precedence.
    auth = kwargs.get("auth")
    if url.user is not None:
        if auth is not None:
            raise ValueError("Cannot combine AUTH argument with credentials encoded in URL")
        auth = BasicAuth(url.user, url.password or "")
        url = url.with_user(None)
    if auth is None:
        base = getattr(session, "_base_url", None)
        default_auth = getattr(session, "auth", None)
        if default_auth is not None and (not base or base.origin() == url.origin()):
            auth = default_auth
    if auth is not None:
        if hdrs.AUTHORIZATION in hs:
            raise ValueError("Cannot combine AUTHORIZATION header with AUTH argument or credentials encoded in URL")
        hs[hdrs.AUTHORIZATION] = auth.encode()

    params = kwargs.get("params")
    if params:
        url = url.extend_query(params)

    cookie = _cookie_header(session, url, hs.get(hdrs.COOKIE), kwargs.get("cookies"))
    if cookie:
        hs[hdrs.COOKIE] = cookie
    elif hdrs.COOKIE in hs and not hs[hdrs.COOKIE]:
        del hs[hdrs.COOKIE]

    body: bytes | None = None
    data, js = kwargs.get("data"), kwargs.get("json")
    if data is not None and js is not None:
        raise ValueError("data and json parameters can not be used at the same time")
    if js is not None:
        body = session.json_serialize(js).encode("utf-8")
        if hdrs.CONTENT_TYPE not in hs and "content-type" not in skip:
            hs[hdrs.CONTENT_TYPE] = "application/json"
    elif data is not None:
        maybe = data() if isinstance(data, FormData) else data
        try:
            pl = aio_payload.PAYLOAD_REGISTRY.get(maybe, disposition=None)
        except aio_payload.LookupError:
            pl = FormData(maybe)()  # aiohttp's own rule; an unknown type raises its TypeError here
        body = await pl.as_bytes()
        for key, value in (pl.headers or {}).items():
            if key not in hs and str(key).lower() not in skip:
                hs[key] = value

    defaults = dict(getattr(getattr(aiohttp, "ClientRequest", None), "DEFAULT_HEADERS", None) or {"Accept": "*/*"})
    for key, value in defaults.items():
        if key not in hs and str(key).lower() not in skip:
            hs[key] = value
    if hdrs.USER_AGENT not in hs and "user-agent" not in skip:
        hs[hdrs.USER_AGENT] = aiohttp.http.SERVER_SOFTWARE

    extensions: dict[str, Any] = {CALL_EXT: call}
    seconds = _timeout_seconds(aiohttp, session, kwargs)
    if seconds is not None:
        extensions["timeout"] = {"read": seconds}

    call.url = url
    return httpx.Request(call.method.upper(), str(url), headers=list(hs.items()), content=body, extensions=extensions)


# ── response side ──────────────────────────────────────────────────────────────


class _NoStreamWriter:
    """What aiohttp 3.14's constructor reads off ``stream_writer`` when ``writer`` is
    ``None`` (a request already sent): the bytes written — none, here."""

    output_size = 0
    buffer_size = 0
    length: int | None = 0


def make_client_response(
    aiohttp: Any,
    *,
    session: Any,
    method: str,
    url: Any,
    request_headers: Iterable[tuple[str, str]],
    status: int,
    reason: str,
    headers: Iterable[tuple[str, str]],
    body: bytes,
    loop: asyncio.AbstractEventLoop,
) -> Any:
    """A genuine ``aiohttp.ClientResponse`` for a body already in memory — the recipe
    aiohttp's own tests use (see the module docstring). The session's
    ``response_class`` is honoured when it has one."""
    from multidict import CIMultiDict, CIMultiDictProxy
    from aiohttp import ClientResponse, RequestInfo
    from aiohttp.base_protocol import BaseProtocol
    from aiohttp.streams import StreamReader

    cls = getattr(session, "_response_class", None) or ClientResponse
    req_headers = CIMultiDictProxy(CIMultiDict(list(request_headers)))
    info = RequestInfo(url, method, req_headers, url)
    wanted = dict(
        writer=None,
        continue100=None,
        timer=None,
        request_info=info,
        traces=[],
        loop=loop,
        session=session,
        stream_writer=_NoStreamWriter(),
    )
    accepted = inspect.signature(cls.__init__).parameters
    resp = cls(method, url, **{k: v for k, v in wanted.items() if k in accepted})

    items = [(str(k), str(v)) for k, v in headers]
    resp.version = aiohttp.HttpVersion11
    resp.status = int(status)
    resp.reason = reason or ""
    resp._headers = CIMultiDictProxy(CIMultiDict(items))
    resp._raw_headers = tuple((k.encode("utf-8"), v.encode("utf-8")) for k, v in items)
    set_cookie = tuple(v for k, v in items if k.lower() == "set-cookie")
    if set_cookie:
        resp._raw_cookie_headers = set_cookie  # what `cookies` (3.14+) and the session jar read

    content = StreamReader(BaseProtocol(loop), limit=2**16, loop=loop)
    if body:
        content.feed_data(body)
    content.feed_eof()
    resp.content = content
    return resp


def _drive(coro: Any) -> Any:
    """Run a coroutine that must complete without suspending (a read of a body that
    is already at EOF) — no event loop required, so the self-check works inside AND
    outside a running loop."""
    try:
        coro.send(None)
    except StopIteration as done:
        return done.value
    coro.close()
    raise RuntimeError("the probe suspended")


def self_check(aiohttp: Any) -> None:
    """Prove the response recipe against the installed aiohttp before patching
    anything: build one buffered response and read it back through aiohttp's own
    ``read()`` / ``json()``. Raises ``RuntimeError`` naming the version otherwise."""
    from yarl import URL

    try:
        running: asyncio.AbstractEventLoop | None = asyncio.get_running_loop()
    except RuntimeError:
        running = None
    loop = running or asyncio.new_event_loop()
    try:
        resp = make_client_response(
            aiohttp,
            session=None,
            method="GET",
            url=URL("https://probe.invalid/knoxcall"),
            request_headers=[("accept", "*/*")],
            status=200,
            reason="OK",
            headers=[("content-type", "application/json"), ("x-probe", "1"), ("set-cookie", "probe=1; Path=/")],
            body=b'{"ok": true}',
            loop=loop,
        )
        assert isinstance(resp, aiohttp.ClientResponse)
        assert resp.status == 200 and resp.ok and resp.reason == "OK"
        assert resp.headers["x-probe"] == "1" and resp.content_type == "application/json"
        assert resp.cookies["probe"].value == "1"
        assert resp.request_info.method == "GET" and str(resp.url) == "https://probe.invalid/knoxcall"
        assert _drive(resp.read()) == b'{"ok": true}'
        assert _drive(resp.json()) == {"ok": True}
        assert _drive(resp.text()) == '{"ok": true}'
        resp.raise_for_status()
        resp.release()
        assert resp.closed
    except Exception as e:  # any shape: a changed constructor, a renamed attribute, a stricter check
        raise RuntimeError(
            f"the 'aiohttp' intercept stack cannot build a ClientResponse on aiohttp "
            f"{getattr(aiohttp, '__version__', '?')} ({type(e).__name__}: {e}); the stack is refused rather than "
            "patched — report this with the aiohttp version"
        ) from e
    finally:
        if running is None:
            loop.close()


async def finish_response(aiohttp: Any, call: AiohttpCall, request: httpx.Request, resp: httpx.Response) -> Any:
    """The pipeline's ``httpx.Response`` → the caller's ``aiohttp.ClientResponse``,
    with the session-level after-effects ``_request`` applies: ``Set-Cookie`` into
    the session's jar, then ``raise_for_status`` (the call's, else the session's)."""
    session = call.session
    out = make_client_response(
        aiohttp,
        session=session,
        method=request.method,
        url=call.url,
        request_headers=request.headers.multi_items(),
        status=resp.status_code,
        reason=resp.reason_phrase,
        headers=resp.headers.multi_items(),
        body=resp.content,
        loop=asyncio.get_running_loop(),
    )
    jar = getattr(session, "cookie_jar", None)
    if jar is not None and out.cookies:
        jar.update_cookies(out.cookies, out.url)
    rfs = call.kwargs.get("raise_for_status")
    if rfs is None:
        rfs = getattr(session, "raise_for_status", None)
    if callable(rfs):
        await rfs(out)
    elif rfs:
        out.raise_for_status()
    return out
