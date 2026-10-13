"""Wrap transport — the data-plane machinery behind ``knox.wrap.transport()``.

Python mirror of ``sdk/knoxcall-node/src/wrap-transport.ts`` (sdk-wrapping PR4).

A wrapped third-party SDK (Stripe, OpenAI, …) keeps its own serialization,
retries, idempotency keys and error types; only its HTTP transport is swapped
for one that re-targets each request through KnoxCall — the ephemeral proxy in
transparent mode by default, or, with ``routes="auto"``, the Route that covers
the request's host + path (route-aware-interception-plan.md, PARITY §21.1).
In Python the seam is **httpx**: most modern SDKs accept
``http_client=httpx.Client(transport=...)`` (or an ``AsyncClient``), so this
module provides a custom :class:`httpx.BaseTransport` and
:class:`httpx.AsyncBaseTransport`.

The provider credential the SDK sets on its ``Authorization`` header is LIFTED
out-of-band (delivered to the upstream by the server, never forwarded as a raw
header, never logged) — or, in escrow mode, replaced by a named escrowed
credential the server resolves and host-pins.

Pure, transport-agnostic helpers (route-around matching, the both-must-agree
sandbox assertion, header filtering) live here so they are unit-testable without
a client; the :class:`WrapResource` methods in ``resources/wrap.py`` wire them
to :meth:`APIClient.ephemeral`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Mapping
from urllib.parse import urlparse

import httpx

from ._egress_observations import EgressObservationReporter, observation_for, observe_uncovered_disabled_by_env
from ._intercept import InterceptDecision, intercept_kill_switch, normalise_host, resolve_intercept
from ._intercept_store import InterceptManifestStore
from .core import SDK_INTERCEPT_ORIGIN
from ._warn import warn_security
from .errors import APIConnectionError, KnoxCallError


class WrapSandboxMismatchError(KnoxCallError):
    """A wrapped provider key's Test/Live prefix disagrees with the client's
    ``sandbox`` flag, a publishable key was supplied, or a caller-supplied
    route-around host is not a bare DNS hostname. Subclass of
    :class:`KnoxCallError` so it is catchable in the SDK error hierarchy."""


# ── Route-around rules ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RouteAroundRule:
    """A rule that sends a matching request DIRECTLY to the provider, untouched.

    ``host`` is an exact lower-case DNS hostname; ``path_prefix`` (optional)
    narrows the rule to a path prefix; ``reason`` is surfaced to the
    ``on_route_around`` hook and docs.
    """

    host: str
    reason: str
    path_prefix: str | None = None


def _coerce_rule(rule: RouteAroundRule | Mapping[str, Any]) -> RouteAroundRule:
    """Accept a :class:`RouteAroundRule` or a plain dict (``host`` / ``reason`` /
    ``path_prefix`` — ``pathPrefix`` also accepted for parity with the Node SDK)."""
    if isinstance(rule, RouteAroundRule):
        return rule
    if isinstance(rule, Mapping):
        return RouteAroundRule(
            host=rule["host"],
            reason=rule.get("reason", ""),
            path_prefix=rule.get("path_prefix", rule.get("pathPrefix")),
        )
    raise TypeError(
        "route_around rules must be RouteAroundRule instances or dicts with "
        "'host'/'reason'(/'path_prefix') keys"
    )


# Built-in route-around defaults. Mirrors the SERVER's raw-PAN refusal
# (src/client-api/ephemeral-proxy.ts PAN_ENDPOINT_DENYLIST) so a wrapped SDK's
# raw-card call is sent straight to Stripe instead of hard-failing on the 403.
DEFAULT_ROUTE_AROUND: list[RouteAroundRule] = [
    RouteAroundRule(
        host="api.stripe.com",
        path_prefix="/v1/tokens",
        reason="raw-card endpoint (PCI): sent direct to the provider",
    ),
    RouteAroundRule(
        host="api.stripe.com",
        path_prefix="/v1/sources",
        reason="raw-card endpoint (PCI): sent direct to the provider",
    ),
]


def _normalize_host(host: str) -> str:
    """Strip a single trailing dot from an FQDN and lower-case it."""
    return host.lower().rstrip(".") if host else ""


def match_route_around(url: str, rules: list[RouteAroundRule]) -> RouteAroundRule | None:
    """First route-around rule matching this URL, or ``None``.

    Trailing-dot FQDNs (``api.stripe.com.``) resolve to the same host but would
    dodge an exact-match rule — both sides are normalized, exactly as the
    server's PAN denylist normalizes ``refusedPanEndpoint``.
    """
    try:
        u = urlparse(url)
    except ValueError:
        return None
    host = _normalize_host(u.hostname or "")
    for r in rules:
        if host != _normalize_host(r.host):
            continue
        if r.path_prefix and not u.path.startswith(r.path_prefix):
            continue
        return r
    return None


def assert_route_around_rules(rules: list[RouteAroundRule]) -> None:
    """Validate caller-supplied route-around rules: a ``host`` that isn't a bare
    DNS hostname (a scheme/port/path slipped in) can never match a parsed
    hostname and would silently disable the rule — fail loud instead. Mirrors
    the escrow allowed-hosts contract."""
    for r in rules:
        h = (r.host or "").strip()
        try:
            parsed = urlparse(f"https://{h}").hostname or ""
        except ValueError:
            parsed = ""
        if not h or _normalize_host(parsed) != _normalize_host(h):
            raise WrapSandboxMismatchError(
                f"Invalid route_around host {r.host!r}: expected a bare DNS "
                "hostname (no scheme, port, or path)."
            )


# ── Both-must-agree sandbox assertion ──────────────────────────────────────────

_PUBLISHABLE_RE = re.compile(r"^pk_(test|live)_")
_SECRET_RE = re.compile(r"^(?:sk|rk)_(test|live)_")
_BEARER_RE = re.compile(r"^Bearer\s+", re.IGNORECASE)


def assert_key_matches_sandbox(authorization_value: str | None, sandbox: bool) -> None:
    """Both-must-agree: a Stripe key's Test/Live prefix must match the KnoxCall
    client's ``sandbox`` flag, so a test key can never be wrapped by a live
    client (or vice versa). Publishable keys (``pk_``) are rejected outright:
    they are not server credentials. Non-Stripe schemes we cannot classify are
    left alone (return without raising).

    ``authorization_value`` is the full header value, e.g. ``"Bearer sk_live_…"``.
    """
    if not authorization_value:
        return
    # Trim BEFORE stripping the scheme: leading whitespace would otherwise stop
    # the anchored ^Bearer from matching, leaving "Bearer sk_live_…" in `token`,
    # which the classifier can't parse — silently skipping the check.
    token = _BEARER_RE.sub("", authorization_value.strip()).strip()
    if _PUBLISHABLE_RE.match(token):
        raise WrapSandboxMismatchError(
            "A Stripe publishable key (pk_…) is not a server credential and cannot "
            "be wrapped. Use a secret (sk_…) or restricted (rk_…) key."
        )
    m = _SECRET_RE.match(token)
    if not m:
        return  # unknown / non-Stripe scheme — nothing to assert
    key_is_test = m.group(1) == "test"
    if key_is_test != sandbox:
        raise WrapSandboxMismatchError(
            f"Provider key is a {'TEST' if key_is_test else 'LIVE'} key but the "
            f"KnoxCall client was constructed with sandbox={sandbox}. Test keys "
            "require sandbox=True, live keys require sandbox=False — construct a "
            "matching client."
        )


# Headers the shim must NOT forward to the upstream: the provider Authorization
# is lifted out-of-band; host/content-length are recomputed by httpx.
DROP_FORWARDED = frozenset({"authorization", "host", "content-length"})

# Response headers dropped when marshalling the ephemeral response back to the
# wrapped SDK: `client.ephemeral()` already DECODED the body, so a surviving
# content-encoding/length would make the SDK's httpx re-decode wrong bytes.
_RESPONSE_DROP = frozenset({"content-encoding", "content-length", "transfer-encoding"})


def forwardable_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """The upstream headers to forward (everything the SDK set except the
    dropped ones — case-insensitive)."""
    return {k: v for k, v in headers.items() if k.lower() not in DROP_FORWARDED}


def _timeout_from(request: httpx.Request) -> float | None:
    """Extract a single local timeout (seconds) from the request's httpx timeout
    extension so the caller's configured timeout is preserved on the proxy call.
    Prefers the ``read`` phase; falls back to the largest defined phase."""
    t = request.extensions.get("timeout")
    if isinstance(t, Mapping):
        read = t.get("read")
        if isinstance(read, (int, float)):
            return float(read)
        vals = [v for v in t.values() if isinstance(v, (int, float))]
        if vals:
            return float(max(vals))
    return None


def _marshal_response(resp: httpx.Response, request: httpx.Request) -> httpx.Response:
    """Rebuild the ephemeral response into a fresh response the wrapped SDK can
    read. Content is already decoded, so encoding/length headers are dropped and
    httpx recomputes the length from ``content``."""
    headers = [
        (k, v) for k, v in resp.headers.multi_items() if k.lower() not in _RESPONSE_DROP
    ]
    return httpx.Response(
        status_code=resp.status_code,
        headers=headers,
        content=resp.content,
        request=request,
    )


# ── Transports ─────────────────────────────────────────────────────────────────

# Observability hook payloads are plain dicts (Pythonic mirror of the Node hooks):
#   on_route_around({"url", "host", "reason"})
#   on_promoted({"host", "slug"})
#   on_reroute({"host", "url", "mode", "slug"?, "reason"})
#   on_refresh({"reason", "version", "added", "removed"})
#   on_unmatched_path({"host", "url"})
#   on_refused({"host", "url", "slug", "status", "redecided"})
#   on_fallback({"host", "url", "error"})
RouteAroundHook = Callable[[dict[str, str]], None]
PromotedHook = Callable[[dict[str, str]], None]
Hook = Callable[[dict[str, Any]], None]


def _is_route_refusal(resp: httpx.Response) -> bool:
    """The route-mode REFUSAL predicate (PARITY §21.1, "Refusal-driven refresh";
    the cross-language contract is ``sdk/fixtures/route-refusal.json``).

    A KnoxCall-origin refusal on the route data plane is the one response the
    interceptor answers by refreshing its manifest ONCE and re-deciding ONCE:

    * a ``401`` with no upstream stamp — the credential was refused, or the
      caller is not authenticated for the route it named. ``call()`` has already
      spent its one re-mint by the time we see this.
    * a ``404`` whose envelope ``error.type`` is ``route_not_found`` — since the
      founder's 2026-09-26 decision an AUTHENTICATED key gets a real 404 for a
      route that does not resolve, and a stale manifest naming a Route that was
      deleted since the poll is exactly this. The ``environment_*`` types are
      refused as-is: a refresh cannot fix an environment.

    Any response carrying ``X-Knox-Upstream-Status`` (the route plane's response
    block) or ``X-Knox-Destination-Status`` (the ephemeral proxy's older spelling)
    is the UPSTREAM's answer, whatever its status or body, and never a refusal.
    """
    if resp.headers.get("x-knox-upstream-status") or resp.headers.get("x-knox-destination-status"):
        return False
    if resp.status_code == 401:
        return True
    if resp.status_code != 404:
        return False
    return _route_refusal_type(resp) == "route_not_found"


def _route_refusal_type(resp: httpx.Response) -> str | None:
    """The envelope's ``error.type`` on a 404, or ``None`` for anything that is
    not the Shape-A envelope ``{"error": {"type", "message", "request_id"}}``."""
    try:
        parsed = resp.json()
    except (ValueError, httpx.ResponseNotRead, httpx.StreamError):
        return None  # not JSON, or a body this predicate may not consume
    if not isinstance(parsed, dict):
        return None
    error = parsed.get("error")
    if not isinstance(error, dict):
        return None
    type_ = error.get("type")
    return type_ if isinstance(type_, str) else None


class _WrapBase:
    """Shared configuration and pre-send planning for the sync/async transports.

    Duck-types its ``client``: it reads ``client.sandbox`` / ``client.base_url`` /
    ``client.proxy_base_url`` / ``client.environment`` when present and awaits
    ``client.ephemeral(...)`` / ``client.call(...)``, so tests can pass a fake
    ephemeral hook in place of a real :class:`APIClient`.

    Route-aware (``routes="auto"``, route-aware-interception-plan.md §2): the
    transport holds an :class:`InterceptManifestStore` and decides each request
    with :func:`resolve_intercept` — ROUTE when a Route covers host + path,
    EPHEMERAL for a listed host no Route covers, DIRECT otherwise. ``hosts`` is
    the caller's explicit list (``"all"`` for an explicit transport, where every
    request is by definition one the caller chose to send through KnoxCall).
    """

    def __init__(
        self,
        client: Any,
        *,
        credential: Mapping[str, Any] | None = None,
        route_around: list[RouteAroundRule | Mapping[str, Any]] | None = None,
        disable_default_route_around: bool = False,
        route: str | None = None,
        auto_switch: bool = False,
        on_route_around: RouteAroundHook | None = None,
        on_promoted: PromotedHook | None = None,
        # ── route-aware ──
        routes: str = "off",
        hosts: Any = "all",
        host_options: Mapping[str, Mapping[str, Any]] | None = None,
        require_context: bool = False,
        in_context: Callable[[], bool] | None = None,
        unavailable: str = "error",
        manifest_fetch: Callable[..., Awaitable[Mapping[str, Any] | None]] | None = None,
        store: InterceptManifestStore | None = None,
        on_reroute: Hook | None = None,
        on_refresh: Hook | None = None,
        on_manifest_error: Callable[[BaseException], None] | None = None,
        on_unmatched_path: Hook | None = None,
        on_refused: Hook | None = None,
        on_fallback: Hook | None = None,
        # ── uncovered-egress observations (PARITY §21.3) ──
        observe_uncovered: bool = True,
        on_observation_flush: Callable[[dict[str, int]], None] | None = None,
        observation_report: ObservationReport | None = None,
        observer: EgressObservationReporter | None = None,
        runner: Callable[[Awaitable[Any]], Any] | None = None,
    ) -> None:
        # Escrow-vs-transit is decided by the credential shape; a malformed
        # `{}` (or `{"secret": ""}`) must NOT silently fall through to transit
        # mode and leak the SDK's raw key — fail loud.
        _check_credential(credential, "wrap")
        for h, o in (host_options or {}).items():
            _check_credential(o.get("credential") if isinstance(o, Mapping) else None, f"intercept host {h}")
        if routes not in ("auto", "off"):
            raise ValueError("routes must be 'auto' or 'off'")
        if unavailable not in ("error", "direct"):
            raise ValueError("unavailable must be 'error' or 'direct'")
        self._client = client
        self._credential = credential
        coerced: list[RouteAroundRule] = [_coerce_rule(r) for r in (route_around or [])]
        if coerced:
            assert_route_around_rules(coerced)
        self._rules: list[RouteAroundRule] = [
            *([] if disable_default_route_around else DEFAULT_ROUTE_AROUND),
            *coerced,
        ]
        self._route = route
        self._auto_switch = auto_switch
        self._on_route_around = on_route_around
        self._on_promoted = on_promoted
        # Per-instance auto-switch memory (host → promoted slug). Client-side and
        # process-local by design — this is the customer's single SDK instance.
        # Kept for callers on `auto_switch=True` from before the manifest
        # existed; consulted only when no manifest entry covers the host.
        self._auto_switched: dict[str, str] = {}

        self._routes = routes
        if hosts == "all":
            self._hosts: Any = "all"
        else:
            self._hosts = frozenset(normalise_host(h) for h in hosts if normalise_host(h))
        self._host_options: dict[str, Mapping[str, Any]] = {
            normalise_host(h): o for h, o in (host_options or {}).items()
        }
        self._require_context = require_context
        self._in_context: Callable[[], bool] = in_context or (lambda: True)
        self._unavailable = unavailable
        self._on_reroute = on_reroute
        self._on_unmatched_path = on_unmatched_path
        self._on_refused = on_refused
        self._on_fallback = on_fallback
        self._unmatched_warned: set[str] = set()

        self._store: InterceptManifestStore | None = None
        if routes == "auto":
            if store is not None:
                self._store = store
            else:
                fetch = manifest_fetch or _default_manifest_fetch(client)
                self._store = InterceptManifestStore(
                    fetch,
                    on_refresh=_wrap_refresh_hook(on_refresh),
                    on_error=on_manifest_error,
                )

        # Uncovered-egress observations (PARITY §21.3). ON by default (founder
        # decision 2026-09-26) for the process-wide interceptor — which hands in
        # its shared `observer` — and for an explicit transport with
        # routes="auto"; `observe_uncovered=False` or the environment turns it
        # off. An explicit transport treats every host as listed, so `unlisted`
        # never occurs there by construction: the reporter exists so the
        # contract (and the opt-out) reads the same in every form.
        self._observer: EgressObservationReporter | None = None
        if observe_uncovered is not False and not observe_uncovered_disabled_by_env():
            if observer is not None:
                self._observer = observer
            elif routes == "auto":
                self._observer = build_observer(
                    client, runner, {"observation_report": observation_report, "on_observation_flush": on_observation_flush}
                )

    # ── route-aware controls ──

    @property
    def store(self) -> InterceptManifestStore | None:
        """The manifest store (``None`` with ``routes="off"``)."""
        return self._store

    def manifest(self) -> Mapping[str, Any] | None:
        """The manifest this transport is deciding on, or ``None``."""
        return self._store.manifest if self._store else None

    async def arefresh(self) -> None:
        """Refresh the manifest now (async; no-op with ``routes="off"``)."""
        if self._store:
            await self._store.arefresh("manual", force=True)

    def stop(self) -> None:
        """Drop the manifest and stop refreshing (and flush the uncovered-egress
        reporter once more). The transport keeps working ephemeral/direct."""
        if self._store:
            self._store.stop()
        if self._observer is not None:
            self._observer.stop()

    @property
    def observer(self) -> EgressObservationReporter | None:
        """The uncovered-egress reporter (``None`` when reporting is off)."""
        return self._observer

    def observe_direct(self, url: str, method: str, headers: Any) -> None:
        """A seam passed this request through untouched: record it when — and
        only when — the decision is DIRECT + ``unlisted`` and it carries a
        credential-bearing header (PARITY §21.3). Runs after the decision,
        before the direct send; never raises into the application's request."""
        obs = self._observer
        if obs is None:
            return
        try:
            d = self._decide_url(url, str(method or "GET").upper())
            if d.mode != "direct" or d.reason != "unlisted":
                return
            rec = observation_for(url, method, headers)
            if rec is not None:
                obs.record(rec)
        except Exception:  # noqa: BLE001 — best-effort: telemetry must never reach the application's request
            pass

    # ── planning ──

    def _own_hosts(self) -> frozenset[str]:
        out: set[str] = set()
        for attr in ("base_url", "proxy_base_url"):
            u = getattr(self._client, attr, None)
            if isinstance(u, str) and u:
                try:
                    h = normalise_host(urlparse(u).hostname)
                except ValueError:
                    h = ""
                if h:
                    out.add(h)
        return frozenset(out)

    def _decide(self, request: httpx.Request) -> InterceptDecision:
        return self._decide_url(str(request.url), request.method.upper())

    def _decide_url(self, url: str, method: str) -> InterceptDecision:
        return resolve_intercept(
            url=url,
            method=method,
            hosts=self._hosts,
            manifest=self._store.manifest if self._store else None,
            own_hosts=self._own_hosts(),
            route_around=self._rules,
            kill_switch=intercept_kill_switch(),
            require_context=self._require_context,
            in_context=self._in_context(),
        )

    def _plan(self, request: httpx.Request) -> tuple[str, Any, InterceptDecision]:
        """Decide, WITHOUT reading the body or performing I/O, how to send this
        request. Returns ``(kind, data, decision)`` where kind is ``"direct"``
        (data = the matched route-around rule or ``None``), ``"route"`` (data =
        ``(slug, method, path, headers)``) or ``"ephemeral"`` (data =
        ``(url, ephemeral_kwargs)``). Callers with ``routes="auto"`` must have
        refreshed the store first (``aensure``)."""
        decision = self._decide(request)
        url = str(request.url)
        method = request.method.upper()
        headers = {k.lower(): v for k, v in request.headers.items()}

        if decision.mode == "direct":
            rule = None
            if decision.reason == "route_around":
                rule = match_route_around(url, self._rules)
            elif decision.reason == "unlisted" and self._observer is not None:
                try:
                    rec = observation_for(url, method, headers)
                    if rec is not None:
                        self._observer.record(rec)
                except Exception:  # noqa: BLE001 — best-effort telemetry
                    pass
            return "direct", rule, decision

        fwd = forwardable_headers(headers)
        host = decision.host

        # Explicit `route` (legacy) wins for every non-direct request, with the
        # full path — exactly as before the manifest existed. Then the manifest.
        # Then the legacy auto-switch memory.
        if self._route:
            return "route", (self._route, method, _full_path(request), fwd), decision
        if decision.mode == "route":
            return "route", (decision.slug, method, decision.path, fwd), decision
        legacy = self._auto_switched.get(host) if self._auto_switch else None
        if legacy:
            return "route", (legacy, method, _full_path(request), fwd), decision

        # Ephemeral (transparent) mode.
        host_opts = self._host_options.get(host, {})
        credential = host_opts.get("credential") if isinstance(host_opts, Mapping) else None
        credential = credential if credential is not None else self._credential
        kwargs: dict[str, Any] = {"method": method, "headers": fwd, "mode": "transparent"}
        if credential is not None:
            # Escrow mode — the raw key never travels.
            kwargs["upstream_auth_secret"] = credential["secret"]
            scheme = credential.get("scheme")
            if scheme is not None:
                kwargs["upstream_auth_scheme"] = scheme
        else:
            # Transit mode — lift the SDK's own Authorization header out-of-band.
            auth = headers.get("authorization")
            assert_key_matches_sandbox(auth, bool(getattr(self._client, "sandbox", False)))
            if auth is not None:
                kwargs["upstream_authorization"] = auth
        return "ephemeral", (url, kwargs), decision

    # ── hooks ──

    def _fire_route_around(self, request: httpx.Request, rule: RouteAroundRule | None) -> None:
        if rule is not None and self._on_route_around is not None:
            self._on_route_around(
                {"url": str(request.url), "host": normalise_host(request.url.host), "reason": rule.reason}
            )

    def _fire_reroute(self, request: httpx.Request, mode: str, decision: InterceptDecision, slug: str | None) -> None:
        if self._on_reroute is not None:
            info: dict[str, Any] = {"host": decision.host, "url": str(request.url), "mode": mode, "reason": decision.reason}
            if slug:
                info["slug"] = slug
            self._on_reroute(info)

    def _note_unmatched(self, request: httpx.Request, decision: InterceptDecision) -> None:
        if decision.reason != "no_base_path_match" or self._on_unmatched_path is None:
            return
        first = "/".join((request.url.path or "/").split("/")[:2])
        key = f"{decision.host} {first}"
        if key in self._unmatched_warned:
            return
        self._unmatched_warned.add(key)
        self._on_unmatched_path({"host": decision.host, "url": str(request.url)})

    def _note_promoted(self, resp: httpx.Response, host: str) -> None:
        # Promoted-route hint (PR6): a Route now covers this host. With a
        # manifest, the hint is a signal to refresh it — the manifest is the
        # truth. Without one (legacy `auto_switch`), remember the slug directly.
        slug = resp.headers.get("x-knox-promoted-route")
        if slug and host:
            if self._on_promoted is not None:
                self._on_promoted({"host": host, "slug": slug})
            if self._store is not None:
                self._store.hint()
            elif self._auto_switch:
                self._auto_switched[host] = slug

    def _can_fall_back(self, decision: InterceptDecision, kwargs: Mapping[str, Any]) -> bool:
        # D4: fail closed by default. `unavailable="direct"` is honoured only
        # for TRANSIT traffic — the key is in the process there. Escrow and
        # route mode have nothing to go direct with.
        host_opts = self._host_options.get(decision.host, {})
        policy = host_opts.get("unavailable") if isinstance(host_opts, Mapping) else None
        policy = policy or self._unavailable
        return policy == "direct" and "upstream_auth_secret" not in kwargs

    def _fire_fallback(self, request: httpx.Request, decision: InterceptDecision, err: BaseException) -> None:
        if self._on_fallback is not None:
            self._on_fallback({"host": decision.host, "url": str(request.url), "error": err})

    def _fire_refused(self, request: httpx.Request, decision: InterceptDecision, slug: str, status: int, redecided: str | None) -> None:
        if self._on_refused is not None:
            self._on_refused({"host": decision.host, "url": str(request.url), "slug": slug, "status": status, "redecided": redecided})


def _check_credential(credential: Any, where: str) -> None:
    if credential is None:
        return
    secret = credential.get("secret") if isinstance(credential, Mapping) else None
    if not isinstance(secret, str) or secret == "":
        raise TypeError(
            f"{where} credential must be {{'secret': <non-empty string>}} for "
            "escrow mode; omit `credential` entirely for transit mode."
        )


def _full_path(request: httpx.Request) -> str:
    path = request.url.path or "/"
    if request.url.query:
        path = path + "?" + request.url.query.decode("ascii")
    return path


ObservationReport = Callable[[list[dict[str, Any]]], Awaitable[Mapping[str, Any]]]


def _default_observation_report(client: Any) -> ObservationReport | None:
    wrap = getattr(client, "wrap", None)
    report = getattr(wrap, "report_egress_observations", None)
    if report is None:
        return None  # a duck-typed client with nothing to report to

    async def _report(observations: list[dict[str, Any]]) -> Mapping[str, Any]:
        return await report(observations)

    return _report


def build_observer(client: Any, runner: Callable[[Awaitable[Any]], Any] | None, opts: Mapping[str, Any]) -> EgressObservationReporter | None:
    """The uncovered-egress reporter for a transport or handle, or ``None`` when
    reporting is off (``observe_uncovered=False``, ``KNOXCALL_OBSERVE_UNCOVERED=off``,
    or a client with no ``wrap.report_egress_observations``)."""
    if opts.get("observe_uncovered", True) is False or observe_uncovered_disabled_by_env():
        return None
    report = opts.get("observation_report") or _default_observation_report(client)
    if report is None:
        return None
    return EgressObservationReporter(report, runner=runner, on_flush=opts.get("on_observation_flush"))


def _default_manifest_fetch(client: Any) -> Callable[..., Awaitable[Mapping[str, Any] | None]]:
    wrap = getattr(client, "wrap", None)
    fetch = getattr(wrap, "intercept_manifest", None)
    if fetch is None:
        raise TypeError("routes='auto' needs a KnoxCall client (with wrap.intercept_manifest) or a manifest_fetch=")
    env = getattr(client, "environment", None)

    async def _fetch(*, if_none_match: str | None = None) -> Mapping[str, Any] | None:
        # The store passes the version it holds; the resource sends it as the
        # server's weak ETag and maps a 304 to None (PARITY §21.1).
        kwargs: dict[str, Any] = {}
        if env:
            kwargs["environment"] = env
        if if_none_match is not None:
            kwargs["if_none_match"] = if_none_match
        return await fetch(**kwargs)

    return _fetch


def _wrap_refresh_hook(user_hook: Hook | None) -> Hook:
    """Warn once per route about `requires_clients` and ambiguity, then call the user's hook."""

    def _hook(info: dict[str, Any]) -> None:
        for e in info.get("added", []):
            if e.get("requires_clients"):
                warn_security(
                    f"KnoxCall route \"{e.get('slug')}\" ({e.get('host')}{e.get('base_path')}) requires a registered "
                    "client; a bearer-only SDK call will be refused (403). Register this process as a client of the "
                    "route, or leave the route out of interception."
                )
            if e.get("ambiguous"):
                warn_security(
                    f"KnoxCall: more than one intercept-enabled route covers {e.get('host')}{e.get('base_path')}; "
                    "the lexically lowest slug is used. Disable the others."
                )
        if user_hook is not None:
            user_hook(info)

    return _hook


class KnoxWrapAsyncTransport(_WrapBase, httpx.AsyncBaseTransport):
    """An :class:`httpx.AsyncBaseTransport` that routes a wrapped async SDK's
    requests through KnoxCall. Hand it to any SDK that accepts
    ``http_client=httpx.AsyncClient(transport=...)``. Ephemeral by default;
    route-aware with ``routes="auto"``."""

    def __init__(
        self,
        client: Any,
        *,
        direct_transport: httpx.AsyncBaseTransport | None = None,
        **opts: Any,
    ) -> None:
        _WrapBase.__init__(self, client, **opts)
        # Transport used for route-around / direct calls — pinned so they never
        # recurse back through KnoxCall. Injected in tests.
        self._direct: httpx.AsyncBaseTransport = direct_transport or httpx.AsyncHTTPTransport()

    async def ready(self) -> None:
        """Load the manifest once (no-op with ``routes="off"``). Never raises."""
        if self._store is not None:
            await self._store.aensure()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if self._store is not None:
            await self._store.aensure()
        kind, data, decision = self._plan(request)
        if kind == "direct":
            self._fire_route_around(request, data)
            # Forward the ORIGINAL request untouched — body/headers intact.
            return await self._direct.handle_async_request(request)

        timeout = _timeout_from(request)
        raw = await request.aread()
        body = raw if raw else None

        if kind == "route":
            slug, method, path, fwd = data
            self._fire_reroute(request, "route", decision, slug)
            resp = await self._client.call(slug, method=method, path=path, headers=fwd, body=body, timeout=timeout, _origin=SDK_INTERCEPT_ORIGIN)
            if self._store is not None and decision.mode == "route" and _is_route_refusal(resp):
                # Stale manifest or refused credential — one refresh tells them
                # apart (PARITY §21). Re-decide once; resend only if the answer
                # changed (the refusal was answered before any upstream contact).
                await self._store.arefresh("route_refused", force=True)
                kind2, data2, decision2 = self._plan(request)
                changed = kind2 != "route" or data2[0] != slug or data2[2] != path
                self._fire_refused(request, decision, slug, resp.status_code, kind2 if changed else None)
                if changed:
                    if kind2 == "route":
                        slug2, method2, path2, fwd2 = data2
                        resp = await self._client.call(slug2, method=method2, path=path2, headers=fwd2, body=body, timeout=timeout, _origin=SDK_INTERCEPT_ORIGIN)
                    elif kind2 == "ephemeral":
                        return await self._send_ephemeral(request, data2, decision2, body, timeout)
                    else:
                        return await self._direct.handle_async_request(request)
            return _marshal_response(resp, request)

        return await self._send_ephemeral(request, data, decision, body, timeout)

    async def _send_ephemeral(self, request: httpx.Request, data: Any, decision: InterceptDecision, body: Any, timeout: float | None) -> httpx.Response:
        url, kwargs = data
        self._note_unmatched(request, decision)
        self._fire_reroute(request, "ephemeral", decision, None)
        try:
            resp = await self._client.ephemeral(url, body=body, timeout=timeout, **kwargs)
        except APIConnectionError as err:
            if self._can_fall_back(decision, kwargs):
                self._fire_fallback(request, decision, err)
                return await self._direct.handle_async_request(request)
            raise
        self._note_promoted(resp, decision.host)
        return _marshal_response(resp, request)


class KnoxWrapTransport(_WrapBase, httpx.BaseTransport):
    """An :class:`httpx.BaseTransport` (synchronous) that routes a wrapped SDK's
    requests through KnoxCall. Hand it to any SDK that accepts
    ``http_client=httpx.Client(transport=...)``.

    ``client.ephemeral()`` is async, so a ``runner`` is required that drives a
    coroutine to completion synchronously (the sync facade supplies its
    background-event-loop runner)."""

    def __init__(
        self,
        client: Any,
        runner: Callable[[Awaitable[Any]], Any],
        *,
        direct_transport: httpx.BaseTransport | None = None,
        **opts: Any,
    ) -> None:
        _WrapBase.__init__(self, client, runner=runner, **opts)
        self._runner = runner
        self._direct: httpx.BaseTransport = direct_transport or httpx.HTTPTransport()

    def ready(self) -> None:
        """Load the manifest once (no-op with ``routes="off"``). Never raises."""
        if self._store is not None:
            self._runner(self._store.aensure())

    def refresh(self) -> None:
        """Refresh the manifest now (no-op with ``routes="off"``)."""
        if self._store is not None:
            self._runner(self._store.arefresh("manual", force=True))

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if self._store is not None:
            self._runner(self._store.aensure())
        kind, data, decision = self._plan(request)
        if kind == "direct":
            self._fire_route_around(request, data)
            return self._direct.handle_request(request)

        timeout = _timeout_from(request)
        raw = request.read()
        body = raw if raw else None

        if kind == "route":
            slug, method, path, fwd = data
            self._fire_reroute(request, "route", decision, slug)
            resp = self._runner(self._client.call(slug, method=method, path=path, headers=fwd, body=body, timeout=timeout, _origin=SDK_INTERCEPT_ORIGIN))
            if self._store is not None and decision.mode == "route" and _is_route_refusal(resp):
                self._runner(self._store.arefresh("route_refused", force=True))
                kind2, data2, decision2 = self._plan(request)
                changed = kind2 != "route" or data2[0] != slug or data2[2] != path
                self._fire_refused(request, decision, slug, resp.status_code, kind2 if changed else None)
                if changed:
                    if kind2 == "route":
                        slug2, method2, path2, fwd2 = data2
                        resp = self._runner(self._client.call(slug2, method=method2, path=path2, headers=fwd2, body=body, timeout=timeout, _origin=SDK_INTERCEPT_ORIGIN))
                    elif kind2 == "ephemeral":
                        return self._send_ephemeral(request, data2, decision2, body, timeout)
                    else:
                        return self._direct.handle_request(request)
            return _marshal_response(resp, request)

        return self._send_ephemeral(request, data, decision, body, timeout)

    def _send_ephemeral(self, request: httpx.Request, data: Any, decision: InterceptDecision, body: Any, timeout: float | None) -> httpx.Response:
        url, kwargs = data
        self._note_unmatched(request, decision)
        self._fire_reroute(request, "ephemeral", decision, None)
        try:
            resp = self._runner(self._client.ephemeral(url, body=body, timeout=timeout, **kwargs))
        except APIConnectionError as err:
            if self._can_fall_back(decision, kwargs):
                self._fire_fallback(request, decision, err)
                return self._direct.handle_request(request)
            raise
        self._note_promoted(resp, decision.host)
        return _marshal_response(resp, request)
