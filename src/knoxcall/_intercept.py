"""The route-aware interception decision table — pure, no I/O.

Python mirror of ``sdk/knoxcall-node/src/intercept-resolver.ts``
(docs/internal/sdk-wrapping/route-aware-interception-plan.md §2.2, PARITY §21).

One request in, one decision out: send it DIRECT (untouched, via the original
transport), through a ROUTE (the manifest says an intercept-enabled Route
covers this host + path; the Route injects the stored secret), or through the
EPHEMERAL proxy (the caller listed the host, no Route covers it; the SDK's own
credential is lifted out-of-band). The order of the rules is the feature: a
listed host silently upgrades from ephemeral to route the moment a Route
covers it, and downgrades back when the Route is disabled.

Every SDK's resolver passes the SAME fixtures — ``sdk/fixtures/intercept-resolver.json``
— so this module is a contract, not a private heuristic. Keep it boring.
"""

from __future__ import annotations

import contextvars
import os
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit

# Marks the SDK's OWN traffic (a reroute's hops, the uncovered-egress report)
# so a process-wide seam in the same context never re-intercepts or observes
# it. Defined here, in the leaf module, so the seams and the reporter share one
# variable without an import cycle.
SUPPRESS: contextvars.ContextVar[bool] = contextvars.ContextVar("knoxcall_intercept_suppress", default=False)

# Stable reason codes, mirrored by every SDK (observability hooks report them).
REASONS = (
    "kill_switch",
    "unparseable",
    "own_host",
    "route_around",
    "outside_context",
    "manifest",
    "no_base_path_match",
    "no_route",
    "unlisted",
)


@dataclass(frozen=True)
class InterceptDecision:
    """What to do with one request."""

    mode: str  # "direct" | "route" | "ephemeral"
    reason: str
    host: str
    slug: str | None = None
    """Route mode: the slug to send as ``x-knoxcall-route``."""
    path: str | None = None
    """Route mode: the rebased path + query to forward."""
    entry: Mapping[str, Any] | None = None
    """Route mode: the manifest entry that matched (carries requires_clients / ambiguous)."""
    route_around_reason: str | None = None


def intercept_kill_switch() -> bool:
    """``KNOXCALL_INTERCEPT=off`` turns every interceptor and route-aware
    transport into pass-through, per request, no deploy."""
    v = os.environ.get("KNOXCALL_INTERCEPT")
    return isinstance(v, str) and v.strip().lower() in ("off", "0", "false")


def normalise_host(hostname: str | None) -> str:
    """Lower-case, trailing dot stripped, IPv6 brackets stripped — PARITY §21's host contract."""
    h = (hostname or "").strip().lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    return h.rstrip(".")


def is_platform_host(host: str) -> bool:
    """KnoxCall's own domains are never intercepted, whatever a manifest or a host list says."""
    return host == "knoxcall.com" or host.endswith(".knoxcall.com")


def rebase_path(request_path: str, base_path: str) -> str | None:
    """The request path with the route's base prefix removed (leading slash
    kept), or ``None`` when the request is not under the base. ``/crm/v3``
    covers ``/crm/v3`` and ``/crm/v3/x``, never ``/crm/v30`` — the boundary is a
    path segment. Mirrors the server's ``rebasePath``."""
    req = request_path or "/"
    if base_path in ("/", ""):
        return req if req.startswith("/") else "/" + req
    if req == base_path:
        return "/"
    if not req.startswith(base_path + "/"):
        return None
    return req[len(base_path):] or "/"


def entries_for_host(manifest: Mapping[str, Any] | None, host: str) -> list[Mapping[str, Any]]:
    """Manifest entries for a host, longest ``base_path`` first, then slug — so
    the first entry whose base covers the path is the longest-prefix,
    lowest-slug match."""
    if not manifest:
        return []
    routes: Iterable[Mapping[str, Any]] = manifest.get("routes") or []
    matched = [e for e in routes if normalise_host(str(e.get("host", ""))) == host]
    return sorted(matched, key=lambda e: (-len(str(e.get("base_path", "/"))), str(e.get("base_path", "/")), str(e.get("slug", ""))))


def resolve_intercept(
    *,
    url: str,
    method: str,
    hosts: "set[str] | frozenset[str] | str",
    manifest: Mapping[str, Any] | None,
    own_hosts: "set[str] | frozenset[str]",
    route_around: Sequence[Any],
    kill_switch: bool,
    require_context: bool,
    in_context: bool,
) -> InterceptDecision:
    """The decision table. ``hosts`` is the caller's explicit host list
    (normalised) or the string ``"all"`` for the explicit-transport form, where
    every request the wrapped SDK makes is by definition one the caller chose to
    send through KnoxCall."""
    if kill_switch:
        return InterceptDecision("direct", "kill_switch", "")

    try:
        u = urlsplit(url)
    except ValueError:
        return InterceptDecision("direct", "unparseable", "")
    if u.scheme not in ("http", "https"):
        return InterceptDecision("direct", "unparseable", "")
    try:
        host = normalise_host(u.hostname)
    except ValueError:
        return InterceptDecision("direct", "unparseable", "")
    if not host:
        return InterceptDecision("direct", "unparseable", "")

    if is_platform_host(host) or host in own_hosts:
        return InterceptDecision("direct", "own_host", host)

    # Function-level import: wrap_transport imports this module.
    from .wrap_transport import match_route_around

    around = match_route_around(url, list(route_around))
    if around is not None:
        return InterceptDecision("direct", "route_around", host, route_around_reason=around.reason)

    if require_context and not in_context:
        return InterceptDecision("direct", "outside_context", host)

    entries = entries_for_host(manifest, host)
    path = u.path or "/"
    for entry in entries:
        rebased = rebase_path(path, str(entry.get("base_path", "/")))
        if rebased is not None:
            full = rebased + ("?" + u.query if u.query else "")
            return InterceptDecision("route", "manifest", host, slug=str(entry["slug"]), path=full, entry=entry)

    listed = hosts == "all" or host in hosts  # type: ignore[operator]
    if listed:
        return InterceptDecision("ephemeral", "no_base_path_match" if entries else "no_route", host)

    return InterceptDecision("direct", "unlisted", host)
