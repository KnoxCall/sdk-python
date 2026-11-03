"""Uncovered-egress observations (PARITY §21.3; founder decisions 2026-09-26).

Python mirror of ``sdk/knoxcall-node/src/egress-observations.ts``.

A route-aware interceptor sees every outbound request the process makes and
sends only the covered ones through KnoxCall. The rest go direct — and among
them are calls that carry a credential the platform does not hold:
"uncovered egress". This module records those (host, first path segment,
method, credential header NAME) in memory and reports the aggregate to
``POST /v1/wrap/egress-observations``, so the dashboard can show a tenant
which credentials are still leaving their process un-custodied.

What is recorded is bounded on purpose, and the bound is the feature:

- names, never values — the credential header's NAME, never its value;
- the FIRST path segment only — never the query string, never the body,
  never a deeper path;
- counts per (host, segment, method, header) with first/last seen.

Only a DIRECT decision with reason ``unlisted`` is observed. ``own_host``,
``route_around``, ``kill_switch``, ``outside_context`` and ``unparseable``
are never reported.

Nothing here may add latency to, throw into, or alter the application's
request: :meth:`EgressObservationReporter.record` is synchronous and cheap,
the flush runs on a daemon timer thread (sync facade) or as a task on the
caller's loop (async facade), and every failure is swallowed after one
warning. The reporter is process memory only.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import random
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Iterable, Mapping
from urllib.parse import unquote, urlsplit

from ._intercept import SUPPRESS, normalise_host
from ._warn import warn_security
from .errors import PermissionDeniedError

# Header names (lower-case) that carry a credential. The shared fixture
# (sdk/fixtures/egress-observation.json) pins this list.
CREDENTIAL_HEADER_ALLOWLIST: tuple[str, ...] = (
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "apikey",
    "x-apikey",
    "x-auth-token",
    "x-access-token",
    "x-token",
    "token",
    "x-secret",
    "x-secret-key",
    "x-client-secret",
    "ocp-apim-subscription-key",
    "x-goog-api-key",
    "x-amz-security-token",
    "x-shopify-access-token",
    "klaviyo-api-key",
    "x-hubspot-api-key",
)

# A lower-cased header name ending in one of these also counts.
CREDENTIAL_HEADER_SUFFIXES: tuple[str, ...] = ("-api-key", "-token", "-secret", "-auth")

# The methods the server accepts (upper-case); anything else is `invalid_method`.
OBSERVATION_METHODS: tuple[str, ...] = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE")

_ALLOWLIST_INDEX = {name: i for i, name in enumerate(CREDENTIAL_HEADER_ALLOWLIST)}
# The server's shape check (src/wrap/egress-observations.ts).
_HEADER_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
_MAX_HEADER_NAME_LENGTH = 64
_FIRST_SEGMENT_RE = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%-]{0,255}$")

DEFAULT_FLUSH_INTERVAL = 60.0
DEFAULT_FLUSH_AT_KEYS = 200
DEFAULT_MAX_KEYS = 1_000
DEFAULT_MAX_PER_REQUEST = 200


def is_credential_header_name(name: str | None) -> bool:
    """Whether a header NAME (any casing) is credential-bearing."""
    n = (name or "").strip().lower()
    if not n or len(n) > _MAX_HEADER_NAME_LENGTH or not _HEADER_NAME_RE.match(n):
        return False
    if n in _ALLOWLIST_INDEX:
        return True
    return any(len(n) > len(s) and n.endswith(s) for s in CREDENTIAL_HEADER_SUFFIXES)


def _items(headers: Any) -> Iterable[tuple[Any, Any]]:
    if headers is None:
        return ()
    if hasattr(headers, "items"):
        return headers.items()
    return headers


def credential_header_name(headers: Any) -> str | None:
    """The credential header NAME to report for a request, or ``None``.

    Allowlist entries win in allowlist order; then the lexicographically
    smallest suffix match. A header whose value is empty after trimming never
    counts. Only names are read — values are looked at solely to discard
    empties and are never returned.
    """
    best: str | None = None
    best_rank = len(CREDENTIAL_HEADER_ALLOWLIST) + 1
    best_suffix: str | None = None
    for raw_name, raw_value in _items(headers):
        name = str(raw_name or "").strip().lower()
        if not name:
            continue
        value = raw_value.decode("latin-1", "replace") if isinstance(raw_value, (bytes, bytearray)) else str(raw_value or "")
        if value.strip() == "":
            continue
        rank = _ALLOWLIST_INDEX.get(name)
        if rank is not None:
            if rank < best_rank:
                best_rank = rank
                best = name
            continue
        if is_credential_header_name(name):
            if best_suffix is None or name < best_suffix:
                best_suffix = name
    return best if best is not None else best_suffix


# ── a credential in the first path segment (server #1022) ───────────────────
# Some APIs put a credential in the path (Telegram's `/bot<id>:<secret>/...`).
# The server stores such a segment as `/`; the SDK applies the SAME rule
# before sending, so the value never leaves the process.

MAX_PLAIN_FIRST_SEGMENT_LENGTH = 64

_CREDENTIAL_SEGMENT_PREFIXES = tuple(re.compile(p) for p in (
    r"(?i)^bot\d+:",
    r"(?i)^(sk|pk|rk)_(live|test)_",
    r"^sk-",
    r"^xox[abposr]-",
    r"^gh[pousr]_",
    r"^github_pat_",
    r"^glpat-",
    r"^shp(at|ca|pa|ss)_",
    r"^(AKIA|ASIA)[0-9A-Z]{12,}",
    r"^AIza[0-9A-Za-z_-]{20,}",
    r"^eyJ[A-Za-z0-9_-]{8,}",
    r"^SG\.",
))
_HIGH_ENTROPY_RUN_RE = re.compile(r"[A-Za-z0-9_-]{24,}")


def _mixes_classes(run: str) -> bool:
    return sum(1 for p in (r"[a-z]", r"[A-Z]", r"[0-9]") if re.search(p, run)) >= 2


def first_segment_looks_like_credential(first_segment: str) -> bool:
    """Whether a first segment (``/`` + one segment) looks like it carries a
    credential — the server's rule, on the raw and percent-decoded forms."""
    raw = (first_segment or "")[1:] if (first_segment or "").startswith("/") else (first_segment or "")
    if not raw:
        return False
    for s in {raw, unquote(raw)}:
        if len(s) > MAX_PLAIN_FIRST_SEGMENT_LENGTH:
            return True
        if any(p.search(s) for p in _CREDENTIAL_SEGMENT_PREFIXES):
            return True
        if any(_mixes_classes(run) for run in _HIGH_ENTROPY_RUN_RE.findall(s)):
            return True
    return False


def observation_first_segment(url: str) -> str:
    """``/`` or ``/<first path segment>`` of the URL — never the query, never deeper."""
    try:
        path = urlsplit(url).path or "/"
    except ValueError:
        return "/"
    # Exactly ONE leading slash is consumed: `//double` has an empty first
    # segment and reports `/` (str.lstrip would eat both and report `/double`).
    seg = (path[1:] if path.startswith("/") else path).split("/", 1)[0]
    return "/" + seg


def observation_for(url: str, method: str, headers: Any) -> dict[str, str] | None:
    """The whole classifier, pure: the four identifying fields for this request,
    or ``None`` when it carries no credential-bearing header. The caller has
    ALREADY decided the request is direct + ``unlisted``."""
    try:
        parts = urlsplit(url)
        host = normalise_host(parts.hostname)
    except ValueError:
        return None
    if not host or _is_ip(host):
        return None  # an IP literal is never a Route target; the server drops it (`ip_literal`)
    upper = str(method or "GET").upper()
    if upper not in OBSERVATION_METHODS:
        return None
    segment = observation_first_segment(url)
    if first_segment_looks_like_credential(segment):
        segment = "/"  # reported as `/`; the entry is kept
    if not _FIRST_SEGMENT_RE.match(segment):
        return None
    name = credential_header_name(headers)
    if name is None:
        return None
    return {"host": host, "first_segment": segment, "method": upper, "header_name": name}


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def observe_uncovered_disabled_by_env() -> bool:
    """``KNOXCALL_OBSERVE_UNCOVERED=off|false|0`` turns the reporter off (read when a transport is built)."""
    v = os.environ.get("KNOXCALL_OBSERVE_UNCOVERED")
    return isinstance(v, str) and v.strip().lower() in ("off", "0", "false")


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{int((ts % 1) * 1000):03d}Z"


ReportFn = Callable[[list[dict[str, Any]]], Awaitable[Mapping[str, Any]]]
FlushHook = Callable[[dict[str, int]], None]


class EgressObservationReporter:
    """In-memory aggregation of uncovered-egress observations for ONE handle /
    transport, flushed in the background. Bounded; never raises.

    ``runner`` is the sync facade's bridge (drives a coroutine to completion
    on the SDK's loop thread); with it the timer is a daemon
    :class:`threading.Timer` and the immediate flush a daemon thread. Without
    it (the async facade) the timer is ``loop.call_later`` on the loop that was
    running when the observation was recorded, and flushes are tasks on it —
    neither keeps a process alive.
    """

    def __init__(
        self,
        report: ReportFn,
        *,
        runner: Callable[[Awaitable[Any]], Any] | None = None,
        on_flush: FlushHook | None = None,
        flush_interval: float = DEFAULT_FLUSH_INTERVAL,
        flush_at_keys: int = DEFAULT_FLUSH_AT_KEYS,
        max_keys: int = DEFAULT_MAX_KEYS,
        max_per_request: int = DEFAULT_MAX_PER_REQUEST,
        now: Callable[[], float] = time.time,
        rand: Callable[[], float] = random.random,
    ) -> None:
        self._report = report
        self._runner = runner
        self._on_flush = on_flush
        self._interval = flush_interval
        self._flush_at = flush_at_keys
        self._max_keys = max_keys
        self._max_per_request = max_per_request
        self._now = now
        self._rand = rand
        self._lock = threading.Lock()
        self._buffer: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        self._timer: threading.Timer | None = None
        self._loop_timer: asyncio.TimerHandle | None = None
        self._flushing = False
        self._stopped = False
        self._forbidden = False
        self._warned_overflow = False
        self._warned_failed = False

    # ── state ──────────────────────────────────────────────────────────────

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._buffer)

    @property
    def stopped(self) -> bool:
        return self._stopped

    @property
    def forbidden(self) -> bool:
        """True once the endpoint answered 403: reporting is off for the life of this reporter."""
        return self._forbidden

    def pending(self) -> list[dict[str, Any]]:
        """The observations that would be sent now (a copy)."""
        with self._lock:
            return [self._wire(e) for e in self._buffer.values()]

    # ── record ─────────────────────────────────────────────────────────────

    def record(self, obs: Mapping[str, str]) -> None:
        """Record one uncovered credentialed call. Synchronous, never raises."""
        if self._stopped or self._forbidden:
            return
        key = (obs["host"], obs["first_segment"], obs["method"], obs["header_name"])
        at = self._now()
        flush_now = False
        arm = False
        with self._lock:
            hit = self._buffer.get(key)
            if hit is not None:
                hit["count"] += 1
                hit["last_seen"] = at
                return
            if len(self._buffer) >= self._max_keys:
                if not self._warned_overflow:
                    self._warned_overflow = True
                    warn_security(
                        f"KnoxCall: more than {self._max_keys} distinct uncovered-egress observations are pending; "
                        "new ones are dropped until the next flush."
                    )
                return
            self._buffer[key] = {
                "host": key[0], "first_segment": key[1], "method": key[2], "header_name": key[3],
                "count": 1, "first_seen": at, "last_seen": at,
            }
            if len(self._buffer) >= self._flush_at:
                flush_now = True
            else:
                arm = True
        if flush_now:
            self._flush_soon()
        elif arm:
            self._arm()

    # ── flush ──────────────────────────────────────────────────────────────

    async def aflush(self) -> None:
        """Send what is pending now. A concurrent flush returns immediately. Never raises."""
        if self._flushing:
            return
        self._flushing = True
        try:
            await self._do_flush()
        except BaseException:  # noqa: BLE001 — telemetry never surfaces
            pass
        finally:
            self._flushing = False

    async def _do_flush(self) -> None:
        self._cancel_timers()
        if self._forbidden:
            return
        with self._lock:
            if not self._buffer:
                return
            batch = [self._wire(e) for e in self._buffer.values()]
            self._buffer.clear()
        token = SUPPRESS.set(True)
        try:
            for i in range(0, len(batch), self._max_per_request):
                chunk = batch[i : i + self._max_per_request]
                try:
                    res = await self._report(chunk)
                except PermissionDeniedError:
                    # The key lacks `routes:read`: reporting is off for good.
                    self._forbidden = True
                    with self._lock:
                        self._buffer.clear()
                    warn_security(
                        "KnoxCall: the credential cannot report uncovered-egress observations (HTTP 403 — it lacks "
                        "`routes:read`); reporting is off for this interceptor. Grant the scope, or pass "
                        "observe_uncovered=False to silence this."
                    )
                    return
                except BaseException:  # noqa: BLE001 — best-effort: the batch is dropped, never retried in a loop
                    if not self._warned_failed:
                        self._warned_failed = True
                        warn_security("KnoxCall: reporting uncovered-egress observations failed; the batch was dropped.")
                    return
                if self._on_flush is not None:
                    try:
                        self._on_flush({"accepted": int(res.get("accepted", 0) or 0), "dropped": int(res.get("dropped", 0) or 0)})
                    except Exception:  # noqa: BLE001 — a caller's hook must never break the reporter
                        pass
        finally:
            SUPPRESS.reset(token)

    def flush(self) -> None:
        """Synchronous flush through the runner (sync facade only; a no-op without one)."""
        if self._runner is not None:
            try:
                self._runner(self.aflush())
            except Exception:  # noqa: BLE001 — the client may already be closed
                pass

    def stop(self) -> None:
        """Stop the timer and flush once more (synchronously through the runner;
        as a task on the running loop otherwise). Idempotent."""
        if self._stopped:
            return
        self._stopped = True
        self._cancel_timers()
        if self._runner is not None:
            self.flush()
            return
        try:
            asyncio.get_running_loop().create_task(self.aflush())
        except RuntimeError:
            # No loop to flush on: whatever is pending is lost — process memory only.
            pass

    async def astop(self) -> None:
        """Stop the timer and await the final flush (async facade)."""
        if self._stopped:
            return
        self._stopped = True
        self._cancel_timers()
        await self.aflush()

    # ── scheduling ─────────────────────────────────────────────────────────

    def _delay(self) -> float:
        return max(0.001, self._interval * (1 + (self._rand() * 0.2 - 0.1)))  # ±10 %

    def _arm(self) -> None:
        if self._stopped:
            return
        if self._runner is not None:
            with self._lock:
                if self._timer is not None:
                    return
                t = threading.Timer(self._delay(), self._timer_fired)
                t.daemon = True
                self._timer = t
            t.start()
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return  # no loop here: the 200-key and stop() flushes still apply
        with self._lock:
            if self._loop_timer is not None:
                return
            self._loop_timer = loop.call_later(self._delay(), self._loop_timer_fired, loop)

    def _timer_fired(self) -> None:
        with self._lock:
            self._timer = None
        self.flush()

    def _loop_timer_fired(self, loop: asyncio.AbstractEventLoop) -> None:
        with self._lock:
            self._loop_timer = None
        try:
            loop.create_task(self.aflush())
        except RuntimeError:
            pass

    def _flush_soon(self) -> None:
        if self._runner is not None:
            threading.Thread(target=self.flush, name="knoxcall-egress-observations", daemon=True).start()
            return
        try:
            asyncio.get_running_loop().create_task(self.aflush())
        except RuntimeError:
            pass

    def _cancel_timers(self) -> None:
        with self._lock:
            t, self._timer = self._timer, None
            lt, self._loop_timer = self._loop_timer, None
        if t is not None:
            t.cancel()
        if lt is not None:
            lt.cancel()

    @staticmethod
    def _wire(e: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "host": e["host"],
            "first_segment": e["first_segment"],
            "method": e["method"],
            "header_name": e["header_name"],
            "count": e["count"],
            "first_seen": _iso(e["first_seen"]),
            "last_seen": _iso(e["last_seen"]),
        }
