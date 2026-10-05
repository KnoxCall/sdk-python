"""The SDK-side copy of the intercept manifest — fetched, held, refreshed
(route-aware-interception-plan.md §2.5). One per transport/interceptor;
process memory only; dropped on ``stop()``.

Python idiom (PARITY §21.1): the manifest is refreshed LAZILY at the TTL —
the first request after ``ttl_seconds`` pays one management call — rather
than by a background timer. That is behaviourally the same contract ("hold
the manifest for ttl_seconds, then refresh") and it works identically under
the sync facade (whose I/O runs on a dedicated loop thread), a caller's own
event loop, a forked worker and a WSGI process, with no thread to own.

- single-flight: concurrent refreshes share one fetch (an ``asyncio.Lock``
  on the loop the client's I/O runs on);
- stale-but-valid: a failed refresh keeps the last GOOD manifest and backs off
  exponentially from the second consecutive failure (cap 8×TTL);
- a 401/403/404 from the manifest endpoint — the credential lacks
  ``routes:read``, or an older server — is NOT a routing failure: the store
  warns once, behaves as "no manifest" (every listed host stays on the
  ephemeral path exactly as before this feature), and re-checks at 10×TTL;
- out-of-cycle refreshes (a route-mode refusal, a promoted-route hint, an
  explicit ``refresh()``) are rate-limited so a burst costs one call.

Discovery failing open is deliberate and bounded: it can only leave a host on
the path it was on before the manifest existed. The DATA-PLANE hop is where
fail-closed lives (D4), and that is in ``wrap_transport.py``.
"""

from __future__ import annotations

import asyncio
import inspect
import time
from typing import Any, Awaitable, Callable, Mapping

from .errors import KnoxCallError
from ._warn import warn_security

DEFAULT_TTL_SECONDS = 60
MAX_BACKOFF_FACTOR = 8
PERMISSION_RECHECK_FACTOR = 10

RefreshHook = Callable[[dict[str, Any]], None]
ErrorHook = Callable[[BaseException], None]


def _entry_key(e: Mapping[str, Any]) -> str:
    return f"{e.get('host')}\x00{e.get('base_path')}\x00{e.get('slug')}"


def _accepts_if_none_match(fetch: Callable[..., Any]) -> bool:
    """Whether ``fetch`` can take ``if_none_match=`` (named, or via ``**kwargs``).
    Decided once at construction so a zero-argument test/user seam keeps working."""
    try:
        params = inspect.signature(fetch).parameters
    except (TypeError, ValueError):
        return False
    if "if_none_match" in params:
        return params["if_none_match"].kind in (
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        )
    return any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())


class InterceptManifestStore:
    """Holds the manifest and decides when it is stale. See the module doc."""

    def __init__(
        self,
        fetch: Callable[..., Awaitable[Mapping[str, Any] | None]],
        *,
        on_refresh: RefreshHook | None = None,
        on_error: ErrorHook | None = None,
        min_refresh_gap: float = 5.0,
        now: Callable[[], float] = time.monotonic,
    ) -> None:
        """``fetch`` performs ``GET /v1/wrap/intercept-manifest``. When it accepts
        an ``if_none_match`` keyword the store passes the version it holds on
        every poll after the first (``If-None-Match: W/"<version>"`` on the
        wire) and reads ``None`` as the server's ``304``: keep the manifest,
        restart the TTL clock, fire no ``on_refresh``. A zero-argument ``fetch``
        is accepted and simply polls unconditionally."""
        self._fetch = fetch
        self._fetch_conditional = _accepts_if_none_match(fetch)
        self._on_refresh = on_refresh
        self._on_error = on_error
        self._gap = min_refresh_gap
        self._now = now
        self._manifest: Mapping[str, Any] | None = None
        self._version: str | None = None
        self._expires_at: float = 0.0  # stale until the first refresh
        self._last_refresh_at: float = -1e9
        self._failures = 0
        self._permission_denied = False
        self._last_error: BaseException | None = None
        self._stopped = False
        self._lock: asyncio.Lock | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    # ── state ──────────────────────────────────────────────────────────────

    @property
    def manifest(self) -> Mapping[str, Any] | None:
        """The last good manifest, or ``None`` before the first success / after a permission refusal."""
        return self._manifest

    @property
    def version(self) -> str | None:
        return self._version

    @property
    def permission_denied(self) -> bool:
        """True once the manifest endpoint refused the credential (warned once; re-checked slowly)."""
        return self._permission_denied

    @property
    def last_error(self) -> BaseException | None:
        return self._last_error

    @property
    def stopped(self) -> bool:
        return self._stopped

    def stale(self) -> bool:
        """Whether the next request should refresh before deciding."""
        return not self._stopped and self._now() >= self._expires_at

    def hint(self) -> None:
        """A promoted-route hint arrived: make the NEXT request refresh (rate-limited)."""
        if self._now() - self._last_refresh_at >= self._gap:
            self._expires_at = self._now()

    def stop(self) -> None:
        """Drop the manifest and refuse further refreshes."""
        self._stopped = True
        self._manifest = None
        self._version = None

    # ── refresh ────────────────────────────────────────────────────────────

    def _get_lock(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        if self._lock is None or self._loop is not loop:
            # A fresh lock per loop: the sync facade may rebuild its loop after
            # a fork, and a Lock bound to a dead loop deadlocks.
            self._lock = asyncio.Lock()
            self._loop = loop
        return self._lock

    async def aensure(self) -> Mapping[str, Any] | None:
        """Refresh if stale (first load, TTL expiry, a hint), then return the manifest."""
        if self.stale():
            await self.arefresh("ttl", force=True)
        return self._manifest

    async def arefresh(self, reason: str, *, force: bool = False) -> Mapping[str, Any] | None:
        """Refresh now. Single-flight; rate-limited unless ``force``."""
        if self._stopped:
            return None
        lock = self._get_lock()
        if lock.locked():
            # Someone is fetching: wait for it and take their answer.
            async with lock:
                return self._manifest
        async with lock:
            if not force and self._now() - self._last_refresh_at < self._gap:
                return self._manifest
            return await self._do_refresh(reason)

    async def _do_refresh(self, reason: str) -> Mapping[str, Any] | None:
        self._last_refresh_at = self._now()
        try:
            # Every poll after the first is conditional on the held version; the
            # server answers 304 (→ None) when nothing changed, and that is a
            # success: keep the manifest, restart the TTL clock, fire no hook.
            if self._fetch_conditional and self._version is not None:
                nxt = await self._fetch(if_none_match=self._version)
            else:
                nxt = await self._fetch()
        except BaseException as err:  # noqa: BLE001 — every failure is classified below
            self._last_error = err
            if self._on_error is not None:
                self._on_error(err)
            status = err.status if isinstance(err, KnoxCallError) else None
            if status in (401, 403, 404):
                self._permission_denied = True
                self._manifest = None
                self._version = None
                warn_security(
                    f"KnoxCall intercept manifest unavailable (HTTP {status}): route-aware interception is off "
                    "for this client — listed hosts use the ephemeral proxy. Grant the credential `routes:read` "
                    "(or upgrade the server) to enable it."
                )
                self._expires_at = self._now() + DEFAULT_TTL_SECONDS * PERMISSION_RECHECK_FACTOR
            else:
                self._failures = min(self._failures + 1, 30)
                factor = min(2 ** (self._failures - 1), MAX_BACKOFF_FACTOR)
                base = float((self._manifest or {}).get("ttl_seconds") or DEFAULT_TTL_SECONDS)
                self._expires_at = self._now() + min(base * factor, base * MAX_BACKOFF_FACTOR)
            return self._manifest

        prev = self._manifest
        self._failures = 0
        self._permission_denied = False
        self._last_error = None
        if nxt is None:
            # Not modified: the held manifest stands for another TTL.
            self._expires_at = self._now() + float((prev or {}).get("ttl_seconds") or DEFAULT_TTL_SECONDS)
            return self._manifest
        version = str(nxt.get("version", ""))
        if prev is None or self._version != version:
            before = {_entry_key(e): e for e in (prev or {}).get("routes", [])}
            after = {_entry_key(e): e for e in nxt.get("routes", [])}
            added = [e for k, e in after.items() if k not in before]
            removed = [e for k, e in before.items() if k not in after]
            self._manifest = nxt
            self._version = version
            if self._on_refresh is not None and (added or removed or prev is None):
                self._on_refresh({"reason": reason, "version": version, "added": added, "removed": removed})
        ttl = float(nxt.get("ttl_seconds") or DEFAULT_TTL_SECONDS)
        self._expires_at = self._now() + ttl
        return self._manifest
