"""Workload-identity credential provider — WIF plan Phase 4.3.

Mirrors ``auth/workload-provider.ts`` in the Node SDK; ``sdk/PARITY.md`` is the
authoritative contract for both.

:func:`knoxcall.exchange_token` is one-shot: it trades one OIDC assertion for
one capability token and hands the caller an ``expires_in`` to manage. That is
fine for a script that makes one call and exits, and wrong for anything
long-lived — a polling worker, a long CI job, an agent process — where the token
silently expires mid-run and the caller discovers it as a 401 they then have to
interpret.

This provider owns that lifecycle: cache the token, refresh it before it dies,
and never hand out one that is about to expire.

THE PART THAT IS NOT LIKE OTHER REFRESH LOOPS
---------------------------------------------
A KnoxCall workload assertion is SINGLE-USE. The exchange spends the whole
assertion — the server claims a hash of it before minting (WIF Phase 1.2), so
presenting the same bytes twice is refused with "subject_token has already been
exchanged". A refresh therefore cannot re-send the assertion it used last time;
it needs a FRESH one from the platform every single time.

That makes the obvious implementation — capture the assertion once, reuse it on
refresh — not merely suboptimal but broken, and broken in a way that only shows
up when the first refresh fires, i.e. minutes into production rather than in
anyone's smoke test. So the provider takes a SOURCE it calls before every
exchange, and refuses to send an assertion whose bytes it has already spent
(:class:`StaleAssertionError`). It fails loudly at the real cause rather than
forwarding a doomed request and surfacing the server's replay refusal, which
reads as "my credentials were rejected" and sends the reader hunting in the
wrong place.

THE TWO-TIER SCHEDULE
---------------------
ADVISORY (expiry minus 120s): refresh opportunistically. If it fails, the token
in hand is still valid, so the caller is served and the failure is a warning,
not an exception. A transient blip near a refresh boundary must not take down a
worker that has two minutes of perfectly good credential left.

MANDATORY (expiry minus 30s): refresh or raise. Below this line the token may
die in flight — between the provider handing it over and the request reaching
the server — and a 401 from an expired capability token is exactly the confusing
failure this provider exists to prevent.

The gap between the two tiers is the whole point: it buys 90 seconds in which a
failing token source or a flaky network is survivable rather than fatal.

UNITS. The tiers are SECONDS here and MILLISECONDS in the Node SDK, because each
follows its own ``CachedToken``: ``expires_at`` is epoch seconds in Python and
epoch milliseconds in TypeScript. The boundaries are the same wall-clock
durations; only the numbers differ.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import time
import warnings
from typing import Any, Awaitable, Callable, Union

import httpx

from ..errors import KnoxCallError
from ..redacted import Redacted
from ..resources.token_exchange import KNOXCALL_AUDIENCE, _UNSET, exchange_token
from .token_store import CachedToken, MemoryTokenStore, TokenStore

#: Refresh opportunistically below this much remaining life; failure is survivable.
ADVISORY_REFRESH_SECONDS = 120.0

#: Refresh or raise below this much remaining life; the token may die in flight.
MANDATORY_REFRESH_SECONDS = 30.0

#: Produces the workload's CURRENT OIDC assertion.
#:
#: Called before EVERY exchange, never cached by the provider. On GitHub Actions
#: this is a fetch of ``ACTIONS_ID_TOKEN_REQUEST_URL``; on GCP or EKS a read of
#: the metadata service or the projected token file. Whatever it is, it must
#: mint or re-read — returning a value captured once at startup is the failure
#: this provider detects rather than tolerates. Sync and async callables both
#: work.
WorkloadAssertionSource = Callable[[], Union[str, Awaitable[str]]]


class StaleAssertionError(KnoxCallError):
    """The assertion source returned bytes already spent on a previous exchange.

    This is a caller-side configuration error, not a credential rejection, and
    it says so: the message names the cause and what to do, because the
    alternative is a replay refusal from the server that reads like "your CI
    identity is not trusted".
    """


class WorkloadCredentialProvider:
    """Caches a workload capability token and refreshes it on the two-tier schedule.

    Concurrency is the store's single-flight lock, so N simultaneous callers
    produce ONE exchange — which matters more here than in an ordinary refresh
    loop: each exchange spends an assertion, and a thundering herd would burn N
    of them and have N-1 refused::

        from knoxcall import WorkloadCredentialProvider

        provider = WorkloadCredentialProvider(assertion=mint_github_id_token, tenant="acme")
        token = await provider.get_access_token()
        headers = {"Authorization": f"Bearer {token.expose()}"}
    """

    def __init__(
        self,
        *,
        assertion: WorkloadAssertionSource,
        resource: Any = _UNSET,
        audience: str = KNOXCALL_AUDIENCE,
        tenant: str | None = None,
        sandbox: bool = False,
        base_url: str | None = None,
        http: httpx.AsyncClient | None = None,
        store: TokenStore | None = None,
        cache_key: str | None = None,
        now: Callable[[], float] | None = None,
    ) -> None:
        self._assertion = assertion
        # ``resource`` is passed through with the module's own _UNSET sentinel
        # rather than None, so that ``resource=""`` still REACHES the server and
        # is refused invalid_target. Treating an empty string as absent would
        # hand back an unconfined agent token to a caller who asked for a
        # confined one; the sentinel must be the same object to compare.
        self._resource = resource
        self._audience = audience
        # Every exchange option carried through verbatim. ``sandbox`` in
        # particular: dropping it would silently send a Test-mode workload's
        # assertion to the Live host, where it matches no binding — a confusing
        # refusal produced by the provider rather than by the caller's config.
        self._tenant = tenant
        self._sandbox = sandbox
        self._base_url = base_url
        self._http = http
        self._store: TokenStore = store if store is not None else MemoryTokenStore()
        # The default key separates Live from Test for the same tenant, so one
        # provider per data space cannot serve the other's token from cache.
        space = "test" if sandbox else "live"
        self._key = cache_key or f"workload:{base_url or tenant or 'default'}:{space}"
        self._now = now or time.time
        # sha256 of every assertion this provider has spent. Never the assertion.
        self._spent: set[str] = set()

    async def get_access_token(self) -> Redacted[str]:
        """A capability token with more than :data:`MANDATORY_REFRESH_SECONDS` of life left.

        Returns :class:`~knoxcall.Redacted` so the token cannot reach a log
        through a stray f-string or a structured-logger field — the same
        treatment every other credential in this SDK gets.
        """
        cached = await self._store.get(self._key)
        remaining = (cached.expires_at - self._now()) if cached else -1.0

        if cached is not None and remaining > ADVISORY_REFRESH_SECONDS:
            return cached.access_token

        if cached is not None and remaining > MANDATORY_REFRESH_SECONDS:
            # ADVISORY tier: try, but the token in hand is still good.
            try:
                return await self._refresh()
            except Exception as err:  # noqa: BLE001 — deliberately broad, see below
                # best-effort: the caller still has a valid credential, and
                # raising here would convert a survivable blip into an outage.
                # The MANDATORY tier below raises it for real if it persists.
                warnings.warn(
                    f"KnoxCall: advisory token refresh failed ({err}); continuing with the "
                    f"current token, which expires in {round(remaining)}s",
                    RuntimeWarning,
                    stacklevel=2,
                )
                return cached.access_token

        # MANDATORY tier, or nothing cached at all.
        return await self._refresh()

    def get_access_token_sync(self) -> Redacted[str]:
        """Synchronous :meth:`get_access_token`.

        Runs on a private event loop, like :func:`knoxcall.exchange_token_sync`.
        Safe across calls because the cached token is loop-agnostic and
        :class:`~knoxcall.MemoryTokenStore` scopes its locks to the running
        loop; call the async form when already inside one.
        """
        return asyncio.run(self.get_access_token())

    async def _refresh(self) -> Redacted[str]:
        """Exchange a fresh assertion, under the store's single-flight lock."""

        async def do_refresh() -> Redacted[str]:
            # Re-read inside the lock: a peer may have refreshed while we
            # waited, and spending a second assertion for a token we already
            # hold is pure waste.
            current = await self._store.get(self._key)
            if current is not None and current.expires_at - self._now() > ADVISORY_REFRESH_SECONDS:
                return current.access_token

            produced = self._assertion()
            assertion = await produced if inspect.isawaitable(produced) else produced
            if not isinstance(assertion, str) or not assertion:
                raise StaleAssertionError(
                    "the workload assertion source returned nothing. It must return the "
                    "workload's current OIDC id_token on every call."
                )

            fingerprint = hashlib.sha256(assertion.encode("utf-8")).hexdigest()
            if fingerprint in self._spent:
                raise StaleAssertionError(
                    "the workload assertion source returned an assertion that has already "
                    "been exchanged. KnoxCall assertions are single-use, so each refresh "
                    "needs a NEWLY minted one — call the platform's token endpoint inside "
                    "the source (for example re-fetch ACTIONS_ID_TOKEN_REQUEST_URL, or "
                    "re-read the projected service-account token file) rather than "
                    "capturing one value at startup."
                )

            res = await exchange_token(
                subject_token=assertion,
                resource=self._resource,
                audience=self._audience,
                tenant=self._tenant,
                sandbox=self._sandbox,
                base_url=self._base_url,
                http=self._http,
            )

            # Recorded only after the exchange returns, so a network failure
            # does not burn a fingerprint the caller could legitimately retry
            # with. The server claims the assertion before it mints, so a
            # SUCCESS is what makes those bytes unusable.
            self._spent.add(fingerprint)

            lifetime = float(res["expires_in"])
            scope = res.get("scope")
            token = CachedToken(
                access_token=Redacted(res["access_token"]),
                expires_at=self._now() + lifetime,
                lifetime=lifetime,
                scope=[scope] if scope else [],
                token_type="Bearer",
            )
            await self._store.set(self._key, token)
            return token.access_token

        return await self._store.with_lock(self._key, do_refresh)
