# Changelog

All notable changes to this package are documented here. This project adheres
to [Semantic Versioning](https://semver.org/) and
[Keep a Changelog](https://keepachangelog.com/).

**First release: 1.0.0, 2026-09-27** — published to PyPI as `knoxcall` (monorepo tag `knoxcall-python-v1.0.0`).

## [Unreleased]

### Changed
- **1.1.0 — registry install instructions.** A registry renders the README that was inside the version it published and never lets it be edited, so the README inside the previous release still showed pre-release install instructions (build from a source checkout) after the package was live; the corrected README reaches a registry only as a new version. `knoxcall.__version__` and the `knoxcall-sdk-python/<v>` User-Agent are `1.1.0`. The version is a minor, not a patch: the `Retry-After` change below adds `ServerError.retry_after`, which is new public API.
- **`Retry-After` is honoured on a 503, not only on a 429.** KnoxCall now answers a request it could not serve because one of its own dependencies did not answer in time with `503 { error: { type: "dependency_unavailable", … } }` + `Retry-After` (on the data plane this used to surface as an opaque `401 Unauthorized`; on `/v1` as `500 internal_error`). `ServerError` exposes the header as `retry_after` (`None` when none was sent), and the retry loop waits it — capped at 30 s — before the next attempt, exactly as it does for a 429; a plain 5xx with no header keeps the jittered backoff. Nothing to change in calling code: it is a retryable server error, never an authentication failure, and never a manifest-refresh trigger. (PARITY §4, §16.)

## [1.0.0] — 2026-09-27

### Changed
- **Refusal-driven refresh learns the 404.** The route data plane now answers an AUTHENTICATED credential's call to a Route that does not resolve with `404 {"error": {"type": "route_not_found" | "environment_not_configured" | "environment_disabled", "message", "request_id"}}` plus the KnoxCall response block, instead of the opaque `401 Unauthorized` (which callers the tenant has not authenticated keep — founder decision 2026-09-26, PARITY §21). `wrap.intercept()` and `wrap.transport(routes="auto")` (sync and async, every patched stack) now treat a KnoxCall-origin `404` whose envelope `error.type` is `route_not_found` as a refresh trigger alongside the 401 — a stale manifest naming a deleted Route is exactly that — refreshing once and re-deciding once, never looping. The `environment_*` types are surfaced as-is; an UPSTREAM 404 (`X-Knox-Upstream-Status` present) never triggers it, whatever its body says. `on_refused` reports `status: 404` for that case. `call()` is unchanged: it returns the 404 raw (PARITY §5) and spends no re-mint on it. Cross-language contract: `sdk/fixtures/route-refusal.json`.

### Added
- **Uncovered-egress observations (PARITY §21.3), on by default.** `wrap.intercept()` (httpx, urllib3 and the opt-in aiohttp arm) and `wrap.transport(routes="auto")` now count calls sent direct because their host is `unlisted` while they carry a credential-bearing header — host, first path segment, method and the header NAME; never the value, the query string or the body — and report them to `POST /v1/wrap/egress-observations` about once a minute (a daemon timer on the sync client, a task on your loop on `KnoxCallAsync`; at 200 distinct keys at once; once more on `uninstall()`). Opt out with `observe_uncovered=False` or `KNOXCALL_OBSERVE_UNCOVERED=off`; nothing is reported while `KNOXCALL_INTERCEPT=off`; a 403 stops reporting with one warning. New `on_observation_flush` hook, `wrap.report_egress_observations(observations)`, the `EgressObservation` / `EgressObservationsReport` TypedDicts and the exported classifier. (Founder decision 2026-09-26: default-on with an opt-out.)
- **A credential in the path is never reported.** Before an uncovered-egress observation is sent, a first path segment that looks like a credential (Telegram's `/bot<id>:<secret>`, a Stripe/GitHub/AWS/Google/Slack/JWT token, any segment over 64 characters, or a 24+ character mixed-class run — raw or percent-decoded) is reported as `/`; the server's identical rule (#1022) counts it under the receipt's new `redacted` field, now on the report type. (PARITY §21.3.)
- `wrap.intercept_manifest(if_none_match=)` — the conditional poll, on the sync and async clients. Pass the manifest `version` you hold and the SDK sends `If-None-Match: W/"<version>"` (`manifest_etag()`, exported); the server's `304` returns `None` — keep what you hold. The route-aware store (`wrap.intercept()`, `wrap.transport(routes="auto")`) now polls this way on every refresh after the first, lazy or forced: a `304` keeps the manifest, restarts the TTL clock, clears backoff and fires no `on_refresh`, so a steady-state poll costs no body bytes. A `manifest_fetch=` seam that takes no `if_none_match` keyword keeps polling unconditionally. Auth, the one re-auth on 401 and retries are unchanged; the unconditional call never returns `None`. (PARITY §21.1 "Conditional poll"; fixture `sdk/fixtures/intercept-store-conditional.json`.)
- **Origin marker on rerouted calls.** Every route-mode send from `wrap.intercept()` / `wrap.transport(routes="auto")` (and the legacy explicit `route=` form) now carries `x-knoxcall-origin: sdk-intercept`, so the API Log shows the call as **SDK intercept** rather than **Direct** (`client_origin` on `RequestLog` rows: `"direct"` | `"sdk_intercept"`). A direct `call()` / bound route sends nothing; an ephemeral hop sends nothing. A caller-supplied `x-knoxcall-origin` in `call()` / `ephemeral()` `headers` is stripped like the proxy-auth headers — the server treats the marker as informational either way. The seam is `call()`'s internal `_origin=` (only `SDK_INTERCEPT_ORIGIN` is accepted; anything else raises `ValueError`). (PARITY §21.2.)
- **`aiohttp` interception, opt-in.** `KnoxCallAsync(...).wrap.intercept(stacks=["aiohttp"])` patches `aiohttp.ClientSession._request` at class level (aiohttp >= 3.13; never a dependency — the arm imports it on demand and raises an `ImportError` naming `pip install 'aiohttp>=3.13'`), so `session.get()` / `.post()` / `.request()` and `async with session.get(...)` on any session — aiobotocore, slack_sdk's async client, azure-core's aiohttp transport — make the same route / ephemeral / direct decisions as the httpx stacks. A matched call is buffered through aiohttp's own payload registry (`json=`, `data=` as bytes, str, a mapping, `FormData` incl. multipart, a file, a sync or async iterable) and answered as a real `aiohttp.ClientResponse` (`async with`, `.json()`/`.text()`/`.read()`, `ok`/`raise_for_status()`, `release()`, `content.iter_chunked()`, `cookies`, `request_info`), a recipe the install proves against the installed aiohttp before patching. Every direct decision — an unmatched host, the kill switch, a route-around rule, `unavailable="direct"` — replays the original call, so it stays aiohttp's own streaming request. Not mirrored: `ws_connect` (goes direct), client middlewares and `TraceConfig`, redirects (the upstream's 3xx is returned as-is). Refused on the sync client with a `TypeError` naming `KnoxCallAsync`: the arm awaits the pipeline on your event loop. (route-aware-interception-plan.md D7; PARITY §21.1.)
- **Route-aware interception.** `knox.wrap.intercept(hosts=..., stacks=["httpx", "urllib3"])` on the sync client patches `httpx` (sync + async) and `urllib3` (`requests`, generated clients such as `hubspot-api-client`) at class level and, by default, sends each request through the Route that covers its host + path (the Route injects the secret; no provider credential travels), through the ephemeral proxy for listed hosts no Route covers, and untouched otherwise. A Route created, enabled or disabled later takes effect on the next request after the TTL, on a refusal, or on `handle.refresh()`. `hosts` may be a list or a `{host: {"credential": …, "unavailable": …}}` map; `require_context=True` scopes to `with routed():`. `wrap.transport(routes="auto")` / `wrap.client(routes="auto")` give an explicit transport the same behaviour (default stays `"off"`); the transports gained `ready()`, `refresh()`, `manifest()`, `stop()`. New hooks: `on_reroute`, `on_refresh`, `on_manifest_error`, `on_unmatched_path`, `on_refused`, `on_fallback`; `unavailable="direct"` (transit only) opts out of fail-closed. `KNOXCALL_INTERCEPT=off` is the kill switch. On `KnoxCallAsync` only the async httpx stack can be patched. Exports `resolve_intercept`, `InterceptDecision`, `InterceptManifestStore`, `InterceptHandle`, `routed`, `intercept_kill_switch`. (route-aware-interception-plan.md PR3; PARITY §21.1.)
- `wrap.intercept_manifest(environment=None)` — `GET /v1/wrap/intercept-manifest`, the per-environment list of upstream hosts an intercept-enabled Route covers (`InterceptManifest` / `InterceptManifestRoute` TypedDicts; `version` doubles as the ETag). What a route-aware interceptor polls (route-aware-interception-plan.md PR1).
- `intercept_enabled=` on `routes.update()` and `routes.upsert_environment()` — the per-environment interception opt-in; echoed on route reads.

### Fixed
- `call()` / `ephemeral()` no longer spend their one token re-mint on an UPSTREAM 401: a response carrying `X-Knox-Upstream-Status` (the route data plane) or `X-Knox-Destination-Status` (the ephemeral proxy) is the upstream's answer, not a KnoxCall refusal. Previously EVERY 401 purged the cached token.
- `call()` — and bound routes, the CLI and the interceptors' route mode, which delegate to it — now places the upstream path under the tenant host's `/api` data-plane entry point whenever the proxy base is a KnoxCall cloud tenant host with no path of its own (derived, or an explicit override naming one); any other base is used verbatim. Before, `client.call("r", path="/users")` sent `https://{tenant}.knoxcall.com/users`, which a tenant host answers with the dashboard, not the proxy — every documented example was affected, and `path="/api/…"` was the only form that worked. `path` is now always the upstream path (PARITY §5).

> **This section was headed `## [1.0.0] — 2026-08-04` and described it as a
> First public release until 2026-08-23. That release never happened**: `git tag --list` is
> empty, the package name was still unclaimed at the last check (2026-08-11,
> `docs/internal/runbooks/sdk-publish.md`), and no artifact was ever pushed to a
> registry. The same fabricated-release shape was removed from the Terraform
> provider's changelog on 2026-08-06; this is that correction applied to the
> remaining packages. The content below is accurate — it is the work that will
> ship in the first release — only the heading was a claim.
>
> `tests/coverage/sdk-changelog-honesty.test.ts` now refuses any release heading
> with no matching git tag, so this cannot recur silently.

### Added
- `WorkloadCredentialProvider` — caches a workload-identity capability token and
  refreshes it on a two-tier schedule (advisory at expiry−120s, mandatory at
  expiry−30s), calling a caller-supplied assertion SOURCE before every exchange.
  Because KnoxCall assertions are single-use, a source that returns bytes already
  spent is refused locally with `StaleAssertionError` rather than sent and refused
  as a replay. N concurrent callers cause one exchange. PARITY §20.
- Full `/v1` management surface (routes, secrets, vaults, PKI, crypto/transit,
  dynamic DB, clients, OAuth clients, environments, API keys, account, audit
  logs, agents, AI Gateway) with typed responses and `{data, meta}` pagination.
- Data-plane `call()`, bound routes, and one-shot `ephemeral()` proxying.
- OAuth 2.1 client-credentials, pre-acquired token, and OIDC token-exchange
  bootstraps; zero-config env + `~/.knoxcall/credentials.json` auto-detection;
  DPoP (RFC 9449) with `auto`/`always`/`never` modes.
- `constructEvent` webhook verification (legacy/stripe/github/slack/aws-sns/
  custom) and the `knoxcall` CLI (`login`/`logout`/`whoami`).

### Security
- The SDK credential is now the sole data-plane auth authority: `call()` and
  `ephemeral()` strip any caller-supplied proxy-auth headers
  (`Authorization`, `DPoP`, `x-knoxcall-key`, `x-knoxcall-agent-id`,
  `x-knoxcall-agent-token`) before setting their own.
- The credentials-file lock is now ownership-aware (unique owner tag, atomic
  rename to break a stale lock, content-matched release) and the stale window
  sits above a bounded refresh timeout — closing a double-refresh race that
  could trip server-side refresh-token family revocation.
- Tenant slugs are validated as bare DNS labels before becoming a data-plane
  hostname, preventing token misdirection from a hostile slug.
