# knoxcall — official Python SDK for KnoxCall

Standards-based OAuth 2.1 + DPoP (RFC 9449). One import, sync or async.

## Install

```bash
pip install "knoxcall>=1.0,<2.0"
```

Requires Python 3.10+.

## Quick start

```python
from knoxcall import KnoxCall

# Credentials inline — the tenant is discovered from the credential
client = KnoxCall(client_id="tk_xxxxxxxx", client_secret="...")

# Or zero-arg with the environment configured
# (KNOXCALL_CLIENT_ID, KNOXCALL_CLIENT_SECRET)
client = KnoxCall()

# tenant= is still accepted and skips the discovery lookup
client = KnoxCall(tenant="acme", client_id="tk_xxxxxxxx", client_secret="...")

routes = client.routes.list()
resp = client.call("payments-stripe", path="/v1/customers")  # route slug (preferred)
print(resp.json())

# Async — use in FastAPI, async frameworks, etc.
async with KnoxCall(sync=False) as client:
    routes = await client.routes.list()
```

## Authentication

Pass credentials as plain constructor arguments:

| Kwarg | Use |
|---|---|
| `client_id` + `client_secret` | OAuth client-credentials grant (recommended for servers) |
| `access_token` / `api_key` | a pre-acquired token or key — two spellings, one behavior; works with `kc_…` tokens and legacy `tk_…`/`AKE…` keys |
| `bootstrap=` | advanced: `OIDCTokenExchange` and friends |

> **A pre-acquired `access_token`/`api_key` is not auto-renewed.** It has no
> refresh token, so the SDK uses it until it expires server-side, then raises a
> 401 `AuthenticationError`. For long-lived processes that should re-auth on
> their own, use `client_id` + `client_secret` (or `knoxcall login` /
> `ensure_login()`), which mint and refresh tokens for you.
>
> **Transport & storage:** a plaintext `http://` base or proxy URL pointing at a
> non-loopback host emits a one-time `KnoxCallSecurityWarning` — credentials
> would travel unencrypted; use `https://` (plain `http://` is only for
> localhost). On POSIX, the SDK also warns once if
> `~/.knoxcall/credentials.json` is group/other-readable (`chmod 600` it).

With no explicit credentials, the SDK auto-detects from the environment in priority order:

1. `KNOXCALL_ACCESS_TOKEN` (or `KNOXCALL_API_KEY`) env var
2. Credentials file written by `knoxcall login` (`~/.knoxcall/credentials.json`)
3. GitHub Actions OIDC
4. GCP metadata service
5. AWS IRSA (`AWS_WEB_IDENTITY_TOKEN_FILE`)
6. Azure Managed Identity
7. Vercel OIDC token
8. CircleCI OIDC token
9. `KNOXCALL_CLIENT_ID` + `KNOXCALL_CLIENT_SECRET`

### Log in once with the CLI

The package ships a `knoxcall` command. Sign in once in your browser and every
script, notebook, and agent on the machine picks the credential up
automatically — no env vars, no keys in code:

```bash
knoxcall login                    # opens your browser (PKCE); prints the URL too
knoxcall login --device           # headless/SSH machines: device-code flow
knoxcall login --sandbox          # log in against the sandbox environment
knoxcall login --profile staging  # keep multiple accounts side by side
knoxcall whoami                   # show the signed-in tenant
knoxcall logout                   # revoke + remove the stored credential
```

```python
from knoxcall import KnoxCall

with KnoxCall() as client:   # zero config — tenant and base URL come from the login
    routes = client.routes.list()
```

Credentials are stored in `~/.knoxcall/credentials.json` (file mode 0600).
The stored tenant and base URL seed the client automatically; explicit
constructor arguments or env vars always win. Access tokens refresh
themselves, and refreshes are cross-process safe (file lock + atomic
rotation of the single-use refresh token). If a refresh fails because the
credential was revoked or expired, the SDK raises `AuthenticationError`
telling you to run `knoxcall login` again. Select a non-default profile with
`KNOXCALL_PROFILE` (or `StoredCredentials(profile=...)`).

### Environment variables

| Variable | Meaning |
|---|---|
| `KNOXCALL_TENANT` | tenant slug (enables zero-arg `KnoxCall()`) |
| `KNOXCALL_ENVIRONMENT` | default environment for data-plane calls |
| `KNOXCALL_CLIENT_ID` / `KNOXCALL_CLIENT_SECRET` | client-credentials grant |
| `KNOXCALL_ACCESS_TOKEN` / `KNOXCALL_API_KEY` | pre-acquired token (ACCESS_TOKEN wins) |
| `KNOXCALL_BASE_URL` | management API base override |
| `KNOXCALL_PROXY_BASE_URL` | data-plane base override |
| `KNOXCALL_CREDENTIALS_FILE` | credentials file path override (default `~/.knoxcall/credentials.json`) |
| `KNOXCALL_PROFILE` | credentials-file profile to use (default `default`) |

## Calling routes

`client.call()` proxies a request through a KnoxCall route to your upstream and returns the raw `httpx.Response`.

### Bound routes

State the route (and optional defaults) once with `client.route()`, then use plain HTTP verbs:

```python
printnode = client.route("ops-printnode", environment="production")

computers = printnode.get("/computers").json()
printnode.post("/printjobs", body={"printerId": 1, "title": "Invoice"})
printnode.request("DELETE", "/printjobs/42")
# per-call kwargs still override the bound defaults:
printnode.get("/computers", environment="staging")
```

Works identically on the async client (`await printnode.get(...)`). The handle holds no state beyond the defaults — retries, token refresh, and 401 re-mint behave exactly as on `call()`.

Reference routes by **slug** — the write-once machine handle set on the route (dashboard or API). Slugs are immutable, so unlike names they can never be broken by a rename, and unlike UUIDs the same code works across every tenant that uses the same slug convention. UUIDs also work; bare names are legacy.

```python
# GET
resp = await client.call("payments-stripe", path="/users")
users = resp.json()

# POST with body
resp = await client.call("payments-stripe", method="POST", path="/v1/charges",
                          body={"amount": 2000, "currency": "usd"})

# Target a specific environment
resp = await client.call("payments-stripe", path="/data", environment="staging")

# With extra headers and query params
resp = await client.call("payments-stripe", path="/search",
                          headers={"X-Correlation-ID": "abc"},
                          query={"q": "example", "limit": "10"})
```

`path` is the **upstream** path. On a KnoxCall cloud tenant host the data plane is served under `/api` (`https://{tenant}.knoxcall.com/api/<path>`); the SDK adds that prefix itself whenever the proxy base is a cloud tenant host with no path of its own, and uses any other base verbatim (self-hosted, or an override that already carries a path). So `/api/v2/tickets` reaches an upstream path that itself begins with `/api`.

### Ephemeral proxy

`client.ephemeral()` makes a one-shot proxied request without a configured route. The proxy resolves `{{ token: "..." }}` template expressions in the body on the wire — the upstream never receives raw token values:

```python
resp = client.ephemeral("https://api.stripe.com/v1/charges",
                        method="POST",
                        body={"card": "{{ token: 'tok_abc123' }}"},
                        timeout_ms=10_000)
```

By default the proxy URL is derived from your tenant slug (`https://{tenant}.knoxcall.com`). Override for local dev:

```python
client = KnoxCall(tenant="acme", base_url="http://localhost:3000",
                  proxy_base_url="http://localhost:3000")
# Or via env var: KNOXCALL_PROXY_BASE_URL=http://localhost:3000
```

### Route-aware interception (preview)

Send an untouched third-party SDK's traffic through the Route that covers it —
and through the ephemeral proxy where no Route does — with no per-SDK wiring:

```python
knox = KnoxCall(api_key=...)
stop = knox.wrap.intercept(hosts=["api.resend.com"])   # hosts with NO Route still covered (ephemeral)
stop.ready()                                           # first manifest loaded

hubspot = HubSpot(access_token="placeholder")          # an untouched SDK (urllib3 underneath)
hubspot.crm.contacts.basic_api.get_page()              # via the Route that covers api.hubapi.com
stop.uninstall()
```

Per request: the kill switch (`KNOXCALL_INTERCEPT=off`), KnoxCall's own hosts
and route-around rules go direct; a Route in the manifest covering host + path
goes through that Route (the Route injects the stored secret — no provider
credential travels); a host in `hosts` with no Route goes through the ephemeral
proxy; everything else is untouched. Turn a Route's **Intercept** toggle on and
it takes effect on the next request after the 60 s TTL, or on the next
refusal, with no code change. Per-host options:
`hosts={"api.resend.com": {"credential": {"secret": "resend-key"}}}` (escrow)
or `{"unavailable": "direct"}` (transit only: send direct when KnoxCall is
unreachable; the default is fail closed). `require_context=True` limits
interception to code inside `with routed():`.

Stacks patched: `httpx` (sync + async clients on the default transport) and
`urllib3` (`requests`, OpenAPI-generated clients, `botocore`). Opt-in on the
async client: `KnoxCallAsync(...).wrap.intercept(stacks=["aiohttp"])` patches
`aiohttp.ClientSession._request` (aiohttp >= 3.13, installed separately —
aiobotocore, slack_sdk's async client, azure-core's aiohttp transport) and
answers with a real `aiohttp.ClientResponse`; a direct decision replays the
original call. Not reached: an explicitly injected custom transport, raw
`http.client`, `pycurl`, and on the aiohttp stack a WebSocket handshake
(`ws_connect` goes direct). The same decisions are available to an explicit
transport with `knox.wrap.transport(routes="auto")` (`ready()`, `refresh()`,
`manifest()`).

This is a convenience, not a security boundary: it patches process-wide
classes and composes with APM agents in install order. Route mode is the
custody path — the key never enters your process.

#### What the SDK reports about uncovered calls, and how to turn it off

**Reporting is on by default.** When the interceptor sends a call direct
because no Route covers its host and you did not list the host, and that call
carries a credential header (`Authorization`, `X-Api-Key`, or any name ending
in `-api-key`, `-token`, `-secret` or `-auth`), the SDK counts it. About once a
minute, the SDK reports the counts to KnoxCall
(`POST /v1/wrap/egress-observations`) with its own credential. The dashboard
uses the report to show which credentials still leave your process outside
KnoxCall custody.

**What is sent.** Each report carries the host, the first path segment, the
method, the credential header's **name**, a count, and first/last-seen times.
The header's **value** is never sent, and neither are the query string, the
body, or any deeper path.

**How to turn it off.** Pass `observe_uncovered=False` when you install, or set
`KNOXCALL_OBSERVE_UNCOVERED=off` in the environment. Nothing is reported while
`KNOXCALL_INTERCEPT=off`. If your key lacks `routes:read`, the first report is
refused, you get one warning, and reporting stops. `on_observation_flush` receives the
server's `{accepted, dropped}` after each report.

## Managing resources

### Response shapes & pagination

The server wraps every JSON response in `{"data": ..., "meta": ...}`.
Single-object methods (`get`, `create`, `update`, …) return `data`
unwrapped. Paginated `list` methods take `page` / `per_page` (server
default 20, cap 100) and return the full typed page —
`{"data": [...], "meta": {"total", "page", "per_page", "total_pages", "request_id"}}` —
while `iterate()` walks every page for you. A few list endpoints are
plain (unpaginated) arrays: `environments.list`, `agents.list`,
`crypto.list_keys`, `oauth_clients.list`, PKI lists, dynamic-db
lists, `routes.list_environments`, and `clients.list_credentials`.
Every method's return shape is a `TypedDict` in `knoxcall.types`.

```python
page = await client.routes.list(page=2, per_page=50)
print(page["meta"]["total_pages"], [r["name"] for r in page["data"]])
```

### Routes

```python
page  = await client.routes.list(per_page=50)      # {"data": [...], "meta": {...}}
route = await client.routes.get("payments-stripe")  # slug preferred; UUID works too
new   = await client.routes.create(name="my-api", target_base_url="https://api.example.com")
await client.routes.update(new["id"], enabled=False)
await client.routes.delete(new["id"])

# Pagination — walks pages until meta.total_pages
async for route in client.routes.iterate():
    print(route["name"])

# Request logs (paginated)
logs = await client.routes.get_logs(new["id"], per_page=100)

# Per-environment config
envs = await client.routes.list_environments(new["id"])
await client.routes.upsert_environment(new["id"], "production",
    target_base_url="https://api.example.com",
    ip_allowlist=["10.0.0.0/8"],
    rate_limit_enabled=True, rate_limit_requests=1000, rate_limit_window_sec=60)
await client.routes.delete_environment(new["id"], "staging")

# Field-actions — declarative field-level encrypt/decrypt/tokenize on the wire
actions = await client.routes.list_actions(new["id"])
act = await client.routes.create_action(new["id"],
    direction="request", action="tokenize", selectors=["$.card.number"])
await client.routes.delete_action(new["id"], act["id"])
```

### AI Gateway

An agent needs an upstream credential, so the first step is a Secret holding
your provider key. Pass `provider` + `upstream_secret_id` and KnoxCall composes
the upstream route for you — **an agent created without either has no upstream,
and its first data-plane call 502s.**

```python
# 1. Escrow the provider key. It never leaves KnoxCall in plaintext again.
secret = await client.secrets.create(name="anthropic-key", secret_type="api_key",
                                     value=os.environ["ANTHROPIC_API_KEY"])

# 2. Gateway -> agent. `provider` is a plain string; the catalog is server-side
#    (anthropic, openai, gemini, groq, bedrock, …) and a bad one comes back as
#    a 400 naming the valid set.
gw    = await client.ai_gateway.create_gateway(name="Prod", slug="prod", budget_daily_usd=50)
agent = await client.ai_gateway.create_agent(
    gw["id"], name="copilot", slug="copilot",
    provider="anthropic", upstream_secret_id=secret["id"],
    default_model="claude-sonnet-5",
)

# 3. Mint a capability token and point any AI SDK at the agent.
minted = await client.ai_gateway.mint_token(agent["id"], kind="agent")
# minted["token"] is the plaintext capability token — shown exactly once.
print(agent["agent_url"])   # https://<tenant>.knoxcall.com/v1/ai/copilot
# e.g. anthropic.Anthropic(base_url=agent["agent_url"], api_key=minted["token"])

usage = await client.ai_gateway.usage(period="30d")   # cost + tokens by model
async for gw in client.ai_gateway.iterate_gateways():
    print(gw["slug"])
```

`upstream` is required for the four providers whose endpoint is yours rather than
the vendor's: `azure-openai`, `ollama`, `bedrock` and `openai-compatible`. It is
not defaulted — creating an agent on one of those four without it is a 400 —
and `openai-compatible` additionally requires `default_model`. If you already
have a Route carrying the credential, pass `primary_route_id` instead of the
`provider` pair — never both.

### Secrets

```python
secret = await client.secrets.create(name="stripe-key", secret_type="api_key", value="sk_live_...")
await client.secrets.update(secret["id"], expires_at="2027-01-01T00:00:00Z")
await client.secrets.set_value(secret["id"], value="sk_live_new...")  # rotate value only

# Structured secret types (the base create() can't carry these fields):
await client.secrets.create_oauth2(name="Salesforce", provider="custom", client_id="ci",
                                   client_secret="cs", token_url="https://login.example.com/oauth/token", scopes=["api"])
await client.secrets.create_certificate(name="mTLS client",
                                        certificate_content="-----BEGIN CERTIFICATE-----\n...", certificate_type="pem")

# Get current token for an OAuth2 secret (auto-refreshes if expired)
token_info = await client.secrets.get_oauth_token(secret["id"])

async for s in client.secrets.iterate():
    print(s["name"])
```

### Webhooks

```python
wh = await client.webhooks.create(
    name="order-events",
    url="https://example.com/webhooks/knoxcall",
    event_types=["request.success", "request.server_error"],
    include_response_body=True,
    retry_on_failure=True,
    max_retries=5,
)
# wh["secret_key"] is returned ONCE — save it for signature verification
await client.webhooks.update(wh["id"], enabled=False)

# Discover subscribable event types / fire a synthetic test delivery
types_ = await client.webhooks.list_event_types()
result = await client.webhooks.test(wh["id"])

# Delivery logs (paginated)
logs = await client.webhooks.get_logs(wh["id"], per_page=50)
```

### Webhook verification — `construct_event` (recommended)

Verifies a delivery AND returns the parsed, typed event in one step. Pass
the RAW request body (never re-serialized JSON), the delivery headers, and
your endpoint secret. Raises `WebhookSignatureVerificationError` on any
failure — missing header, bad signature, stale timestamp, non-JSON body:

```python
from knoxcall import construct_webhook_event, WebhookSignatureVerificationError

try:
    event = construct_webhook_event(request.body, request.headers, "whsec_...")
except WebhookSignatureVerificationError:
    return 400

if event["event"] == "request.server_error":
    alert(event["data"]["route_name"], event["data"]["response"]["status"])
```

`format=` matches the webhook's configured `hmac_format`: `"legacy"`
(default), `"stripe"`, `"github"`, `"slack"`, `"aws-sns"`, or `"custom"`
(pass `header_name=`). `tolerance_seconds` (default 300) bounds replay;
pass `None` to disable. Also available as `client.webhooks.construct_event()`
on both facades.

The boolean helper remains for compatibility:

```python
# As a standalone function
from knoxcall import verify_webhook_signature

valid = verify_webhook_signature(
    raw_body=request.body,
    signature=request.headers["X-Webhook-Signature"],
    secret="whsec_...",
    tolerance_seconds=300,
)

# Or directly on the client
valid = client.verify_signature(
    raw_body=request.body,
    signature=request.headers["X-Webhook-Signature"],
    secret="whsec_...",
)
```

### mTLS clients

```python
# Create a client
c = await client.clients.create(name="backend-server", ip_address="10.0.0.5")
await client.clients.update(c["id"], enabled=False)
await client.clients.delete(c["id"])

# Manage credentials (IP allowlist, mTLS thumbprints, etc.)
creds = await client.clients.list_credentials(c["id"])

# Add an IP credential
cred = await client.clients.create_credential(c["id"],
    kind="ip", data={"ip_address": "10.0.0.5"}, label="prod server")

# Issue an mTLS certificate (the one-shot "reveal" carries the PEMs — save them immediately)
cred = await client.clients.create_credential(c["id"],
    kind="mtls_thumbprint", data={"mode": "issue"}, label="auto-issued cert")
# cred["reveal"]["certificate_pem"], cred["reveal"]["private_key_pem"], cred["reveal"]["ca_chain_pem"]

await client.clients.update_credential(c["id"], cred["id"], enabled=False)
await client.clients.delete_credential(c["id"], cred["id"])
```

### OAuth 2.1 clients

```python
# Create — client_secret returned ONCE, save it immediately
oc = await client.oauth_clients.create(
    name="ci-runner",
    grant_types=["client_credentials"],
    require_dpop=True,
    token_format="opaque",
)
secret = oc["client_secret"]  # save this now (oc.get("warning") reminds you)

apps = await client.oauth_clients.list()  # plain list — no pagination on this endpoint

await client.oauth_clients.update(oc["id"],
    allowed_scopes=["routes:read", "secrets:read"])

# Rotate secret (returns new secret once)
new_creds = await client.oauth_clients.rotate_secret(oc["id"])

# Revoke (cascades to all active tokens)
await client.oauth_clients.revoke(oc["id"])
```

### Environments

```python
envs = await client.environments.list()  # plain list
env = await client.environments.create(name="staging", color="#f59e0b")
await client.environments.update(env["id"], display_name="Staging")
await client.environments.delete(env["id"])
```

### API keys

```python
page = await client.api_keys.list(per_page=50)
key = await client.api_keys.create(name="ci-key")   # key["api_key"] shown ONCE
await client.api_keys.revoke(key["key_id"])
```

### Account

```python
account = await client.account.get()          # slug, plan, trial/billing dates
usage = await client.account.get_usage()      # API calls + resource counts vs limits
print(usage["api_calls"]["used"], "/", usage["api_calls"]["limit"])
```

### Audit logs

```python
async for entry in client.audit_logs.iterate(action="secret.created"):
    print(entry["created_at"], entry["action"], entry["resource_id"])
```

### Agents

```python
agent = await client.agents.create(name="build-agent")  # agent["agent_secret"] shown ONCE
agents = await client.agents.list()                     # plain list
events = await client.agents.get_tamper_events(agent["id"])
await client.agents.revoke(agent["id"])
```

### Crypto (encryption-as-a-service)

Keyed transit operations:

```python
key = await client.crypto.create_key(name="app-key", mode="encrypt")
enc = await client.crypto.encrypt("app-key", plaintext="hello")
dec = await client.crypto.decrypt("app-key", ciphertext=enc["ciphertext"], format="utf8")
await client.crypto.rotate_key("app-key")
sig = await client.crypto.sign_jwt("signing-key", claims={"sub": "user_1"})
```

Portable `kc:` encryption — structure-preserving over arbitrary JSON:

```python
enc = await client.crypto.encrypt_data({"ssn": "123-45-6789"})    # leaves become kc: strings
dec = await client.crypto.decrypt_data(enc["data"])
info = await client.crypto.inspect(enc["data"]["ssn"])            # metadata, no decryption
bundle = await client.crypto.get_sealing_bundle()                 # browser-side sealing pubkey
tok = await client.crypto.mint_client_token(action="decrypt", data=enc["data"]["ssn"])
```

### PKI (private CA)

```python
root = await client.pki.create_root(name="internal", subject={"common_name": "Acme Internal CA"})
await client.pki.create_role("internal", role_name="services", allowed_domains=["svc.acme.internal"])
leaf = await client.pki.issue_cert("internal", "services",
    subject={"common_name": "api.svc.acme.internal"})
pem = await client.pki.get_root_cert("internal")   # raw PEM string
crl = await client.pki.get_crl("internal")         # raw CRL text
```

### Vaults (tokenization)

```python
vault = await client.vaults.create(name="pci", token_format="uuid")
tok = await client.vaults.tokenize("pci", value="4242424242424242")
plain = await client.vaults.detokenize("pci", tok["token"])

async for t in client.vaults.iterate_tokens("pci"):
    print(t["token"], t["expires_at"])

result = await client.vaults.delete("pci")  # result["deleted"] is the vault NAME string
```

### Dynamic DB credentials

```python
await client.dynamic_db.create(name="reports-db", engine="postgres",
    host="db.internal", admin_username="postgres", admin_password="...")
await client.dynamic_db.create_role("reports-db", name="readonly", template="postgres_readonly")
cred = await client.dynamic_db.mint("reports-db", "readonly", ttl_seconds=900)
# cred["username"] / cred["password"] (shown once) / cred["lease_id"]
leases = await client.dynamic_db.list_leases(limit=20)   # {"leases": [...], "total", "limit", "offset"}
await client.dynamic_db.revoke_lease(cred["lease_id"])
```

### Signup (headless, no credentials)

Two steps: `signup()` returns a claim handle and emails a sign-in link; the
starter key is released once the account owner clicks it.

```python
import asyncio
from knoxcall import signup, claim_signup, signup_sync, claim_signup_sync

accepted = await signup(email="dev@example.com", tenant_name="Acme Inc")
handle = accepted["claim_handle"]          # a secret — it collects the key

# …the owner clicks the emailed sign-in link…
claim = await claim_signup(claim_handle=handle)
while claim["status"] == "pending":        # a normal success, not an error
    await asyncio.sleep(accepted["poll_after_seconds"])
    claim = await claim_signup(claim_handle=handle)

# claim["starter"]["api_key"]["api_key"] is a one-time test key — store it now
accepted = signup_sync(email="dev@example.com", tenant_name="Acme Inc")  # sync variants
claim = claim_signup_sync(claim_handle=handle)
```

`signup()` is enumeration-safe: its reply is identical whether or not the address
already has an account. Both calls raise `SignupError` (a `KnoxCallError`
subclass with `.status` / `.type`) on failure.

## DPoP

```python
client = KnoxCall(tenant="acme", dpop="always")
```

The SDK generates an ES256 keypair, binds the access token via `cnf.jkt`, and signs a fresh proof on every request — both admin API calls and proxy `call()` requests.

In the default `"auto"` mode the SDK starts with plain Bearer tokens and upgrades to DPoP automatically if the OAuth client record has `require_dpop` set.

## Thread safety & long-lived processes

The sync client is thread-safe: all I/O runs on one dedicated background
event-loop thread, so a single instance can be shared as a module-level
singleton across request threads (gunicorn, Frappe, Django, Celery). It also
survives `fork()` — a child process lazily rebuilds its own loop and
connection pool on first use.

```python
_client = None

def knoxcall():
    global _client
    if _client is None:
        _client = KnoxCall(tenant="acme", bootstrap=...)
    return _client
```

A token rejected by the server (rotation, revocation, restart) is purged and
re-minted once automatically — on both the admin API and proxy `call()`
paths — so a long-lived singleton never wedges on a dead cached token. If
the token endpoint is briefly unreachable, a cached token that has entered
the refresh-ahead window but is still genuinely valid keeps being used.

## Request bodies

JSON bodies are encoded with support for `datetime`/`date`/`time`
(ISO 8601), `timedelta` (seconds), `Decimal` (float), `UUID` (str), and
`set` (list) out of the box — ORM/ERP dicts serialize without preprocessing.
Pass `json_default=` to override, or pass `bytes`/`str` (with your own
`Content-Type` header) to send a pre-serialized body untouched.

## Redis token store (multi-instance)

```python
from redis.asyncio import Redis
from knoxcall import KnoxCall, RedisTokenStore

store = RedisTokenStore(Redis.from_url("redis://localhost"))
client = KnoxCall(tenant="acme", sync=False, token_store=store)
```

## Typed responses

Every resource method's return shape is declared as a `TypedDict` in
`knoxcall.types` (e.g. `types.Route`, `types.RoutePage`, `types.Vault`) —
erased at runtime, no validation layer, but IDEs and mypy see the exact
server fields.

## Error handling

```python
from knoxcall import RateLimitError, ValidationError, AuthenticationError, NotFoundError

try:
    await client.routes.create(name="x", target_base_url="https://api.example.com")
except ValidationError as e:
    print(e.fields)
except RateLimitError as e:
    await asyncio.sleep(e.retry_after or 1)
except AuthenticationError:
    await client.authenticate()
except NotFoundError:
    pass
```

The SDK automatically retries admin-API calls on 408, 429, 500, 502, 503, 504 with exponential backoff + jitter (3 attempts by default), honoring `Retry-After` on 429 (capped at 30s). Mutating requests get an auto-generated idempotency key so retries are safe. A 401 triggers one transparent token re-mint before the error is raised. 403 maps to `PermissionDeniedError` (the old `PermissionError` name shadowed Python's builtin and remains as a deprecated alias).

Proxy `call()` / `ephemeral()` return the raw response without raising on HTTP status (the upstream's status belongs to you), but transport failures are mapped to `APIConnectionError`/`APIConnectionTimeoutError` and retried when safe: connection-refused errors always (the request never left), later failures (read timeout, idle-keepalive reset) only for GET/HEAD so a mutating request is never replayed.

## Constructor parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `tenant` | `str` | auto-discovered | Tenant slug; falls back to `$KNOXCALL_TENANT`, then discovery from the credential |
| `environment` | `str` | `$KNOXCALL_ENVIRONMENT` | Default environment for `call()`/routes (per-call and bound values win) |
| `client_id` / `client_secret` | `str` | env | OAuth client-credentials (flat form) |
| `access_token` / `api_key` | `str` | env | Pre-acquired token/key (flat form) |
| `sync` | `bool` | `True` | `True` = sync client, `False` = async client |
| `sandbox` | `bool` | `False` | Test mode: defaults `base_url` to `https://sandbox.knoxcall.com` and the data plane to `https://sandbox-{tenant}.knoxcall.com` (explicit `base_url` / `KNOXCALL_BASE_URL` win) |
| `base_url` | `str` | `https://api.knoxcall.com` | Admin API base URL |
| `proxy_base_url` | `str` | derived from tenant | Proxy base URL for `call()` |
| `dpop` | `"auto"` \| `"always"` \| `"never"` | `"auto"` | DPoP mode |
| `scope` | `list[str]` | `[]` | OAuth scopes to request |
| `token_store` | `TokenStore` | `MemoryTokenStore` | Where tokens are cached |
| `retry_max_attempts` | `int` | `3` | Max retry attempts |
| `timeout` | `float` | `30.0` | HTTP timeout in seconds (per-request override: `call(..., timeout=120)`) |
| `json_default` | `Callable[[Any], Any]` | built-in encoder | `json.dumps` fallback for request bodies |

## License

Apache-2.0
