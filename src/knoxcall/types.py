"""Typed response models for every KnoxCall /v1 resource method.

Aligned field-by-field to the server's success-response catalog (each handler
wraps its payload in ``{"data": ..., "meta": ...}``; resource methods unwrap
``data`` — paginated lists return the full typed page envelope).

These are :class:`typing.TypedDict` declarations — erased at runtime, no
validation layer. ``total=False`` sections mark fields the server only
includes conditionally.
"""

from __future__ import annotations

from typing import Any, TypedDict

__all__ = [
    # Pagination
    "PageMeta",
    "RoutePage",
    "RouteLogPage",
    "SecretPage",
    "WebhookPage",
    "WebhookLogPage",
    "ClientPage",
    "ApiKeyPage",
    "Role",
    "RolePage",
    "AuditLogPage",
    "AuditEventPage",
    "CursorMeta",
    "RequestLog",
    "RequestLogPage",
    "RequestLogProof",
    "ProofStep",
    "ProofAnchor",
    "VaultPage",
    "VaultTokenPage",
    # Routes
    "Route",
    "RouteDetail",
    "RouteFull",
    "RouteLogEntry",
    "RouteEnvironmentListItem",
    "RouteEnvironmentConfig",
    "RouteAction",
    "DeleteResult",
    "NameDeleteResult",
    # Secrets
    "Secret",
    "SecretEnvironmentVersion",
    "SecretOAuthToken",
    "SecretCreateResult",
    "SecretUpdateResult",
    "SecretValueResult",
    # Wrap-credential escrow
    "WrapEscrowResult",
    # Wrap base-URL gateway tokens
    "WrapGatewayUrlResult",
    "WrapGatewayToken",
    "WrapGatewayTokenRevokeResult",
    # Opportunities
    "Opportunity",
    "OpportunityPage",
    "AcceptedOpportunityRoute",
    "AcceptOpportunityResult",
    "OpportunityDismissResult",
    # Webhooks
    "Webhook",
    "WebhookDetail",
    "WebhookCreateResult",
    "WebhookUpdateResult",
    "WebhookLogEntry",
    "WebhookEventTypeInfo",
    "WebhookEventTypesData",
    "WebhookTestResult",
    # Webhook event construction
    "WebhookEvent",
    "RequestEventData",
    "RequestEventRequest",
    "RequestEventResponse",
    "AuditEventData",
    # Clients
    "Client",
    "ClientDetail",
    "ClientRouteAssignment",
    "ClientFull",
    "ClientCredential",
    "ClientCredentialReveal",
    # Environments
    "Environment",
    "EnvironmentFull",
    # API keys
    "ApiKey",
    "ApiKeyCreateResult",
    "ApiKeyRevokeResult",
    # Account
    "Account",
    "AccountUsage",
    "BillingPeriod",
    "ApiCallUsage",
    "ResourceUsageEntry",
    "ResourceUsage",
    # Audit logs
    "AuditLogEntry",
    # Agents
    "Agent",
    "AgentCreateResult",
    "AgentRevokeResult",
    "TamperEvent",
    # OAuth clients
    "OAuthClient",
    "OAuthClientDetail",
    "OAuthClientCreateResult",
    "OAuthClientUpdateResult",
    "OAuthClientRotateSecretResult",
    "OAuthClientRevokeResult",
    # PKI
    "CARoot",
    "CARole",
    "CreateRootResult",
    "RotateIntermediateResult",
    "IssuedCertificate",
    "RevokeCertResult",
    # Vaults
    "Vault",
    "VaultStats",
    "VaultDetail",
    "RotateResult",
    "VaultToken",
    "BulkTokenizeResult",
    "VaultTokenListItem",
    "DetokenizeResult",
    "TokenUpdateResult",
    # Dynamic DB credentials
    "DbConnectionCreateResult",
    "DbConnection",
    "DbUpdateResult",
    "RotateSshKeyResult",
    "DbRoleCreateResult",
    "DbRole",
    "MintedDbCredential",
    "DbLease",
    "DbLeaseList",
    "LeaseRevokeResult",
    # Crypto / transit
    "TransitKey",
    "TransitKeyListItem",
    "KeyRotateResult",
    "KeyUpdateResult",
    "KeyVersionDestroyResult",
    "EncryptResult",
    "DecryptResult",
    "RewrapResult",
    "SignResult",
    "VerifyResult",
    "PublicKeyResult",
    "JwtSignResult",
    "JwtVerifyResult",
    "WebhookSignResult",
    # Portable (kc:) encryption
    "EncryptDataResult",
    "DecryptDataResult",
    "InspectResult",
    "InspectKeyRef",
    "ClientTokenResult",
    "SealingKeyRef",
    "SealingBundle",
    # Signup
    "SignupTenant",
    "StarterRoute",
    "StarterApiKey",
    "StarterResources",
    "SignupSandbox",
    "SignupResult",
    "SignupClaimResult",
    # Workflows
    "Workflow",
    "WorkflowPage",
    "WorkflowExecution",
    "WorkflowExecutionPage",
    "WorkflowRun",
    "WorkflowDeleteResult",
    "WorkflowCancelResult",
    # AI Gateway
    "AIGateway",
    "AIGatewayPage",
    "AIGatewayArchiveResult",
    "AIGatewayAgent",
    "AIGatewayAgentPage",
    "AIGatewayMcpServer",
    "AIGatewayMcpServerPage",
    "AIGatewayMcpTool",
    "AIGatewayMcpToolPage",
    "AIGatewayMcpToolDeleteResult",
    "AIGatewayToken",
    "AIGatewayTokenPage",
    "AIGatewayMintedToken",
    "AIGatewayTokenRevokeResult",
    "AIGatewayUsageByModel",
    "AIGatewayUsageTotals",
    "AIGatewayUsage",
    "AIGatewayUsageExportRow",
    "AIGatewayUsageExport",
    "AIGatewayFirewallRule",
    "AIGatewayFirewallPolicy",
    "AIGatewayFirewallPolicyPage",
    "AIGatewayFirewallTestMatch",
    "AIGatewayFirewallTestResult",
    "AIGatewayFirewallDeleteResult",
    "AIGatewayPiiPolicy",
    "AIGatewayPiiPolicyPage",
    "AIGatewayPiiRecognizer",
    "AIGatewayPiiRecognizerPage",
    "AIGatewayPiiTestMatch",
    "AIGatewayPiiTestResult",
    "AIGatewayPiiDeleteResult",
]


# ── Pagination envelope ───────────────────────────────────────────────────────
# Paginated endpoints take ``page`` / ``per_page`` query params (server
# default 20, cap 100) and return ``{data: [...], meta: PageMeta}``.
#
# TWO endpoints are keyset/cursor paginated instead, deliberately: ``GET
# /v1/audit-logs/events`` and ``GET /v1/logs``. Offset pagination over a table
# that is being written to skips and repeats rows with no way to tell which,
# which is fine for a console and wrong for a feed. Those return ``CursorMeta``.
# (Earlier revisions of this comment said there was no cursor pagination
# anywhere in the API; that stopped being true when the audit event feed
# shipped.)


class PageMeta(TypedDict):
    total: int
    page: int
    per_page: int
    total_pages: int
    request_id: str


class CursorMeta(TypedDict):
    """``meta`` on a keyset feed (``GET /v1/audit-logs/events``, ``GET /v1/logs``).

    ``next_cursor`` is OPAQUE: pass it back verbatim, never parse or rebuild it.
    ``None`` means the feed is drained to the watermark, NOT that it has ended.
    """

    next_cursor: str | None
    limit: int
    delivery: str
    dedupe_on: str
    watermark_seconds: int

# ── Routes ────────────────────────────────────────────────────────────────────


class Route(TypedDict):
    """GET /v1/routes row."""

    id: str
    name: str
    slug: str | None
    # Derived from the base environment's config; None only when the route
    # has no environment configs.
    target_base_url: str | None
    base_environment: str | None
    enabled: bool
    requires_clients: bool
    collection_id: str | None
    created_at: str
    environment_override_count: int
    require_signature: bool | None
    rate_limit_enabled: bool | None
    rate_limit_requests: int | None
    rate_limit_window_sec: int | None
    allowed_methods: list[str] | None


class RoutePage(TypedDict):
    data: list[Route]
    meta: PageMeta


class _RouteDetailBase(TypedDict):
    id: str
    name: str
    slug: str | None
    # Derived from the base environment's config; None only when the route
    # has no environment configs.
    target_base_url: str | None
    base_environment: str | None
    enabled: bool
    requires_clients: bool
    mtls_certificate_id: str | None
    collection_id: str | None
    created_at: str
    environment_override_count: int
    configured_environments: list[str]


class RouteDetail(_RouteDetailBase, total=False):
    """GET /v1/routes/:id — the ``total=False`` fields are only present when a
    base-environment config row exists."""

    payload_structure: dict[str, Any]
    injection_rules: list[Any]
    ip_allowlist: list[str]
    data_plane_node_id: str | None


class RouteFull(TypedDict):
    """POST / PATCH /v1/routes — the full ``routes`` row."""

    id: str
    tenant_id: str
    name: str
    slug: str | None
    sandbox: bool
    # Derived from the base environment's config (echoed from the request on create).
    target_base_url: str | None
    enabled: bool
    created_at: str
    requires_clients: bool
    base_environment: str | None
    mtls_certificate_id: str | None
    egress_server_id: str | None
    collection_id: str | None
    favicon_url: str | None
    favicon_updated_at: str | None
    favicon_data: str | None


class DeleteResult(TypedDict):
    deleted: bool


class NameDeleteResult(TypedDict):
    """DELETE result whose ``deleted`` value is the NAME/ID STRING rather than
    ``True`` (vaults, vault tokens, dyn-db connections/roles) — do not unify."""

    deleted: str


class RouteLogEntry(TypedDict):
    """GET /v1/routes/:id/logs row (``api_requests``)."""

    id: str
    request_id: str
    ts: str
    src_ip: str | None
    method: str
    path: str
    status_code: int | None
    latency_ms: int | None
    upstream_host: str | None
    error: str | None
    environment: str | None
    rate_limited: bool
    signature_valid: bool | None
    source_ip_country: str | None
    source_ip_city: str | None


class RouteLogPage(TypedDict):
    data: list[RouteLogEntry]
    meta: PageMeta


class RouteEnvironmentListItem(TypedDict):
    """GET /v1/routes/:id/environments item (bare array)."""

    environment_name: str
    target_base_url: str
    inject_headers_json: dict[str, Any]
    inject_body_json: dict[str, Any]
    require_signature: bool
    signature_tolerance_sec: int
    rate_limit_enabled: bool
    rate_limit_requests: int | None
    rate_limit_window_sec: int | None
    rate_limit_burst: int | None
    allowed_methods: list[str] | None


class RouteEnvironmentConfig(TypedDict):
    """PUT /v1/routes/:id/environments/:env — full ``route_environment_configs`` row."""

    id: str
    route_id: str
    environment_name: str
    target_base_url: str
    inject_headers_json: dict[str, Any]
    inject_body_json: dict[str, Any]
    created_at: str
    updated_at: str
    require_signature: bool
    signature_tolerance_sec: int
    rate_limit_enabled: bool
    rate_limit_requests: int | None
    rate_limit_window_sec: int | None
    rate_limit_burst: int | None
    allowed_methods: list[str] | None
    method_configs: list[Any] | None
    use_method_specific_configs: bool | None
    http_method_restrictions_enabled: bool | None
    egress_server_id: str | None
    # Per-environment enforcement knobs (migrations 20260723/20260724)
    enabled: bool
    requires_clients: bool
    mtls_certificate_id: str | None
    payload_structure: dict[str, Any]
    injection_rules: list[Any]
    ip_allowlist: list[str]
    data_plane_node_id: str | None
    intercept_enabled: bool


class RouteAction(TypedDict):
    """Route field-action (declarative field-level encrypt/decrypt/tokenize)."""

    id: str
    direction: str  # "request" | "response"
    action: str  # "encrypt" | "decrypt" | "tokenize" | "detokenize"
    selectors: list[str]
    key_name: str | None
    data_role: str | None
    content_type: str


# ── Secrets ───────────────────────────────────────────────────────────────────


class SecretEnvironmentVersion(TypedDict):
    """One entry of ``Secret["environments"]`` (GET /v1/secrets/:id).

    ``value_version`` counts genuine value writes for this environment,
    starting at 1 when its first value is stored. It moves ONLY for writes
    that change the stored value — rotations, admin value/certificate
    updates, platform-managed custodial key rotation — and deliberately not
    for OAuth2 token refreshes, expiry-override edits, certificate metadata
    re-parsing, or a re-encryption of the same plaintext under a new tenant
    key. Compare it against the version your own last write returned to
    detect a rotation performed outside your tooling; ``updated_at`` cannot
    be used for that, because non-value writes move it too.
    """

    environment_name: str
    value_version: int
    updated_at: str
    expires_at_override: str | None


class Secret(TypedDict, total=False):
    """GET /v1/secrets row (same shape for GET /v1/secrets/:id).

    ``environments`` is present only on GET /v1/secrets/:id.
    """

    id: str
    name: str
    shortcode_name: str
    base_environment: str | None
    secret_type: str  # "string" | "oauth2" | "certificate"
    collection_id: str | None
    created_at: str
    expires_at: str | None
    strict_expiry_enforcement: bool
    environment_count: int
    environments: list[SecretEnvironmentVersion]


class SecretPage(TypedDict):
    data: list[Secret]
    meta: PageMeta


class SecretOAuthToken(TypedDict):
    access_token: str
    expires_at: str | None
    token_type: str
    connection_status: str


class _SecretCreateBase(TypedDict):
    id: str
    name: str
    secret_type: str
    base_environment: str
    collection_id: str | None


class SecretCreateResult(_SecretCreateBase, total=False):
    """POST /v1/secrets — extra fields vary by secret type
    (string / oauth2 / certificate)."""

    shortcode_name: str
    environment_count: int
    expires_at: str | None
    strict_expiry_enforcement: bool
    provider: str
    redirect_uri: str
    connection_status: str
    mtls_certificate_id: str | None
    certificate_type: str
    metadata: dict[str, Any]


class SecretUpdateResult(TypedDict):
    id: str
    name: str
    expires_at: str | None
    strict_expiry_enforcement: bool


class SecretValueResult(TypedDict):
    """PUT /v1/secrets/:id/value result.

    ``value_version`` is the environment's version AFTER this write — 1 when
    this call stored the environment's first value, otherwise the previous
    version plus one. It is the version this call produced, so storing it has
    no read-after-write race with a concurrent rotation.
    """

    id: str
    name: str
    environment: str
    value_version: int


# ── Wrap-credential escrow ────────────────────────────────────────────────────


class WrapEscrowResult(TypedDict):
    """POST /v1/wrap/credentials result.

    The raw provider credential is escrowed (sent once, never returned). The
    result carries only the metadata needed to reference the stored secret and
    the host pin that constrains where it may be used upstream.
    """

    secret_id: str
    name: str
    provider: str
    allowed_hosts: list[str]
    sandbox: bool


# ── Wrap base-URL gateway tokens ──────────────────────────────────────────────


class _WrapGatewayUrlBase(TypedDict):
    id: str
    token: str
    base_url: str
    host: str
    secret_id: str
    sandbox: bool
    expires_at: str | None


class WrapGatewayUrlResult(_WrapGatewayUrlBase, total=False):
    """POST /v1/wrap/tokens result — a minted base-URL gateway token.

    ``base_url`` is what you set as the wrapped SDK's base URL; the SDK's own key
    becomes a placeholder because KnoxCall injects the escrowed secret server-side.
    ``token`` is a bearer credential embedded in ``base_url`` — treat it as a
    secret, never store or log it. ``id`` is the handle for
    :meth:`WrapResource.revoke_gateway_token`.

    ``base_url_style`` (``"path"`` | ``"subdomain"``) reports which ``base_url``
    form the server returned; it is present only when the server includes it.
    """

    base_url_style: str


class WrapGatewayToken(TypedDict):
    """GET /v1/wrap/tokens row — a gateway token's metadata.

    The token itself is NEVER returned by list; only the metadata needed to
    identify and manage it.
    """

    id: str
    secret_id: str
    host: str
    label: str | None
    created_at: str
    expires_at: str | None
    revoked_at: str | None
    last_used_at: str | None


class InterceptManifestRoute(TypedDict, total=False):
    """One entry of the intercept manifest: an upstream host an intercept-enabled
    Route covers. `ambiguous` is present (True) only when another entry shares
    the same (host, base_path)."""

    host: str
    base_path: str
    slug: str
    route_id: str
    requires_clients: bool
    allowed_methods: list[str] | None
    ambiguous: bool
    updated_at: str | None


class InterceptManifest(TypedDict):
    """GET /v1/wrap/intercept-manifest — which hosts an intercept-enabled Route
    covers for one environment. `version` doubles as the ETag."""

    version: str
    ttl_seconds: int
    environment: str
    sandbox: bool
    routes: list[InterceptManifestRoute]


class EgressObservation(TypedDict):
    """One uncovered-egress observation (PARITY §21.3): a credentialed call the
    interceptor sent DIRECT because no Route covered its host and nobody listed
    it. Names, never values — `header_name` is the credential header's NAME,
    never its value; `first_segment` is `/` or `/<first path segment>`, never
    the query string, never deeper. `first_seen` / `last_seen` are ISO-8601 UTC."""

    host: str
    first_segment: str
    method: str
    header_name: str
    count: int
    first_seen: str
    last_seen: str


class _EgressObservationsReportBase(TypedDict):
    accepted: int
    dropped: int
    reasons: dict[str, int]


class EgressObservationsReport(_EgressObservationsReportBase, total=False):
    """POST /v1/wrap/egress-observations result: what the server did with a
    report. `redacted` counts accepted entries whose content the server
    reduced, by reason (e.g. `first_segment_looks_like_credential`)."""

    redacted: dict[str, int]


class WrapGatewayTokenRevokeResult(TypedDict):
    """DELETE /v1/wrap/tokens/:id result."""

    id: str
    revoked: bool


# ── Opportunities ─────────────────────────────────────────────────────────────


class Opportunity(TypedDict):
    """GET /v1/opportunities row — a detected outbound-usage promotion candidate.

    ``source`` is ``"agent_monitor"`` (client-agent telemetry) or
    ``"gateway_traffic"`` (proxy detection, refreshed on list). ``status`` moves
    ``pending`` → ``onboarded`` (via :meth:`accept`) or ``dismissed``.
    """

    id: str
    source: str
    service: str
    destination_host: str | None
    status: str
    confidence: float | None
    suggested_route_json: dict[str, Any] | None
    evidence_json: dict[str, Any] | None
    accepted_route_id: str | None
    created_at: str
    updated_at: str
    acted_at: str | None


class OpportunityPage(TypedDict):
    data: list[Opportunity]
    meta: PageMeta


class AcceptedOpportunityRoute(TypedDict):
    id: str
    slug: str | None
    name: str


class AcceptOpportunityResult(TypedDict):
    """POST /v1/opportunities/:id/accept result — the durable route the
    suggestion was promoted into, plus the collection/environment it landed in."""

    opportunity_id: str
    route: AcceptedOpportunityRoute
    collection_id: str
    environment: str


class OpportunityDismissResult(TypedDict):
    """POST /v1/opportunities/:id/dismiss result."""

    opportunity_id: str
    status: str


# ── Webhooks ──────────────────────────────────────────────────────────────────


class Webhook(TypedDict):
    """GET /v1/webhooks row."""

    id: str
    name: str
    description: str | None
    url: str
    method: str
    event_types: list[str]
    auth_type: str
    enabled: bool
    last_triggered_at: str | None
    trigger_count: int
    success_count: int
    failure_count: int
    created_at: str


class WebhookPage(TypedDict):
    data: list[Webhook]
    meta: PageMeta


class WebhookDetail(TypedDict):
    """GET /v1/webhooks/:id.

    `request_headers` is deliberately absent (server fix row 2-492): it is
    accepted on create/update but never returned, because the dispatcher
    spreads it into the outbound header map alongside the
    `auth_config`-derived ``Authorization``, so a value stored there is
    indistinguishable from a destination API key. Same reason ``secret_key``
    and ``auth_config`` have never been on this type.
    """

    id: str
    name: str
    description: str | None
    url: str
    method: str
    event_types: list[str]
    auth_type: str
    route_filter: list[str] | None
    include_request_body: bool
    include_response_body: bool
    include_headers: bool
    timeout_seconds: int
    retry_on_failure: bool
    max_retries: int
    enabled: bool
    last_triggered_at: str | None
    last_success_at: str | None
    last_failure_at: str | None
    trigger_count: int
    success_count: int
    failure_count: int
    created_at: str


class WebhookCreateResult(TypedDict):
    """POST /v1/webhooks — ``secret_key`` is returned ONCE."""

    id: str
    name: str
    description: str | None
    url: str
    method: str
    event_types: list[str]
    auth_type: str
    enabled: bool
    hmac_key_id: str | None
    hmac_format: str | None
    hmac_header_name: str | None
    created_at: str
    secret_key: str


class WebhookUpdateResult(TypedDict):
    id: str
    name: str
    description: str | None
    url: str
    method: str
    event_types: list[str]
    auth_type: str
    enabled: bool
    created_at: str


class WebhookLogEntry(TypedDict):
    id: str
    http_method: str | None
    target_url: str | None
    source_ip: str | None
    response_status: int | None
    response_time_ms: int | None
    executed_at: str
    success: bool
    error_message: str | None


class WebhookLogPage(TypedDict):
    data: list[WebhookLogEntry]
    meta: PageMeta


class WebhookEventTypeInfo(TypedDict):
    value: str
    label: str
    description: str


class WebhookEventTypesData(TypedDict):
    event_types: list[WebhookEventTypeInfo]


class _WebhookTestBase(TypedDict):
    success: bool
    response_time_ms: int


class WebhookTestResult(_WebhookTestBase, total=False):
    status: int
    error: str


# ── Webhook event construction (construct_event) ─────────────────────────────


class RequestEventRequest(TypedDict):
    method: str
    path: str
    ip: str


class RequestEventResponse(TypedDict):
    status: int
    latency_ms: int


class RequestEventData(TypedDict):
    """``data`` for the ``request.*`` event family."""

    route_id: str
    route_name: str
    environment: str
    request: RequestEventRequest
    response: RequestEventResponse


class AuditEventData(TypedDict):
    """``data`` for ``audit.event``."""

    id: str
    action: str
    resource_type: str
    resource_id: str | None
    details: dict[str, Any]
    ip_address: str | None


class _WebhookEventBase(TypedDict):
    event: str
    timestamp: str
    data: Any  # RequestEventData for request.*, AuditEventData for audit.event


class WebhookEvent(_WebhookEventBase, total=False):
    """A verified webhook delivery envelope. ``webhook_id``/``webhook_name``
    are present on ``request.*`` events and absent on ``audit.event``.
    Unknown event types parse fine — the list is open."""

    webhook_id: str
    webhook_name: str


# ── Clients ───────────────────────────────────────────────────────────────────


class Client(TypedDict):
    """GET /v1/clients row."""

    id: str
    name: str
    type: str  # "user" | "server"
    ip_address: str
    ip_notes: dict[str, Any]
    description: str | None
    enabled: bool
    collection_id: str | None
    created_at: str
    updated_at: str


class ClientPage(TypedDict):
    data: list[Client]
    meta: PageMeta


class ClientRouteAssignment(TypedDict):
    route_id: str
    route_name: str
    environment_name: str


class ClientDetail(Client):
    """GET /v1/clients/:id."""

    route_assignments: list[ClientRouteAssignment]


class ClientFull(TypedDict):
    """POST / PATCH /v1/clients — the full ``clients`` row."""

    id: str
    tenant_id: str
    name: str
    type: str
    ip_address: str
    description: str | None
    enabled: bool
    created_at: str
    updated_at: str
    created_by: str | None
    collection_id: str | None
    ip_notes: dict[str, Any]
    agent_version: str | None
    agent_os: str | None
    agent_arch: str | None
    agent_hostname: str | None
    agent_last_seen: str | None
    agent_mode: str | None


class _ClientCredentialBase(TypedDict):
    id: str
    client_id: str
    tenant_id: str
    kind: str  # ip | mtls_thumbprint | signature_hmac | signature_ed25519 | machine_id | workload_identity
    label: str | None
    data: dict[str, Any]  # redacted — secret_ct / private_key_pem stripped
    enabled: bool
    expires_at: str | None
    created_at: str
    updated_at: str
    last_matched_at: str | None


class ClientCredentialReveal(TypedDict):
    certificate_pem: str
    private_key_pem: str
    ca_chain_pem: str


class ClientCredential(_ClientCredentialBase, total=False):
    """``reveal`` is a ONE-SHOT extra on mTLS 'issue'-mode creation."""

    reveal: ClientCredentialReveal


# ── Environments ──────────────────────────────────────────────────────────────


class Environment(TypedDict):
    """GET /v1/environments row (bare array)."""

    id: str
    name: str
    display_name: str
    description: str | None
    color: str
    is_default: bool
    created_at: str


class EnvironmentFull(Environment):
    """POST / PATCH /v1/environments — full row."""

    tenant_id: str
    sandbox: bool


# ── API keys ──────────────────────────────────────────────────────────────────


class ApiKey(TypedDict):
    """GET /v1/api-keys row."""

    id: str
    key_id: str
    key_prefix: str
    key_type: str  # test | standard | access_key
    name: str
    active: bool
    created_at: str
    last_used_at: str | None
    rate_limit_requests: int | None
    rate_limit_window_sec: int | None


class ApiKeyPage(TypedDict):
    data: list[ApiKey]
    meta: PageMeta


class Role(TypedDict):
    """GET /v1/roles row. Rule bodies are deliberately not exposed on /v1."""

    id: str
    name: str
    description: str | None
    applies_to: list[str]  # subset of {"user", "api_key"}
    is_default: bool
    # True for platform-maintained roles. Only a seeded key role is accepted in
    # ``role_ids``; False marks a custom role, which is being retired.
    seeded: bool


class RolePage(TypedDict):
    data: list[Role]
    meta: PageMeta


class ApiKeyCreateResult(TypedDict):
    """POST /v1/api-keys — ``api_key`` is returned ONCE."""

    id: str
    role_ids: list[str]
    key_id: str
    api_key: str
    key_prefix: str
    key_type: str
    name: str
    message: str


class ApiKeyRevokeResult(TypedDict):
    revoked: bool


# ── Account ───────────────────────────────────────────────────────────────────


class Account(TypedDict):
    id: str
    slug: str
    name: str
    region: str
    subscription_plan: str
    subscription_status: str
    trial_start_at: str | None
    trial_end_at: str | None
    subscription_current_period_start: str | None
    subscription_current_period_end: str | None
    subscription_cancel_at: str | None
    created_at: str


class BillingPeriod(TypedDict):
    year: int
    month: int
    start: str | None
    end: str | None


class ApiCallUsage(TypedDict):
    used: int
    limit: int | None
    percentage: int


class ResourceUsageEntry(TypedDict):
    used: int
    limit: int | None


class ResourceUsage(TypedDict):
    routes: ResourceUsageEntry
    secrets: ResourceUsageEntry
    clients: ResourceUsageEntry
    environments: ResourceUsageEntry


class AccountUsage(TypedDict):
    billing_period: BillingPeriod
    api_calls: ApiCallUsage
    resources: ResourceUsage
    plan: str
    status: str


class RequestLog(TypedDict, total=False):
    """``GET /v1/logs`` row (``api_requests``).

    The first twelve keys are exactly what the Merkle anchor commits to, in
    order; everything after ``ts`` is operational detail and is NOT part of the
    leaf. ``total=False`` because the identity tier (``src_ip``,
    ``matched_client_id``, ``identification_method``) is ABSENT — not ``None`` —
    when the caller lacks ``log:read_identity``.
    """

    # ``api_requests.id`` is a bigint, so it is a decimal STRING: a JSON number
    # is a double and cannot hold one exactly past 2**53.
    id: str
    request_id: str
    tenant_id: str
    route_id: str | None
    matched_client_id: str | None
    identification_method: str | None
    method: str | None
    status_code: int | None
    src_ip: str | None
    environment: str | None
    # Live/Test partition. ``None`` on rows written before the partition
    # existed, which are treated as Live. None/False/True are three distinct
    # facts and the anchor keeps them apart.
    sandbox: bool | None
    ts: str

    path: str | None
    latency_ms: int | None
    upstream_host: str | None
    error: str | None
    rate_limited: bool | None
    proxy_mode: str | None
    # How the call arrived at the Route: ``"sdk_intercept"`` when a KnoxCall
    # SDK's route-aware interceptor rerouted a third-party SDK's request
    # (PARITY §21.2), ``"direct"`` for a plain ``call()`` and for every row
    # written before the marker existed. Informational only.
    client_origin: str
    cursor: str


class RequestLogPage(TypedDict):
    data: list[RequestLog]
    meta: CursorMeta


class ProofStep(TypedDict):
    """One sibling on the path from leaf to root.

    ``right`` True means the sibling is the RIGHT operand: hash(acc, sibling).
    """

    hash: str
    right: bool


class ProofAnchor(TypedDict):
    id: str
    sequence_number: str
    anchored_at: str
    algo: str
    merkle_root: str
    leaf_count: int
    from_id: str
    to_id: str
    chain_row_hash: str | None


class RequestLogProof(RequestLog, total=False):
    """``GET /v1/logs/{request_id}/proof``.

    Read ``anchored`` and ``verified`` rather than the status code — every
    outcome is a 200. ``reason`` is one of ``not_yet_anchored``,
    ``range_incomplete``, ``range_grew``, ``root_mismatch``,
    ``row_not_in_range`` or ``anchor_range_too_large``. ``range_incomplete`` is
    the EXPECTED result once retention has trimmed an anchored range and is not
    a sign of tampering; ``root_mismatch`` is. ``proof`` is absent whenever
    ``verified`` is not True.
    """

    anchored: bool
    verified: bool
    reason: str
    detail: str
    observed_leaf_count: int
    recomputed_root: str | None
    anchor: ProofAnchor
    leaf_index: int
    leaf_hash: str
    proof: list[ProofStep]
    verification: dict[str, Any]

# ── Audit logs ────────────────────────────────────────────────────────────────


class _AuditLogEntryBase(TypedDict):
    id: str
    action: str
    resource_type: str
    resource_id: str | None
    # Always sanitised by the server (credential-shaped values and URL userinfo
    # removed); ``{}`` when ``details_redacted`` is true.
    details: dict[str, Any]
    ip_address: str | None
    created_at: str


class AuditLogEntry(_AuditLogEntryBase, total=False):
    """One ``GET /v1/audit-logs`` row.

    ``details_redacted`` is ``True`` when ``details`` was withheld from this
    caller: a user-bound token whose holder may not read audit details (only
    Admins and Owners may). API keys and OAuth clients holding
    ``audit_log:list`` always receive sanitised details. Not required, because
    older servers do not send it.
    """

    details_redacted: bool


class AuditLogPage(TypedDict):
    data: list[AuditLogEntry]
    meta: PageMeta


class AuditEventPage(TypedDict):
    """``GET /v1/audit-logs/events`` — the keyset feed a SIEM shipper uses."""

    data: list[AuditLogEntry]
    meta: CursorMeta


# ── Agents ────────────────────────────────────────────────────────────────────


class Agent(TypedDict):
    """GET /v1/agents row (bare array)."""

    id: str
    name: str
    agent_id: str
    status: str  # active | revoked
    require_verified_build: bool
    last_seen_at: str | None
    last_session_issued_at: str | None
    created_at: str
    has_tamper_events: bool


class AgentCreateResult(TypedDict):
    """POST /v1/agents — ``agent_secret`` is returned ONCE."""

    id: str
    name: str
    agent_id: str
    status: str
    require_verified_build: bool
    created_at: str
    agent_secret: str


class AgentRevokeResult(TypedDict):
    revoked: bool


class TamperEvent(TypedDict):
    id: str
    version_reported: str | None
    build_sig_reported: str | None
    src_ip: str | None
    action_taken: str | None
    detected_at: str


# ── OAuth clients ─────────────────────────────────────────────────────────────


class OAuthClient(TypedDict):
    """GET /v1/oauth-clients row (bare list, no pagination)."""

    id: str
    client_id: str
    name: str
    type: str  # confidential | public
    grant_types: list[str]
    allowed_scopes: list[str]
    redirect_uris: list[str]
    require_dpop: bool
    require_pkce: bool  # always True; PKCE is mandatory on the authorization-code flow
    token_format: str  # always "opaque" (the RFC 9068 "jwt" format was withdrawn)
    active: bool
    revoked_at: str | None
    created_at: str
    last_used_at: str | None
    source_api_key_id: str | None
    source_key_type: str | None
    system_role: str | None  # 'cli' on the auto-provisioned CLI client (protected)


class OAuthClientDetail(TypedDict):
    """GET /v1/oauth-clients/:id."""

    id: str
    client_id: str
    name: str
    type: str
    grant_types: list[str]
    allowed_scopes: list[str]
    redirect_uris: list[str]
    require_dpop: bool
    require_pkce: bool  # always True; PKCE is mandatory on the authorization-code flow
    token_format: str
    active: bool
    revoked_at: str | None
    created_at: str
    last_used_at: str | None
    source_api_key_id: str | None
    step_up_scopes: list[str]
    system_role: str | None  # 'cli' on the auto-provisioned CLI client (protected)


class _OAuthClientCreateBase(TypedDict):
    id: str
    client_id: str
    client_secret: str | None  # None for public clients
    type: str
    grant_types: list[str]
    allowed_scopes: list[str]
    redirect_uris: list[str]


class OAuthClientCreateResult(_OAuthClientCreateBase, total=False):
    """POST /v1/oauth-clients — the server's top-level ``warning`` is
    attached to the returned object when present."""

    warning: str


class OAuthClientUpdateResult(TypedDict):
    id: str


class _OAuthClientRotateBase(TypedDict):
    client_id: str
    client_secret: str


class OAuthClientRotateSecretResult(_OAuthClientRotateBase, total=False):
    warning: str


class OAuthClientRevokeResult(TypedDict):
    revoked: bool


# ── PKI ───────────────────────────────────────────────────────────────────────


class CARoot(TypedDict):
    id: str
    tenant_id: str
    name: str
    cert_pem: str
    subject: str
    subject_fields: dict[str, Any] | None
    not_before: str
    not_after: str
    status: str  # active | retired | revoked
    created_at: str
    sandbox: bool


class CARole(TypedDict):
    id: str
    ca_root_id: str
    name: str
    allowed_domains: list[str]
    allow_subdomains: bool
    allow_wildcards: bool
    max_ttl_seconds: int
    default_ttl_seconds: int
    key_algorithm: str  # "ecdsa-p256"


class CreateRootResult(TypedDict):
    root: CARoot
    intermediate_not_after: str


class RotateIntermediateResult(TypedDict):
    intermediate_id: str
    not_after: str


class IssuedCertificate(TypedDict):
    serial_hex: str
    cert_pem: str
    private_key_pem: str
    ca_chain_pem: str
    not_before: str
    not_after: str


class RevokeCertResult(TypedDict):
    revoked: bool


# ── Vaults ────────────────────────────────────────────────────────────────────


class Vault(TypedDict):
    id: str
    tenant_id: str
    name: str
    token_format: str
    crypto_key_id: str
    custody_mode: str  # managed | dual
    default_ttl_seconds: int | None
    metadata_jsonb: dict[str, Any]
    description: str | None
    enabled: bool
    created_at: str
    updated_at: str
    created_by: str | None
    sandbox: bool


class VaultPage(TypedDict):
    data: list[Vault]
    meta: PageMeta


class VaultStats(TypedDict):
    token_count: int
    active_count: int
    expiring_in_24h: int


class VaultDetail(Vault):
    stats: VaultStats


class RotateResult(TypedDict):
    new_version: int


class VaultToken(TypedDict):
    """POST /v1/vaults/:v/tokens (tokenize)."""

    id: str
    token: str
    expires_at: str | None
    created_at: str
    # The LAST DAY of the CARD's expiry month ("2029-07-31"), or None.
    # Not ``expires_at``, which is how long the TOKEN lives. Present only
    # for a ``pan`` vault whose tokenize call supplied card_exp_month /
    # card_exp_year; a token created before 2026-09-17 carries None and
    # cannot be backfilled, because the expiry was never captured.
    card_expires_on: str | None
    # BIN intelligence: how the issuer funds the card ("credit" / "debit" /
    # "prepaid") and the issuer's country as ISO 3166-1 alpha-2, derived from
    # the card's first six digits. BOTH ARE None ON EVERY TOKEN TODAY and will
    # be until KnoxCall licenses a BIN table -- treat them as optional
    # indefinitely. Also None for every non-``pan`` vault.
    card_funding_type: str | None
    card_issuing_country: str | None


class BulkTokenizeResult(TypedDict):
    tokens: list[VaultToken]
    count: int


class VaultTokenListItem(TypedDict):
    id: str
    token: str
    expires_at: str | None
    created_at: str
    created_by_api_key_id: str | None
    created_by_user_id: str | None
    # See VaultToken.card_expires_on.
    card_expires_on: str | None
    # See VaultToken.card_funding_type / card_issuing_country.
    card_funding_type: str | None
    card_issuing_country: str | None


class VaultTokenPage(TypedDict):
    data: list[VaultTokenListItem]
    meta: PageMeta


class DetokenizeResult(TypedDict):
    id: str
    token: str
    expires_at: str | None
    created_at: str
    value: str
    value_b64: str
    metadata: dict[str, Any] | None
    crypto_key_version: int


class TokenUpdateResult(TypedDict):
    updated: bool


# ── Dynamic DB credentials ────────────────────────────────────────────────────


class DbConnectionCreateResult(TypedDict):
    id: str
    name: str
    engine: str  # postgres | mysql | mongo
    execution_mode: str  # direct | agent_tunnel | ssh_tunnel | iam


class DbConnection(TypedDict):
    """GET /v1/dyn-db-credentials row (bare array; same shape for GET /:name)."""

    id: str
    name: str
    engine: str
    host: str
    port: int | None
    database_name: str | None
    admin_username: str
    execution_mode: str
    agent_id: str | None
    default_ttl_seconds: int
    max_ttl_seconds: int
    connect_options: dict[str, Any]
    enabled: bool
    created_at: str
    updated_at: str
    ssh_host: str | None
    ssh_port: int | None
    ssh_username: str | None
    iam_region: str | None
    iam_db_user: str | None


class DbUpdateResult(TypedDict):
    updated: str  # the connection / role NAME string


class RotateSshKeyResult(TypedDict):
    rotated: str
    fingerprint_updated: bool


class DbRoleCreateResult(TypedDict):
    id: str
    name: str
    connection: str


class DbRole(TypedDict):
    id: str
    name: str
    creation_sql_template: str
    revocation_sql_template: str
    default_ttl_seconds: int | None
    max_ttl_seconds: int | None
    created_at: str
    updated_at: str


class MintedDbCredential(TypedDict):
    """POST /:name/creds/:role — ``password`` is returned ONCE."""

    username: str
    password: str
    expires_at: str
    lease_id: int
    connection_name: str
    role_name: str


class DbLease(TypedDict):
    id: int
    status: str
    expires_at: str
    issued_at: str
    username: str | None
    connection_name: str | None
    role_name: str | None
    engine: str | None


class DbLeaseList(TypedDict):
    """GET /leases — pagination lives INSIDE data (limit/offset), unlike
    the page/per_page envelope everywhere else."""

    leases: list[DbLease]
    total: int
    limit: int
    offset: int


class LeaseRevokeResult(TypedDict):
    revoked: int  # the lease id


# ── Crypto / transit ──────────────────────────────────────────────────────────


class TransitKey(TypedDict):
    id: str
    tenant_id: str
    name: str
    key_type: str
    mode: str  # cloud-only | bundled
    current_version: int
    deletion_allowed: bool
    description: str | None
    created_at: str
    updated_at: str
    created_by: str | None
    sandbox: bool


class TransitKeyListItem(TypedDict):
    """GET /v1/crypto/keys row (projection — no tenant_id/created_by/sandbox)."""

    id: str
    name: str
    key_type: str
    mode: str
    current_version: int
    deletion_allowed: bool
    description: str | None
    created_at: str
    updated_at: str


class KeyRotateResult(TypedDict):
    new_version: int


class KeyUpdateResult(TypedDict):
    name: str
    deletion_allowed: bool


class KeyVersionDestroyResult(TypedDict):
    destroyed: int


class EncryptResult(TypedDict):
    ciphertext: str
    key_version: int


class _DecryptBase(TypedDict):
    key_version: int


class DecryptResult(_DecryptBase, total=False):
    plaintext_b64: str
    plaintext: str  # only with ?format=utf8


class RewrapResult(TypedDict):
    ciphertext: str
    key_version: int


class SignResult(TypedDict):
    signature: str
    key_version: int


class VerifyResult(TypedDict):
    valid: bool
    key_version: int


class PublicKeyResult(TypedDict):
    pem: str
    jwk: dict[str, Any]
    key_version: int


class JwtSignResult(TypedDict):
    token: str
    key_version: int
    alg: str


class _JwtVerifyBase(TypedDict):
    valid: bool


class JwtVerifyResult(_JwtVerifyBase, total=False):
    claims: dict[str, Any]
    key_version: int
    alg: str
    error: str
    kid: str


class WebhookSignResult(TypedDict):
    signature_header: str  # "t=<unix>,v1=<hex>"
    timestamp_seconds: int
    key_version: int
    format: str  # "stripe"


# ── Portable (kc:) encryption ─────────────────────────────────────────────────


class EncryptDataResult(TypedDict):
    ciphertext: Any
    key: str
    key_version: int


class DecryptDataResult(TypedDict):
    plaintext: Any


class InspectKeyRef(TypedDict):
    tenantId: str
    appKeyId: str
    keyVersion: int


class _InspectBase(TypedDict):
    encrypted: bool


class InspectResult(_InspectBase, total=False):
    scheme: str
    version: int
    datatype: str
    key_ref: InspectKeyRef
    fingerprint: str


class _ClientTokenBase(TypedDict):
    token: str
    expires_at: str
    action: str


class ClientTokenResult(_ClientTokenBase, total=False):
    #: ``tokenize`` only — the resolved vault the capability is bound to.
    vault_id: str
    #: ``tokenize`` only — the normalized, deduped, sorted origin binding.
    origins: list[str]


class SealingKeyRef(TypedDict):
    tenant_id: str
    app_key_id: str
    key_version: int


class SealingBundle(TypedDict):
    public_key_raw: str  # base64url raw EC point
    key_ref: SealingKeyRef


# ── Signup ────────────────────────────────────────────────────────────────────


class SignupTenant(TypedDict):
    id: str
    slug: str
    name: str
    region: str
    plan: str


class StarterRoute(TypedDict):
    id: str
    name: str
    target_base_url: str


class StarterApiKey(TypedDict):
    id: str
    key_id: str
    api_key: str  # ONE-TIME test key
    key_prefix: str
    key_type: str  # "test"


class StarterResources(TypedDict):
    route: StarterRoute | None
    api_key: StarterApiKey
    sandbox_host: str
    curl: str


class SignupSandbox(TypedDict):
    management_api: str
    proxy_host: str
    note: str


class SignupResult(TypedDict):
    """POST /v1/signup ``data`` — the 202 every signup gets.

    Identical whether or not the address already has an account (that is what
    makes the call enumeration-safe), and it carries NO credential. The
    starter key is collected later, from :func:`claim_signup`, once the emailed
    sign-in link has been clicked. Rewritten 2026-08-28: the endpoint used to
    answer 201 with an instant key, which was an account-existence oracle
    (wave-2 row 2-561).
    """

    status: str  # always "pending"
    claim_handle: str  # opaque, single-use — treat it as a secret
    claim_path: str  # "/v1/signup/claim"
    poll_after_seconds: int
    expires_at: str
    message: str
    documentation: str


class SignupClaimResult(TypedDict, total=False):
    """POST /v1/signup/claim ``data``.

    ``status`` discriminates: ``"pending"`` (a 202, and a perfectly normal
    SUCCESS — the sign-in link has not been used yet) carries ``message``,
    ``poll_after_seconds`` and ``expires_at``; ``"ready"`` (the 200, returned
    exactly once) carries ``tenant``, ``starter``, ``sandbox`` and
    ``documentation``. Every key is optional here BECAUSE the two shapes
    differ — read ``status`` first.
    """

    status: str
    message: str
    poll_after_seconds: int
    expires_at: str
    tenant: SignupTenant
    starter: StarterResources
    sandbox: SignupSandbox
    documentation: str


# ── Workflows ─────────────────────────────────────────────────────────────────


class _WorkflowBase(TypedDict):
    id: str
    name: str
    description: str | None
    definition: Any
    environment: str | None
    enabled: bool
    version: int
    sandbox: bool
    timeout_seconds: int | None
    published_at: str | None
    created_at: str
    updated_at: str


class Workflow(_WorkflowBase, total=False):
    """GET /v1/workflows row (same shape for GET/POST/PATCH …/:id).

    ``run_count`` is only present on the paginated list rows.
    """

    run_count: int


class WorkflowPage(TypedDict):
    data: list[Workflow]
    meta: PageMeta


class _WorkflowExecutionBase(TypedDict):
    id: str
    workflow_id: str
    status: str
    trigger_type: str
    started_at: str | None
    completed_at: str | None
    execution_time_ms: int | None
    error_message: str | None
    workflow_version: int | None
    created_at: str


class WorkflowExecution(_WorkflowExecutionBase, total=False):
    """A workflow execution (run). ``node_executions`` (the composed step
    details) is only present on ``get_execution``."""

    node_executions: list[Any]


class WorkflowExecutionPage(TypedDict):
    data: list[WorkflowExecution]
    meta: PageMeta


class WorkflowRun(TypedDict):
    """The queued-execution acknowledgement returned by ``execute``."""

    id: str
    workflow_id: str
    status: str


class WorkflowDeleteResult(TypedDict):
    id: str
    deleted: bool


class WorkflowCancelResult(TypedDict):
    id: str
    status: str


# ── AI Gateway ────────────────────────────────────────────────────────────────


class AIGateway(TypedDict):
    """GET /v1/ai-gateway/gateways row (same shape for GET/POST/PATCH …/:id)."""

    id: str
    tenant_id: str
    name: str
    slug: str
    description: str | None
    budget_daily_usd: float | None
    budget_monthly_usd: float | None
    # AIGW-150: "block" | "warn" -- what happens when a cap above is spent.
    # "block" refuses on BOTH data planes (/v1/ai with 429 budget_exceeded,
    # /v1/mcp on tools/call); "warn" serves and emits X-Knox-AI-Budget-*.
    # There is deliberately no "fallback": that action swaps an AGENT's route
    # and model, which a gateway does not have.
    budget_overage_action: str
    status: str  # active | paused | archived
    paused_reason: str | None
    created_at: str
    updated_at: str
    created_by: str | None


class AIGatewayPage(TypedDict):
    data: list[AIGateway]
    meta: PageMeta


class AIGatewayArchiveResult(TypedDict):
    """DELETE …/gateways/:id and …/agents/:id — archive (soft delete)."""

    id: str
    status: str  # "archived"


class AIGatewayAgent(TypedDict):
    """GET /v1/ai-gateway/agents/:id (same shape for the list rows and
    POST/PATCH …/agents)."""

    id: str
    tenant_id: str
    gateway_id: str
    name: str
    slug: str
    description: str | None
    primary_route_id: str | None
    fallback_route_ids: list[str]
    model_allowlist: list[str]
    model_denylist: list[str]
    default_model: str | None
    model_rewrite: dict[str, Any]
    budget_daily_usd: float | None
    budget_monthly_usd: float | None
    budget_per_call_max_tokens: int | None
    budget_overage_action: str
    fallback_agent_id: str | None
    pii_redact_policy_id: str | None
    # AIGW-100: read-only mirror of (pii_response_mode == "detokenize").
    pii_detokenize_response: bool
    # AIGW-100: "off" | "tokenize" -- what happens to the PROMPT before it
    # leaves KnoxCall. "off" is the only mode on which the provider receives the
    # real value.
    pii_request_mode: str
    # AIGW-100: "redact" | "detokenize" -- what happens to the answer.
    pii_response_mode: str
    pii_streaming_holdback_chars: int
    # "holdback" | "buffer" | "monitor". "monitor" reports detections without
    # rewriting the stream, so the raw value reaches the client -- read it
    # before concluding a streamed answer was redacted.
    pii_streaming_mode: str
    #: FinOps attribution labels (cost_center/team/project/...) echoed onto this
    #: agent's usage rows.
    tags: dict[str, str]
    #: Upstream shape this agent fronts (anthropic|openai|gemini|cohere|
    #: azure-openai|ollama). Set once, at create time -- deliberately NOT
    #: patchable, because changing it without re-pointing ``primary_route_id``
    #: at a matching route would make the stored value a lie. ``None`` on a
    #: pre-AIGW-20 agent whose route shape the backfill did not recognise;
    #: render that as "custom", never as a guess.
    provider: str | None
    cache_mode: str
    cache_ttl_seconds: int
    cache_similarity_threshold: float | None
    cache_embedding_model: str | None
    streaming_enabled: bool
    firewall_policy_id: str | None
    tool_allowlist: list[str]
    output_schema: dict[str, Any] | None
    output_validation_action: str
    data_residency_region: str | None
    cmek_key_id: str | None
    status: str
    paused_reason: str | None
    #: AIGW-42 retry/fail-over policy as stored. The server normalises and
    #: CLAMPS it on every read, so the values here are what was WRITTEN, not
    #: necessarily what the data plane will honour.
    routing_policy: dict[str, Any]
    #: AIGW-45 external guardrail webhook. ``guardrail_webhook_mode`` is the
    #: STRING "off" when the agent has no hook -- never a boolean.
    guardrail_webhook_url: str | None
    guardrail_webhook_secret_id: str | None
    guardrail_webhook_mode: str
    guardrail_webhook_timeout_ms: int
    guardrail_webhook_failure_action: str
    #: Data-plane base URL for this agent -- ``https://{tenant}.knoxcall.com/v1/ai/{slug}``.
    #: Point an AI SDK's ``base_url`` here with a capability token as the API key.
    #: Server-computed, not stored: it MOVES when ``slug`` changes, and is ``""``
    #: when the tenant slug cannot be resolved -- treat empty as "not available".
    agent_url: str
    created_at: str
    updated_at: str
    created_by: str | None


class AIGatewayAgentPage(TypedDict):
    data: list[AIGatewayAgent]
    meta: PageMeta


class AIGatewayMcpServer(TypedDict):
    """GET /v1/ai-gateway/mcp-servers/:id (same shape for list rows and
    POST/PATCH).

    ``connect_url`` and ``resource`` are deliberately DIFFERENT values:
    ``connect_url`` is where an MCP client points (the tenant data-plane host),
    ``resource`` is the RFC 8707 value a token for this server must be bound to.
    """

    id: str
    gateway_id: str | None
    name: str
    slug: str | None
    description: str | None
    server_type: str          # "upstream" | "collection" (only upstream is creatable)
    transport: str | None     # "streamable_http" | "sse"
    upstream_url: str | None
    allowed_tools: list[str]  # EMPTY means the server advertises nothing
    pii_inspection: bool
    auth: dict[str, Any]      # only {{secret_id:…}} references, never a credential
    # AIGW-151: the tenant PII policy whose recognizers apply to this server's
    # tool arguments and results. None = every enabled recognizer this tenant
    # owns, on top of the built-ins. A policy id you do not own is refused 422.
    pii_redact_policy_id: str | None
    firewall_policy_id: str | None
    # AIGW-150: the tenant's own external scanner. `guardrail_webhook_mode` is
    # "off" | "request" | "response" | "both" -- `request` sees the tool
    # ARGUMENTS after redaction and before they leave, `response` sees the tool
    # RESULT before it is returned. No streaming carve-out on this plane.
    guardrail_webhook_url: str | None
    guardrail_webhook_secret_id: str | None
    guardrail_webhook_mode: str
    guardrail_webhook_timeout_ms: int
    guardrail_webhook_failure_action: str
    # AIGW-152: which Live/Test space this server lives in. READ-ONLY -- taken
    # from the mode of the request that created it. Reads and writes are confined
    # to the calling key's own space, a capability token reaches only servers in
    # its own space, and the same slug may exist in both.
    sandbox: bool
    status: str
    created_at: str
    updated_at: str
    connect_url: str
    resource: str


class AIGatewayMcpServerPage(TypedDict):
    data: list[AIGatewayMcpServer]
    meta: PageMeta


class AIGatewayMcpTool(TypedDict):
    """A tool metadata row. It does not widen what the server advertises."""

    id: str
    tenant_id: str
    mcp_server_id: str
    tool_name: str
    route_id: str | None
    description: str | None
    input_schema: dict[str, Any]
    enabled: bool
    created_at: str
    updated_at: str


class AIGatewayMcpToolPage(TypedDict):
    data: list[AIGatewayMcpTool]
    meta: PageMeta


class AIGatewayMcpToolDeleteResult(TypedDict):
    id: str
    deleted: bool


class AIGatewayToken(TypedDict):
    """GET /v1/ai-gateway/agents/:agentId/tokens row — NEVER carries plaintext."""

    id: str
    name: str | None
    kind: str  # agent | read | tool | oneshot
    prefix: str
    dpop_required: bool
    scope_jsonb: dict[str, Any]
    expires_at: str | None
    revoked_at: str | None
    last_used_at: str | None
    created_at: str


class AIGatewayTokenPage(TypedDict):
    data: list[AIGatewayToken]
    meta: PageMeta


class AIGatewayMintedToken(TypedDict, total=False):
    """POST /v1/ai-gateway/agents/:agentId/tokens — ``token`` is the plaintext,
    shown ONCE (``meta.note`` warns it won't be shown again)."""

    id: str
    name: str
    kind: str
    prefix: str
    token: str  # plaintext — shown once
    dpop_required: bool
    expires_at: str | None


class AIGatewayTokenRevokeResult(TypedDict):
    id: str
    revoked: bool  # always True


class AIGatewayUsageByModel(TypedDict):
    provider: str
    model: str
    requests: int
    input_tokens: int
    output_tokens: int
    cost_usd: float
    unpriced_requests: int


class AIGatewayUsageTotals(TypedDict):
    requests: int
    input_tokens: int
    output_tokens: int
    cost_usd: float
    unpriced_requests: int


class AIGatewayUsage(TypedDict):
    """GET /v1/ai-gateway/usage — cost + tokens by model over the period."""

    period_days: int
    by_model: list[AIGatewayUsageByModel]
    totals: AIGatewayUsageTotals


class AIGatewayUsageExportRow(TypedDict):
    """One aggregated row of a FinOps usage export."""

    group: str | None
    requests: int
    input_tokens: int
    output_tokens: int
    cost_usd: float
    unpriced_requests: int


class AIGatewayUsageExport(TypedDict):
    """GET /v1/ai-gateway/usage/export — spend grouped by user | team | agent |
    model | provider | ``tag:<key>`` over the period."""

    group_by: str
    period_days: int
    rows: list[AIGatewayUsageExportRow]


class AIGatewayFirewallRule(TypedDict, total=False):
    """One heuristic rule inside a firewall policy.

    ``regex`` patterns are compiled server-side with a linear-time engine, so
    lookahead, lookbehind and backreferences are rejected at write time (400)
    rather than stored and silently skipped when the policy runs.
    """

    name: str
    kind: str  # regex | keyword
    pattern: str
    flags: str  # only i, m, s, g, y — defaults to "i"; ignored for keyword


class AIGatewayFirewallPolicy(TypedDict):
    """GET/POST/PATCH /v1/ai-gateway/firewall-policies row.

    Tenant-scoped and shared across gateways. An agent with NO policy still runs
    the built-in prompt-injection patterns but its outcome can never exceed
    ``warn``; attach one with ``action="block"`` to have matching requests
    refused with HTTP 400 ``firewall_block`` on the data plane.
    """

    id: str
    tenant_id: str
    name: str
    version: int
    heuristics: list[AIGatewayFirewallRule]
    canary_enabled: bool
    vector_classifier_enabled: bool
    lakera_enabled: bool
    model_classifier_id: str | None
    action: str  # block | warn | tag
    created_at: str


class AIGatewayFirewallPolicyPage(TypedDict):
    data: list[AIGatewayFirewallPolicy]
    meta: PageMeta


class AIGatewayFirewallTestMatch(TypedDict):
    rule: str
    span: list[int]
    matched: str


class AIGatewayFirewallTestResult(TypedDict):
    """POST /v1/ai-gateway/firewall-policies/test."""

    matched: bool
    matches: list[AIGatewayFirewallTestMatch]
    skipped: list[dict[str, str]]


class AIGatewayFirewallDeleteResult(TypedDict):
    id: str
    deleted: bool  # always True


# ── PII policies and recognizers (AIGW-160) ──────────────────────────────────


class AIGatewayPiiPolicy(TypedDict):
    """GET/POST/PATCH /v1/ai-gateway/pii-policies row.

    A tenant-scoped bundle of recognizers plus a default action, attached to an
    agent through ``pii_redact_policy_id`` — one policy serves any number of
    agents, so these sit at the mount root rather than under a gateway id.

    An EMPTY ``recognizer_ids`` does NOT mean "no recognizers": it means "every
    enabled recognizer this tenant owns". An empty list is the WIDEST policy,
    not the narrowest, which is why the server refuses to delete a recognizer a
    policy still lists — dropping the id would widen the policy rather than
    shrink it.
    """

    id: str
    tenant_id: str
    name: str
    version: int
    recognizer_ids: list[str]
    default_action: str  # redact | tokenize | whitelist | warn
    description: str | None
    created_at: str


class AIGatewayPiiPolicyPage(TypedDict):
    data: list[AIGatewayPiiPolicy]
    meta: PageMeta


class AIGatewayPiiRecognizer(TypedDict):
    """GET/POST/PATCH /v1/ai-gateway/pii-recognizers row — one tenant-defined
    PII detector.

    ``kind="regex"`` patterns are compiled server-side with a linear-time
    engine, so lookahead, lookbehind and backreferences are a 400 at write time
    rather than a detector that is stored and then silently skipped at scan
    time (fail-open). ``aho_corasick`` runs in-process too; the three
    ``presidio_*`` kinds are handed to a Presidio sidecar.
    """

    id: str
    tenant_id: str
    name: str
    # regex | aho_corasick | presidio_pattern | presidio_ner | presidio_custom
    kind: str
    pattern: str
    context_words: list[str]  # words that must appear nearby for a match to count
    confidence: float  # 0-1, server default 0.85
    action: str  # redact | tokenize | whitelist | warn
    format: str | None  # token format for `tokenize`; None for the rest
    enabled: bool  # False mutes the recognizer without losing its definition
    created_at: str


class AIGatewayPiiRecognizerPage(TypedDict):
    data: list[AIGatewayPiiRecognizer]
    meta: PageMeta


class AIGatewayPiiTestMatch(TypedDict):
    span: list[int]  # [start, end) character offsets into the sample text
    matched: str
    replacement: str  # what the data plane would substitute for `action`
    entity_type: str


class AIGatewayPiiTestResult(TypedDict):
    """POST /v1/ai-gateway/pii-recognizers/test — a dry run that saves nothing."""

    matched: bool
    matches: list[AIGatewayPiiTestMatch]


class AIGatewayPiiDeleteResult(TypedDict):
    id: str
    deleted: bool  # always True
