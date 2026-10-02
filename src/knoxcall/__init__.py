"""KnoxCall Python SDK — public exports."""

from . import types
from .client import KnoxCall, KnoxCallAsync
from .core import BoundRoute
from .login import ensure_login, ensure_login_sync, login, login_sync
from .resources import (
    AccountResource,
    AgentsResource,
    AIGatewayResource,
    ApiKeysResource,
    AuditLogsResource,
    ClientsResource,
    CryptoResource,
    DynamicDbResource,
    EnvironmentsResource,
    OAuthClientsResource,
    OpportunitiesResource,
    PkiResource,
    RoutesResource,
    SecretsResource,
    SignupError,
    VaultsResource,
    WebhooksResource,
    WorkflowsResource,
    WrapResource,
    KNOXCALL_AUDIENCE,
    TokenExchangeError,
    construct_webhook_event,
    exchange_token,
    exchange_token_sync,
    claim_signup,
    claim_signup_sync,
    signup,
    signup_sync,
    verify_webhook_signature,
)
from .errors import (
    AIGatewayError,
    APIConnectionError,
    APIConnectionTimeoutError,
    APIUserAbortError,
    AuthenticationError,
    BootstrapError,
    ConflictError,
    KnoxCallError,
    NotAuthenticatedError,
    ai_gateway_error_from,
    is_ai_gateway_error_body,
    NotFoundError,
    PaymentRequiredError,
    PermissionDeniedError,
    RateLimitError,
    ServerError,
    ValidationError,
    WebhookSignatureVerificationError,
)
from .wrap_transport import (
    DEFAULT_ROUTE_AROUND,
    KnoxWrapAsyncTransport,
    KnoxWrapTransport,
)
from ._intercept import InterceptDecision, intercept_kill_switch, resolve_intercept
from ._intercept_store import InterceptManifestStore
from ._intercept_patch import InterceptHandle, routed
from .resources.wrap import manifest_etag
from ._egress_observations import (
    EgressObservationReporter,
    credential_header_name,
    first_segment_looks_like_credential,
    is_credential_header_name,
    observation_first_segment,
    observation_for,
    observe_uncovered_disabled_by_env,
)
from .wrap_transport import (
    RouteAroundRule,
    WrapSandboxMismatchError,
)
from .auth.token_store import CachedToken, MemoryTokenStore, RedisTokenStore, TokenStore
from .auth.workload_provider import (
    ADVISORY_REFRESH_SECONDS,
    MANDATORY_REFRESH_SECONDS,
    StaleAssertionError,
    WorkloadAssertionSource,
    WorkloadCredentialProvider,
)
from .auth.bootstrap import (
    AccessToken,
    AccessTokenBootstrap,  # deprecated alias
    Bootstrap,
    ClientCredentials,
    ClientCredentialsBootstrap,  # deprecated alias
    OIDCTokenExchange,
    OidcTokenExchangeBootstrap,  # deprecated alias
    StoredCredentials,
)

__version__ = "1.1.0"

__all__ = [
    # Primary client
    "KnoxCall",
    "KnoxCallAsync",
    "BoundRoute",
    # Typed response models (TypedDicts, erased at runtime)
    "types",
    # Resource classes (for type annotations)
    "AccountResource",
    "AgentsResource",
    "AIGatewayResource",
    "ApiKeysResource",
    "AuditLogsResource",
    "ClientsResource",
    "CryptoResource",
    "DynamicDbResource",
    "EnvironmentsResource",
    "OAuthClientsResource",
    "OpportunitiesResource",
    "PkiResource",
    "RoutesResource",
    "SecretsResource",
    "VaultsResource",
    "WebhooksResource",
    "WorkflowsResource",
    "WrapResource",
    # Wrap data-plane transport (route a wrapped 3rd-party SDK through KnoxCall)
    "KnoxWrapTransport",
    "KnoxWrapAsyncTransport",
    # Route-aware interception (plan PR3)
    "InterceptDecision",
    "InterceptHandle",
    "InterceptManifestStore",
    "intercept_kill_switch",
    "manifest_etag",
    "resolve_intercept",
    "routed",
    # Uncovered-egress observations (PARITY §21.3)
    "EgressObservationReporter",
    "credential_header_name",
    "first_segment_looks_like_credential",
    "is_credential_header_name",
    "observation_first_segment",
    "observation_for",
    "observe_uncovered_disabled_by_env",
    "RouteAroundRule",
    "DEFAULT_ROUTE_AROUND",
    "WrapSandboxMismatchError",
    # Errors
    "KnoxCallError",
    # AIGW-163: the AI DATA plane's typed refusal. The SDK does not make that
    # call for you (you point a provider client at ``agent_url``), so the
    # factory ships alongside the class.
    "AIGatewayError",
    "ai_gateway_error_from",
    "is_ai_gateway_error_body",
    "APIConnectionError",
    "APIConnectionTimeoutError",
    "APIUserAbortError",
    "AuthenticationError",
    "PaymentRequiredError",
    "PermissionDeniedError",
    "NotFoundError",
    "ConflictError",
    "ValidationError",
    "RateLimitError",
    "ServerError",
    "BootstrapError",
    "NotAuthenticatedError",
    "WebhookSignatureVerificationError",
    # Token stores
    "MemoryTokenStore",
    "RedisTokenStore",
    "TokenStore",
    "CachedToken",
    # Workload identity federation
    "WorkloadCredentialProvider",
    "WorkloadAssertionSource",
    "StaleAssertionError",
    "ADVISORY_REFRESH_SECONDS",
    "MANDATORY_REFRESH_SECONDS",
    # Bootstrap / auth sources
    "Bootstrap",
    "AccessToken",
    "ClientCredentials",
    "OIDCTokenExchange",
    "StoredCredentials",
    # Deprecated bootstrap aliases (pre-release names)
    "AccessTokenBootstrap",
    "ClientCredentialsBootstrap",
    "OidcTokenExchangeBootstrap",
    # Webhook helpers (also available as client.verify_signature() /
    # client.webhooks.construct_event())
    "verify_webhook_signature",
    "construct_webhook_event",
    # Headless signup (unauthenticated — no client required)
    "signup",
    "signup_sync",
    "claim_signup",
    "claim_signup_sync",
    "SignupError",
    # OIDC workload federation (unauthenticated — the subject token IS the credential)
    "exchange_token",
    "exchange_token_sync",
    "TokenExchangeError",
    "KNOXCALL_AUDIENCE",
    # Interactive first-run login helpers (opt-in; never on the request path)
    "login",
    "ensure_login",
    "login_sync",
    "ensure_login_sync",
]
