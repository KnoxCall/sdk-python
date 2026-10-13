"""Top-level KnoxCall client — single import, sync or async."""

from __future__ import annotations
import asyncio
import os
import threading
from typing import Any, AsyncIterator, Coroutine, Iterator, Literal, overload

import httpx

from .core import APIClient
from .errors import KnoxCallError
from ._intercept_patch import InterceptHandle
from .resources.account import AccountResource
from .resources.agents import AgentsResource
from .resources.ai_gateway import AIGatewayResource
from .resources.api_keys import ApiKeysResource, RolesResource
from .resources.audit_logs import AuditLogsResource
from .resources.logs import LogsResource
from .resources.clients import ClientsResource
from .resources.crypto import CryptoResource
from .resources.dynamic_db import DynamicDbResource
from .resources.environments import EnvironmentsResource
from .resources.oauth_clients import OAuthClientsResource
from .resources.opportunities import OpportunitiesResource
from .resources.pki import PkiResource
from .resources.routes import RoutesResource
from .resources.secrets import SecretsResource
from .resources.vaults import VaultsResource
from .resources.webhooks import WebhooksResource
from .resources.workflows import WorkflowsResource
from .resources.wrap import WrapResource
from .wrap_transport import KnoxWrapTransport


class KnoxCallAsync(APIClient):
    """Async client — use as ``async with KnoxCall(tenant=..., sync=False) as client:``.

    Exposes every KnoxCall v1 API resource as a sub-client property.
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.routes = RoutesResource(self)
        self.secrets = SecretsResource(self)
        self.webhooks = WebhooksResource(self)
        self.clients = ClientsResource(self)
        self.oauth_clients = OAuthClientsResource(self)
        self.environments = EnvironmentsResource(self)
        self.api_keys = ApiKeysResource(self)
        self.roles = RolesResource(self)
        self.account = AccountResource(self)
        self.audit_logs = AuditLogsResource(self)
        # Per-call proxy request log + Merkle inclusion proofs. Not the change
        # log — that is `audit_logs`.
        self.logs = LogsResource(self)
        self.agents = AgentsResource(self)
        self.crypto = CryptoResource(self)
        self.pki = PkiResource(self)
        self.vaults = VaultsResource(self)
        self.dynamic_db = DynamicDbResource(self)
        self.ai_gateway = AIGatewayResource(self)
        self.workflows = WorkflowsResource(self)
        self.wrap = WrapResource(self)
        self.opportunities = OpportunitiesResource(self)


# ── Sync wrapper ──────────────────────────────────────────────────────────────

class _KnoxCallSync:
    """Synchronous wrapper — use as ``with KnoxCall(tenant=...) as client:``.

    Thread-safe: all async work runs on one dedicated background event-loop
    thread, so a single instance can be shared as a module-level singleton
    across request threads (gunicorn gthread, Frappe, Django, …). Concurrent
    calls interleave on that loop rather than blocking each other at the
    socket level; token refresh stays single-flight.
    """

    def __init__(self, **kwargs: Any) -> None:
        self._closed = False
        self._pid = os.getpid()
        self._lifecycle = threading.Lock()
        self._start_loop()
        try:
            self._async = KnoxCallAsync(**kwargs)
            self._run(self._async.__aenter__())
        except BaseException:
            self._stop_loop()
            raise
        self.routes = _SyncRoutes(self)
        self.secrets = _SyncSecrets(self)
        self.webhooks = _SyncWebhooks(self)
        self.clients = _SyncClients(self)
        self.oauth_clients = _SyncOAuthClients(self)
        self.environments = _SyncEnvironments(self)
        self.api_keys = _SyncApiKeys(self)
        self.roles = _SyncRoles(self)
        self.account = _SyncAccount(self)
        self.audit_logs = _SyncAuditLogs(self)
        self.agents = _SyncAgents(self)
        self.crypto = _SyncCrypto(self)
        self.pki = _SyncPki(self)
        self.vaults = _SyncVaults(self)
        self.dynamic_db = _SyncDynamicDb(self)
        self.ai_gateway = _SyncAIGateway(self)
        self.workflows = _SyncWorkflows(self)
        self.wrap = _SyncWrap(self)
        self.opportunities = _SyncOpportunities(self)

    def _start_loop(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._loop.run_forever, name="knoxcall-sync-loop", daemon=True
        )
        self._thread.start()

    def _stop_loop(self) -> None:
        if not self._loop.is_closed():
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._thread.join(timeout=5)
            self._loop.close()

    def _ensure_loop(self) -> None:
        # After a fork (gunicorn prefork with a pre-imported singleton) the
        # loop thread does not exist in the child and inherited pooled
        # connections belong to the parent — rebuild both, once, lazily.
        if os.getpid() == self._pid:
            return
        with self._lifecycle:
            if os.getpid() == self._pid:
                return
            self._start_loop()  # the parent's loop object is abandoned, not closed
            if self._async._own_http:
                self._async._http = None
            self._pid = os.getpid()

    def _run(self, coro: Coroutine[Any, Any, Any]) -> Any:
        if self._closed:
            coro.close()
            raise KnoxCallError("client is closed")
        self._ensure_loop()
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result()

    def _iter(self, aiter: AsyncIterator[Any]) -> Iterator[Any]:
        """Bridge an async iterator into a real sync generator: each
        ``__anext__`` runs on the background loop thread, so sync ``iterate*``
        walks pages exactly like the async client."""
        try:
            while True:
                try:
                    yield self._run(aiter.__anext__())
                except StopAsyncIteration:
                    return
        finally:
            # Close the async generator on its loop if abandoned early.
            aclose = getattr(aiter, "aclose", None)
            if aclose is not None and not self._closed:
                try:
                    self._run(aclose())
                except Exception:
                    pass

    def call(self, route: str, **kw: Any) -> httpx.Response:
        return self._run(self._async.call(route, **kw))

    def route(self, route: str, **kw: Any) -> "_SyncBoundRoute":
        return _SyncBoundRoute(self, self._async.route(route, **kw))

    def ephemeral(self, upstream_url: str, **kw: Any) -> httpx.Response:
        return self._run(self._async.ephemeral(upstream_url, **kw))

    def authenticate(self) -> None:
        self._run(self._async.authenticate())

    def sign_out(self) -> None:
        self._run(self._async.sign_out())

    @staticmethod
    def verify_signature(**kw: Any) -> bool:
        from .resources.webhooks import verify_webhook_signature as _verify
        return _verify(**kw)

    @staticmethod
    def construct_event(raw_body: str | bytes, headers: Any, secret: str, **kw: Any) -> Any:
        """Verify a webhook delivery AND return the typed event — see
        :func:`knoxcall.construct_webhook_event`."""
        from .resources.webhooks import construct_webhook_event as _construct
        return _construct(raw_body, headers, secret, **kw)

    def close(self) -> None:
        with self._lifecycle:
            if self._closed:
                return
            try:
                future = asyncio.run_coroutine_threadsafe(
                    self._async.__aexit__(None, None, None), self._loop
                )
                future.result(timeout=10)
                asyncio.run_coroutine_threadsafe(
                    self._loop.shutdown_asyncgens(), self._loop
                ).result(timeout=5)
            finally:
                self._closed = True
                self._stop_loop()

    def __enter__(self) -> "_KnoxCallSync":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


# ── Factory ───────────────────────────────────────────────────────────────────

@overload
def KnoxCall(*, sync: Literal[False], tenant: str | None = ..., **kwargs: Any) -> KnoxCallAsync: ...
@overload
def KnoxCall(*, sync: Literal[True] = ..., tenant: str | None = ..., **kwargs: Any) -> _KnoxCallSync: ...


def KnoxCall(  # type: ignore[misc]
    *, tenant: str | None = None, sync: bool = True, **kwargs: Any
) -> "_KnoxCallSync | KnoxCallAsync":
    """Create a KnoxCall client.

        # Sync (default) — scripts, notebooks, Django, Flask
        with KnoxCall(tenant="acme", client_id="tk_...", client_secret="...") as client:
            routes = client.routes.list()
            resp = client.call("3f1e2c9a-...", path="/v1/orders")

        # Zero-arg — credentials and tenant from the environment
        # (KNOXCALL_TENANT, KNOXCALL_CLIENT_ID, KNOXCALL_CLIENT_SECRET, ...)
        client = KnoxCall()

        # Async — FastAPI, async views, asyncio apps
        async with KnoxCall(tenant="acme", sync=False) as client:
            routes = await client.routes.list()
            resp = await client.call("3f1e2c9a-...", path="/v1/orders")
    """
    if sync:
        return _KnoxCallSync(tenant=tenant, **kwargs)
    return KnoxCallAsync(tenant=tenant, **kwargs)


# ── Sync resource wrappers ────────────────────────────────────────────────────

class _SyncBoundRoute:
    """Sync facade over core.BoundRoute — see _KnoxCallSync.route()."""

    def __init__(self, p: _KnoxCallSync, bound: Any) -> None:
        self._p = p
        self._bound = bound

    def request(self, method: str, path: str = "/", **kw: Any) -> httpx.Response:
        return self._p._run(self._bound.request(method, path, **kw))

    def get(self, path: str = "/", **kw: Any) -> httpx.Response:
        return self._p._run(self._bound.get(path, **kw))

    def post(self, path: str = "/", **kw: Any) -> httpx.Response:
        return self._p._run(self._bound.post(path, **kw))

    def put(self, path: str = "/", **kw: Any) -> httpx.Response:
        return self._p._run(self._bound.put(path, **kw))

    def patch(self, path: str = "/", **kw: Any) -> httpx.Response:
        return self._p._run(self._bound.patch(path, **kw))

    def delete(self, path: str = "/", **kw: Any) -> httpx.Response:
        return self._p._run(self._bound.delete(path, **kw))



class _SyncRoutes:
    def __init__(self, p: _KnoxCallSync) -> None:
        self._p = p

    def list(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.routes.list(**kw))

    def iterate(self, **kw: Any) -> Iterator[Any]:
        return self._p._iter(self._p._async.routes.iterate(**kw))

    def get(self, route_id: str) -> Any:
        return self._p._run(self._p._async.routes.get(route_id))

    def create(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.routes.create(**kw))

    def update(self, route_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.routes.update(route_id, **kw))

    def delete(self, route_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.routes.delete(route_id, **kw))

    def get_logs(self, route_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.routes.get_logs(route_id, **kw))

    def list_environments(self, route_id: str) -> Any:
        return self._p._run(self._p._async.routes.list_environments(route_id))

    def upsert_environment(self, route_id: str, env_name: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.routes.upsert_environment(route_id, env_name, **kw))

    def delete_environment(self, route_id: str, env_name: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.routes.delete_environment(route_id, env_name, **kw))

    def list_actions(self, route_id: str) -> Any:
        return self._p._run(self._p._async.routes.list_actions(route_id))

    def create_action(self, route_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.routes.create_action(route_id, **kw))

    def delete_action(self, route_id: str, action_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.routes.delete_action(route_id, action_id, **kw))


class _SyncSecrets:
    def __init__(self, p: _KnoxCallSync) -> None:
        self._p = p

    def list(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.secrets.list(**kw))

    def iterate(self, **kw: Any) -> Iterator[Any]:
        return self._p._iter(self._p._async.secrets.iterate(**kw))

    def get(self, secret_id: str) -> Any:
        return self._p._run(self._p._async.secrets.get(secret_id))

    def create(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.secrets.create(**kw))

    def create_oauth2(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.secrets.create_oauth2(**kw))

    def create_certificate(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.secrets.create_certificate(**kw))

    def update(self, secret_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.secrets.update(secret_id, **kw))

    def set_value(self, secret_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.secrets.set_value(secret_id, **kw))

    def get_oauth_token(self, secret_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.secrets.get_oauth_token(secret_id, **kw))

    def delete(self, secret_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.secrets.delete(secret_id, **kw))


class _SyncWebhooks:
    def __init__(self, p: _KnoxCallSync) -> None:
        self._p = p

    def list(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.webhooks.list(**kw))

    def iterate(self, **kw: Any) -> Iterator[Any]:
        return self._p._iter(self._p._async.webhooks.iterate(**kw))

    def get(self, webhook_id: str) -> Any:
        return self._p._run(self._p._async.webhooks.get(webhook_id))

    def create(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.webhooks.create(**kw))

    def update(self, webhook_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.webhooks.update(webhook_id, **kw))

    def delete(self, webhook_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.webhooks.delete(webhook_id, **kw))

    def get_logs(self, webhook_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.webhooks.get_logs(webhook_id, **kw))

    def list_event_types(self) -> Any:
        return self._p._run(self._p._async.webhooks.list_event_types())

    def test(self, webhook_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.webhooks.test(webhook_id, **kw))

    @staticmethod
    def construct_event(raw_body: str | bytes, headers: Any, secret: str, **kw: Any) -> Any:
        """Verify a webhook delivery AND return the typed event — see
        :func:`knoxcall.construct_webhook_event`. Pure computation, no HTTP."""
        from .resources.webhooks import construct_webhook_event as _construct
        return _construct(raw_body, headers, secret, **kw)


class _SyncClients:
    def __init__(self, p: _KnoxCallSync) -> None:
        self._p = p

    def list(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.clients.list(**kw))

    def iterate(self, **kw: Any) -> Iterator[Any]:
        return self._p._iter(self._p._async.clients.iterate(**kw))

    def get(self, client_id: str) -> Any:
        return self._p._run(self._p._async.clients.get(client_id))

    def create(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.clients.create(**kw))

    def update(self, client_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.clients.update(client_id, **kw))

    def delete(self, client_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.clients.delete(client_id, **kw))

    def list_credentials(self, client_id: str) -> Any:
        return self._p._run(self._p._async.clients.list_credentials(client_id))

    def create_credential(self, client_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.clients.create_credential(client_id, **kw))

    def update_credential(self, client_id: str, credential_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.clients.update_credential(client_id, credential_id, **kw))

    def delete_credential(self, client_id: str, credential_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.clients.delete_credential(client_id, credential_id, **kw))


class _SyncOAuthClients:
    def __init__(self, p: _KnoxCallSync) -> None:
        self._p = p

    def list(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.oauth_clients.list(**kw))

    def get(self, oauth_client_id: str) -> Any:
        return self._p._run(self._p._async.oauth_clients.get(oauth_client_id))

    def create(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.oauth_clients.create(**kw))

    def update(self, oauth_client_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.oauth_clients.update(oauth_client_id, **kw))

    def rotate_secret(self, oauth_client_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.oauth_clients.rotate_secret(oauth_client_id, **kw))

    def revoke(self, oauth_client_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.oauth_clients.revoke(oauth_client_id, **kw))


class _SyncEnvironments:
    def __init__(self, p: _KnoxCallSync) -> None:
        self._p = p

    def list(self) -> Any:
        return self._p._run(self._p._async.environments.list())

    def create(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.environments.create(**kw))

    def update(self, env_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.environments.update(env_id, **kw))

    def delete(self, env_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.environments.delete(env_id, **kw))


class _SyncApiKeys:
    def __init__(self, p: _KnoxCallSync) -> None:
        self._p = p

    def list(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.api_keys.list(**kw))

    def iterate(self, **kw: Any) -> Iterator[Any]:
        return self._p._iter(self._p._async.api_keys.iterate(**kw))

    def create(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.api_keys.create(**kw))

    def revoke(self, key_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.api_keys.revoke(key_id, **kw))


class _SyncRoles:
    def __init__(self, p: _KnoxCallSync) -> None:
        self._p = p

    def list(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.roles.list(**kw))

    def iterate(self, **kw: Any) -> Iterator[Any]:
        return self._p._iter(self._p._async.roles.iterate(**kw))


class _SyncAccount:
    def __init__(self, p: _KnoxCallSync) -> None:
        self._p = p

    def get(self) -> Any:
        return self._p._run(self._p._async.account.get())

    def get_usage(self) -> Any:
        return self._p._run(self._p._async.account.get_usage())


class _SyncAuditLogs:
    def __init__(self, p: _KnoxCallSync) -> None:
        self._p = p

    def list(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.audit_logs.list(**kw))

    def iterate(self, **kw: Any) -> Iterator[Any]:
        return self._p._iter(self._p._async.audit_logs.iterate(**kw))


class _SyncAgents:
    def __init__(self, p: _KnoxCallSync) -> None:
        self._p = p

    def list(self) -> Any:
        return self._p._run(self._p._async.agents.list())

    def create(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.agents.create(**kw))

    def revoke(self, agent_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.agents.revoke(agent_id, **kw))

    def get_tamper_events(self, agent_id: str) -> Any:
        return self._p._run(self._p._async.agents.get_tamper_events(agent_id))


class _SyncCrypto:
    def __init__(self, p: _KnoxCallSync) -> None:
        self._p = p

    def list_keys(self) -> Any:
        return self._p._run(self._p._async.crypto.list_keys())

    def get_key(self, name: str) -> Any:
        return self._p._run(self._p._async.crypto.get_key(name))

    def create_key(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.crypto.create_key(**kw))

    def rotate_key(self, name: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.crypto.rotate_key(name, **kw))

    def destroy_key_version(self, name: str, version: int, **kw: Any) -> Any:
        return self._p._run(self._p._async.crypto.destroy_key_version(name, version, **kw))

    def get_public_key(self, name: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.crypto.get_public_key(name, **kw))

    def encrypt(self, name: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.crypto.encrypt(name, **kw))

    def decrypt(self, name: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.crypto.decrypt(name, **kw))

    def rewrap(self, name: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.crypto.rewrap(name, **kw))

    def encrypt_data(self, data: Any, **kw: Any) -> Any:
        return self._p._run(self._p._async.crypto.encrypt_data(data, **kw))

    def decrypt_data(self, data: Any, **kw: Any) -> Any:
        return self._p._run(self._p._async.crypto.decrypt_data(data, **kw))

    def inspect(self, value: str) -> Any:
        return self._p._run(self._p._async.crypto.inspect(value))

    def mint_client_token(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.crypto.mint_client_token(**kw))

    def get_sealing_bundle(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.crypto.get_sealing_bundle(**kw))

    def sign(self, name: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.crypto.sign(name, **kw))

    def verify(self, name: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.crypto.verify(name, **kw))

    def sign_jwt(self, name: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.crypto.sign_jwt(name, **kw))

    def verify_jwt(self, name: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.crypto.verify_jwt(name, **kw))

    def sign_webhook(self, name: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.crypto.sign_webhook(name, **kw))


class _SyncPki:
    def __init__(self, p: _KnoxCallSync) -> None:
        self._p = p

    def list_roots(self) -> Any:
        return self._p._run(self._p._async.pki.list_roots())

    def create_root(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.pki.create_root(**kw))

    def get_root_cert(self, name: str) -> Any:
        return self._p._run(self._p._async.pki.get_root_cert(name))

    def rotate_intermediate(self, name: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.pki.rotate_intermediate(name, **kw))

    def get_crl(self, name: str) -> Any:
        return self._p._run(self._p._async.pki.get_crl(name))

    def list_roles(self, root_name: str) -> Any:
        return self._p._run(self._p._async.pki.list_roles(root_name))

    def create_role(self, root_name: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.pki.create_role(root_name, **kw))

    def issue_cert(self, root_name: str, role: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.pki.issue_cert(root_name, role, **kw))

    def revoke_cert(self, root_name: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.pki.revoke_cert(root_name, **kw))


class _SyncVaults:
    def __init__(self, p: _KnoxCallSync) -> None:
        self._p = p

    def list(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.vaults.list(**kw))

    def iterate(self, **kw: Any) -> Iterator[Any]:
        return self._p._iter(self._p._async.vaults.iterate(**kw))

    def get(self, name_or_id: str) -> Any:
        return self._p._run(self._p._async.vaults.get(name_or_id))

    def create(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.vaults.create(**kw))

    def update(self, name_or_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.vaults.update(name_or_id, **kw))

    def delete(self, name_or_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.vaults.delete(name_or_id, **kw))

    def rotate(self, name_or_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.vaults.rotate(name_or_id, **kw))

    def tokenize(self, name_or_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.vaults.tokenize(name_or_id, **kw))

    def bulk_tokenize(self, name_or_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.vaults.bulk_tokenize(name_or_id, **kw))

    def list_tokens(self, name_or_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.vaults.list_tokens(name_or_id, **kw))

    def iterate_tokens(self, name_or_id: str, **kw: Any) -> Iterator[Any]:
        return self._p._iter(self._p._async.vaults.iterate_tokens(name_or_id, **kw))

    def detokenize(self, name_or_id: str, id_or_token: str) -> Any:
        return self._p._run(self._p._async.vaults.detokenize(name_or_id, id_or_token))

    def update_token(self, name_or_id: str, id_or_token: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.vaults.update_token(name_or_id, id_or_token, **kw))

    def delete_token(self, name_or_id: str, id_or_token: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.vaults.delete_token(name_or_id, id_or_token, **kw))


class _SyncDynamicDb:
    def __init__(self, p: _KnoxCallSync) -> None:
        self._p = p

    def list(self) -> Any:
        return self._p._run(self._p._async.dynamic_db.list())

    def get(self, name: str) -> Any:
        return self._p._run(self._p._async.dynamic_db.get(name))

    def create(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.dynamic_db.create(**kw))

    def update(self, name: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.dynamic_db.update(name, **kw))

    def delete(self, name: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.dynamic_db.delete(name, **kw))

    def rotate_ssh_key(self, name: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.dynamic_db.rotate_ssh_key(name, **kw))

    def list_roles(self, connection_name: str) -> Any:
        return self._p._run(self._p._async.dynamic_db.list_roles(connection_name))

    def create_role(self, connection_name: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.dynamic_db.create_role(connection_name, **kw))

    def update_role(self, connection_name: str, role: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.dynamic_db.update_role(connection_name, role, **kw))

    def delete_role(self, connection_name: str, role: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.dynamic_db.delete_role(connection_name, role, **kw))

    def mint(self, connection_name: str, role: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.dynamic_db.mint(connection_name, role, **kw))

    def list_leases(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.dynamic_db.list_leases(**kw))

    def revoke_lease(self, lease_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.dynamic_db.revoke_lease(lease_id, **kw))


class _SyncAIGateway:
    def __init__(self, p: _KnoxCallSync) -> None:
        self._p = p

    # Gateways
    def list_gateways(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.ai_gateway.list_gateways(**kw))

    def iterate_gateways(self, **kw: Any) -> Iterator[Any]:
        return self._p._iter(self._p._async.ai_gateway.iterate_gateways(**kw))

    def create_gateway(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.ai_gateway.create_gateway(**kw))

    def get_gateway(self, gateway_id: str) -> Any:
        return self._p._run(self._p._async.ai_gateway.get_gateway(gateway_id))

    def update_gateway(self, gateway_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.ai_gateway.update_gateway(gateway_id, **kw))

    def delete_gateway(self, gateway_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.ai_gateway.delete_gateway(gateway_id, **kw))

    # Agents
    def list_agents(self, gateway_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.ai_gateway.list_agents(gateway_id, **kw))

    def iterate_agents(self, gateway_id: str, **kw: Any) -> Iterator[Any]:
        return self._p._iter(self._p._async.ai_gateway.iterate_agents(gateway_id, **kw))

    def create_agent(self, gateway_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.ai_gateway.create_agent(gateway_id, **kw))

    def get_agent(self, agent_id: str) -> Any:
        return self._p._run(self._p._async.ai_gateway.get_agent(agent_id))

    def update_agent(self, agent_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.ai_gateway.update_agent(agent_id, **kw))

    def delete_agent(self, agent_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.ai_gateway.delete_agent(agent_id, **kw))

    # Firewall policies (AIGW-03)
    def list_firewall_policies(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.ai_gateway.list_firewall_policies(**kw))

    def iterate_firewall_policies(self, **kw: Any) -> Iterator[Any]:
        return self._p._iter(self._p._async.ai_gateway.iterate_firewall_policies(**kw))

    def create_firewall_policy(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.ai_gateway.create_firewall_policy(**kw))

    def get_firewall_policy(self, policy_id: str) -> Any:
        return self._p._run(self._p._async.ai_gateway.get_firewall_policy(policy_id))

    def update_firewall_policy(self, policy_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.ai_gateway.update_firewall_policy(policy_id, **kw))

    def delete_firewall_policy(self, policy_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.ai_gateway.delete_firewall_policy(policy_id, **kw))

    def test_firewall_rules(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.ai_gateway.test_firewall_rules(**kw))

    # PII policies + recognizers (AIGW-160)
    def list_pii_policies(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.ai_gateway.list_pii_policies(**kw))

    def iterate_pii_policies(self, **kw: Any) -> Iterator[Any]:
        return self._p._iter(self._p._async.ai_gateway.iterate_pii_policies(**kw))

    def create_pii_policy(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.ai_gateway.create_pii_policy(**kw))

    def get_pii_policy(self, policy_id: str) -> Any:
        return self._p._run(self._p._async.ai_gateway.get_pii_policy(policy_id))

    def update_pii_policy(self, policy_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.ai_gateway.update_pii_policy(policy_id, **kw))

    def delete_pii_policy(self, policy_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.ai_gateway.delete_pii_policy(policy_id, **kw))

    def list_pii_recognizers(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.ai_gateway.list_pii_recognizers(**kw))

    def iterate_pii_recognizers(self, **kw: Any) -> Iterator[Any]:
        return self._p._iter(self._p._async.ai_gateway.iterate_pii_recognizers(**kw))

    def create_pii_recognizer(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.ai_gateway.create_pii_recognizer(**kw))

    def test_pii_recognizer(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.ai_gateway.test_pii_recognizer(**kw))

    def get_pii_recognizer(self, recognizer_id: str) -> Any:
        return self._p._run(self._p._async.ai_gateway.get_pii_recognizer(recognizer_id))

    def update_pii_recognizer(self, recognizer_id: str, **kw: Any) -> Any:
        return self._p._run(
            self._p._async.ai_gateway.update_pii_recognizer(recognizer_id, **kw)
        )

    def delete_pii_recognizer(self, recognizer_id: str, **kw: Any) -> Any:
        return self._p._run(
            self._p._async.ai_gateway.delete_pii_recognizer(recognizer_id, **kw)
        )

    # Tokens
    def list_tokens(self, agent_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.ai_gateway.list_tokens(agent_id, **kw))

    def iterate_tokens(self, agent_id: str, **kw: Any) -> Iterator[Any]:
        return self._p._iter(self._p._async.ai_gateway.iterate_tokens(agent_id, **kw))

    def mint_token(self, agent_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.ai_gateway.mint_token(agent_id, **kw))

    def revoke_token(self, agent_id: str, token_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.ai_gateway.revoke_token(agent_id, token_id, **kw))

    # Usage
    def usage(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.ai_gateway.usage(**kw))

    def export_usage(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.ai_gateway.export_usage(**kw))


class _SyncWorkflows:
    def __init__(self, p: _KnoxCallSync) -> None:
        self._p = p

    # Workflow CRUD
    def list(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.workflows.list(**kw))

    def iterate(self, **kw: Any) -> Iterator[Any]:
        return self._p._iter(self._p._async.workflows.iterate(**kw))

    def get(self, workflow_id: str) -> Any:
        return self._p._run(self._p._async.workflows.get(workflow_id))

    def create(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.workflows.create(**kw))

    def update(self, workflow_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.workflows.update(workflow_id, **kw))

    def delete(self, workflow_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.workflows.delete(workflow_id, **kw))

    def execute(self, workflow_id: str, input: Any = None, **kw: Any) -> Any:
        return self._p._run(self._p._async.workflows.execute(workflow_id, input, **kw))

    # Executions
    def list_executions(self, workflow_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.workflows.list_executions(workflow_id, **kw))

    def iterate_executions(self, workflow_id: str, **kw: Any) -> Iterator[Any]:
        return self._p._iter(self._p._async.workflows.iterate_executions(workflow_id, **kw))

    def get_execution(self, execution_id: str) -> Any:
        return self._p._run(self._p._async.workflows.get_execution(execution_id))

    def cancel_execution(self, execution_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.workflows.cancel_execution(execution_id, **kw))


class _SyncWrap:
    def __init__(self, p: _KnoxCallSync) -> None:
        self._p = p

    def escrow(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.wrap.escrow(**kw))

    def gateway_url(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.wrap.gateway_url(**kw))

    def list_gateway_tokens(self) -> Any:
        return self._p._run(self._p._async.wrap.list_gateway_tokens())

    def revoke_gateway_token(self, id: str) -> Any:
        return self._p._run(self._p._async.wrap.revoke_gateway_token(id))

    def intercept_manifest(self, *, environment: str | None = None, if_none_match: str | None = None) -> Any:
        """See :meth:`knoxcall.resources.wrap.WrapResource.intercept_manifest`;
        with ``if_none_match`` a ``304`` returns ``None``."""
        return self._p._run(self._p._async.wrap.intercept_manifest(environment=environment, if_none_match=if_none_match))

    def report_egress_observations(self, observations: Any, *, sdk: str | None = None) -> Any:
        return self._p._run(self._p._async.wrap.report_egress_observations(observations, sdk=sdk))

    def intercept(
        self,
        *,
        hosts: Any = (),
        stacks: list[str] | None = None,
        require_context: bool = False,
        **opts: Any,
    ) -> InterceptHandle:
        """Reroute outbound egress for the hosts a Route covers — and for
        ``hosts`` you list — through KnoxCall, with NO per-SDK wiring. Patches
        ``httpx`` (sync + async) and ``urllib3`` (``requests``, generated
        clients such as ``hubspot-api-client``) by default::

            knox = KnoxCall(api_key=...)
            stop = knox.wrap.intercept(hosts=["api.resend.com"])  # no Route → ephemeral
            stop.ready()                                           # first manifest loaded
            hubspot = HubSpot(access_token="placeholder")          # an untouched SDK
            hubspot.crm.contacts.basic_api.get_page()              # via the Route covering api.hubapi.com
            stop.uninstall()

        Route-aware by default (``routes="auto"``); ``hosts`` may be a list or a
        ``{host: {"credential": …, "unavailable": …}}`` map. Per request: the
        kill switch (``KNOXCALL_INTERCEPT=off``), KnoxCall's own hosts and
        route-around rules go direct; a Route covering host + path → route
        mode (the Route injects the secret); a listed host with no Route →
        the ephemeral proxy; otherwise untouched. The ``aiohttp`` stack is
        async-only and refused here — install it from ``KnoxCallAsync``
        (``stacks=["aiohttp"]``). A convenience, not a security boundary — see
        ``_intercept_patch.py``.
        """
        from ._intercept_patch import install_intercept
        from .resources.wrap import _split_hosts

        host_list, host_options = _split_hosts(hosts)
        opts.setdefault("routes", "auto")
        return install_intercept(
            client=self._p._async,
            runner=self._p._run,
            stacks=stacks or ["httpx", "urllib3"],
            hosts=host_list,
            host_options=host_options,
            require_context=require_context,
            transport_opts=opts,
        )

    @staticmethod
    def routed() -> Any:
        """Context manager marking the CALL SITE for ``require_context=True``."""
        from ._intercept_patch import routed

        return routed()

    def transport(self, **opts: Any) -> KnoxWrapTransport:
        """A synchronous :class:`httpx.BaseTransport` that routes a wrapped SDK's
        HTTP calls through KnoxCall's ephemeral proxy (transparent mode). Swap
        ONLY the wrapped SDK's httpx transport::

            stripe.default_http_client = stripe.http_client.HTTPXClient(
                httpx.Client(transport=client.wrap.transport()))

            # Or let KnoxCall build the Client for you:
            with client.wrap.client() as http:
                ...

        The async ``ephemeral`` call runs on the sync client's dedicated
        background event loop. Options mirror :meth:`WrapResource.transport`.
        """
        return KnoxWrapTransport(self._p._async, self._p._run, **opts)

    def client(self, **opts: Any) -> httpx.Client:
        """An :class:`httpx.Client` pre-wired with :meth:`transport` — hand it
        straight to a wrapped SDK's httpx-client parameter."""
        return httpx.Client(transport=self.transport(**opts))


class _SyncOpportunities:
    def __init__(self, p: _KnoxCallSync) -> None:
        self._p = p

    def list(self, **kw: Any) -> Any:
        return self._p._run(self._p._async.opportunities.list(**kw))

    def iterate(self, **kw: Any) -> Iterator[Any]:
        return self._p._iter(self._p._async.opportunities.iterate(**kw))

    def accept(self, opportunity_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.opportunities.accept(opportunity_id, **kw))

    def dismiss(self, opportunity_id: str, **kw: Any) -> Any:
        return self._p._run(self._p._async.opportunities.dismiss(opportunity_id, **kw))
