"""Token caching with single-flight refresh. Mirrors token-store.ts and redis-token-store.ts."""

from __future__ import annotations
import asyncio
import json
import secrets as _secrets
import time
import weakref
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Protocol, TypeVar

from ..redacted import Redacted

T = TypeVar("T")


@dataclass
class CachedToken:
    access_token: Redacted[str]
    expires_at: float  # epoch seconds
    lifetime: float | None = None  # original expires_in, for refresh-ahead sizing
    scope: list[str] = field(default_factory=list)
    token_type: str = "Bearer"  # "Bearer" or "DPoP"
    refresh_token: Redacted[str] | None = None
    cnf_jkt: str | None = None
    tenant: str | None = None  # slug from the token response (auto-discovery)


class TokenStore(Protocol):
    async def get(self, key: str) -> CachedToken | None: ...
    async def set(self, key: str, token: CachedToken) -> None: ...
    async def delete(self, key: str) -> None: ...
    async def with_lock(self, key: str, fn: Callable[[], Awaitable[T]]) -> T: ...


class AsyncRedisClient(Protocol):
    """Minimal async Redis client contract.

    redis-py 4+ async (``redis.asyncio``) and aioredis 2+ satisfy this
    protocol with no adapter code.
    """

    async def get(self, key: str) -> str | bytes | None: ...

    async def set(
        self, key: str, value: str | bytes, *, nx: bool = False, ex: int | None = None
    ) -> Any: ...

    async def delete(self, *keys: str) -> Any: ...


class MemoryTokenStore:
    """Process-local store with per-key asyncio locks for single-flight refresh.

    Locks are scoped to the running event loop (asyncio primitives are
    loop-confined), so the store keeps working when a process forks or a new
    loop is created — the token data itself is loop-agnostic and survives.
    """

    def __init__(self) -> None:
        self._tokens: dict[str, CachedToken] = {}
        self._locks: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, dict[str, asyncio.Lock]]" = (
            weakref.WeakKeyDictionary()
        )

    async def get(self, key: str) -> CachedToken | None:
        return self._tokens.get(key)

    async def set(self, key: str, token: CachedToken) -> None:
        self._tokens[key] = token

    async def delete(self, key: str) -> None:
        self._tokens.pop(key, None)

    async def with_lock(self, key: str, fn: Callable[[], Awaitable[T]]) -> T:
        loop = asyncio.get_running_loop()
        locks = self._locks.setdefault(loop, {})
        lock = locks.setdefault(key, asyncio.Lock())
        async with lock:
            return await fn()


class RedisTokenStore:
    """Shared token cache for multi-instance fleets. Mirrors RedisTokenStore from redis-token-store.ts.

    Pass any ``AsyncRedisClient``-compatible client (redis-py 4+ async,
    aioredis 2+, fakeredis-py, etc.) as the first argument.

        from redis.asyncio import Redis
        store = RedisTokenStore(Redis.from_url("redis://localhost"))
    """

    def __init__(
        self,
        client: AsyncRedisClient,
        *,
        prefix: str = "knoxcall:",
        lock_wait_ms: int = 10_000,
        lock_ttl_seconds: int = 30,
        default_cache_ttl_seconds: int = 3600,
    ) -> None:
        self._client = client
        self._prefix = prefix.rstrip(":") + ":"
        self._lock_wait_ms = lock_wait_ms
        self._lock_ttl = lock_ttl_seconds
        self._default_ttl = default_cache_ttl_seconds

    def _cache_key(self, key: str) -> str:
        return f"{self._prefix}token:{key}"

    def _lock_key(self, key: str) -> str:
        return f"{self._prefix}lock:{key}"

    async def get(self, key: str) -> CachedToken | None:
        raw = await self._client.get(self._cache_key(key))
        if raw is None:
            return None
        try:
            text = raw.decode() if isinstance(raw, bytes) else raw
            p = json.loads(text)
            return CachedToken(
                access_token=Redacted(p["accessToken"]),
                expires_at=float(p["expiresAt"]),
                lifetime=float(p["lifetime"]) if p.get("lifetime") else None,
                scope=p.get("scope", []),
                token_type=p.get("tokenType", "Bearer"),
                refresh_token=Redacted(p["refreshToken"]) if p.get("refreshToken") else None,
                cnf_jkt=p.get("cnfJkt"),
                tenant=p.get("tenant"),
            )
        except Exception:
            return None

    async def set(self, key: str, token: CachedToken) -> None:
        payload: dict[str, Any] = {
            "accessToken": token.access_token.expose(),
            "expiresAt": token.expires_at,
            "scope": token.scope,
            "tokenType": token.token_type,
        }
        if token.lifetime is not None:
            payload["lifetime"] = token.lifetime
        if token.tenant is not None:
            payload["tenant"] = token.tenant
        if token.refresh_token is not None:
            payload["refreshToken"] = token.refresh_token.expose()
        if token.cnf_jkt is not None:
            payload["cnfJkt"] = token.cnf_jkt
        ttl = max(60, min(self._default_ttl, int(token.expires_at - time.time()) + 60))
        await self._client.set(self._cache_key(key), json.dumps(payload), ex=ttl)

    async def delete(self, key: str) -> None:
        await self._client.delete(self._cache_key(key))

    async def with_lock(self, key: str, fn: Callable[[], Awaitable[T]]) -> T:
        lock_key = self._lock_key(key)
        token = _secrets.token_hex(16)
        start = time.monotonic()

        while True:
            result = await self._client.set(lock_key, token, nx=True, ex=self._lock_ttl)
            if result:
                break
            elapsed_ms = (time.monotonic() - start) * 1000
            if elapsed_ms > self._lock_wait_ms:
                break  # Proceed without lock; fn will re-check the cache first
            poll_s = min(200, 25 + int(elapsed_ms / 50)) / 1000
            await asyncio.sleep(poll_s)

        try:
            return await fn()
        finally:
            try:
                current = await self._client.get(lock_key)
                if current is not None:
                    current_str = current.decode() if isinstance(current, bytes) else current
                    if current_str == token:
                        await self._client.delete(lock_key)
            except Exception:
                pass
