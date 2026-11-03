"""Credentials-file provider tests — StoredCredentials bootstrap (PARITY §2).

Every test points KNOXCALL_CREDENTIALS_FILE at tmp_path so the real
~/.knoxcall is never touched (or even read).
"""

from __future__ import annotations

import asyncio
import os
import threading
import time

import httpx
import pytest

from knoxcall import AuthenticationError, KnoxCallAsync
from knoxcall.auth.bootstrap import (
    AccessToken,
    ClientCredentials,
    StoredCredentials,
    auto_detect_bootstrap,
)
from knoxcall.auth.credentials_file import (
    CredentialsFileLock,
    format_expiry,
    read_profile,
    write_profile,
)
from knoxcall.auth.oauth import fetch_token
from knoxcall.errors import KnoxCallError

_ENV_VARS = (
    "KNOXCALL_TENANT",
    "KNOXCALL_BASE_URL",
    "KNOXCALL_PROXY_BASE_URL",
    "KNOXCALL_ACCESS_TOKEN",
    "KNOXCALL_API_KEY",
    "KNOXCALL_CLIENT_ID",
    "KNOXCALL_CLIENT_SECRET",
    "KNOXCALL_CREDENTIALS_FILE",
    "KNOXCALL_PROFILE",
)

_TOKEN_ENDPOINT = "https://api.example.test/oauth/token"


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch, tmp_path):
    for var in _ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    # Never let the chain or the provider read a real ~/.knoxcall file.
    monkeypatch.setenv("KNOXCALL_CREDENTIALS_FILE", str(tmp_path / "credentials.json"))


def _write_creds(
    path,
    *,
    profile="default",
    tenant="acme",
    base_url="https://api.example.test",
    access_token="kc_stored_fresh",
    refresh_token="rt_1",
    expires_in=3600.0,
    client_id="kc_cli_real",
    scope="routes:read",
):
    write_profile(
        str(path),
        profile,
        {
            "tenant": tenant,
            "base_url": base_url,
            "client_id": client_id,
            "refresh_token": refresh_token,
            "access_token": access_token,
            "access_token_expires_at": format_expiry(time.time() + expires_in),
            "scope": scope,
        },
    )
    return str(path)


def _http(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


# ── Auto-detect chain position (slot 2) ──────────────────────────────────────


async def test_auto_detect_picks_up_credentials_file(tmp_path):
    _write_creds(tmp_path / "credentials.json")
    bootstrap = await auto_detect_bootstrap()
    assert isinstance(bootstrap, StoredCredentials)


async def test_env_access_token_beats_file(tmp_path, monkeypatch):
    _write_creds(tmp_path / "credentials.json")
    monkeypatch.setenv("KNOXCALL_ACCESS_TOKEN", "kc_env_token")
    bootstrap = await auto_detect_bootstrap()
    assert isinstance(bootstrap, AccessToken)


async def test_file_beats_env_client_credentials(tmp_path, monkeypatch):
    _write_creds(tmp_path / "credentials.json")
    monkeypatch.setenv("KNOXCALL_CLIENT_ID", "tk_env")
    monkeypatch.setenv("KNOXCALL_CLIENT_SECRET", "sec")
    bootstrap = await auto_detect_bootstrap()
    assert isinstance(bootstrap, StoredCredentials)


async def test_missing_file_skips_provider(monkeypatch):
    # fixture points at a path that was never written
    monkeypatch.setenv("KNOXCALL_CLIENT_ID", "tk_env")
    monkeypatch.setenv("KNOXCALL_CLIENT_SECRET", "sec")
    bootstrap = await auto_detect_bootstrap()
    assert isinstance(bootstrap, ClientCredentials)


async def test_missing_profile_skips_provider(tmp_path, monkeypatch):
    _write_creds(tmp_path / "credentials.json")  # only "default" exists
    monkeypatch.setenv("KNOXCALL_PROFILE", "work")
    monkeypatch.setenv("KNOXCALL_CLIENT_ID", "tk_env")
    monkeypatch.setenv("KNOXCALL_CLIENT_SECRET", "sec")
    bootstrap = await auto_detect_bootstrap()
    assert isinstance(bootstrap, ClientCredentials)


async def test_malformed_file_skips_provider_not_crash(tmp_path, monkeypatch):
    (tmp_path / "credentials.json").write_text("{this is not json", encoding="utf8")
    monkeypatch.setenv("KNOXCALL_CLIENT_ID", "tk_env")
    monkeypatch.setenv("KNOXCALL_CLIENT_SECRET", "sec")
    bootstrap = await auto_detect_bootstrap()
    assert isinstance(bootstrap, ClientCredentials)


# ── Fresh-token fast path ────────────────────────────────────────────────────


async def test_fresh_access_token_used_without_refresh(tmp_path):
    _write_creds(tmp_path / "credentials.json", expires_in=3600)
    calls: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req.url.path)
        return httpx.Response(500)

    async with _http(handler) as http:
        token = await fetch_token(
            token_endpoint=_TOKEN_ENDPOINT, bootstrap=StoredCredentials(), http=http
        )
    assert token.access_token.expose() == "kc_stored_fresh"
    assert token.tenant == "acme"
    assert token.scope == ["routes:read"]
    assert calls == []  # no HTTP at all on the fast path
    # tokens are redacted in reprs (PARITY §3)
    assert "kc_stored_fresh" not in repr(token)
    assert repr(token.access_token) == "[REDACTED]"


# ── Refresh + rotated write-back ─────────────────────────────────────────────


async def test_expired_token_refreshes_and_writes_back_rotated_token(tmp_path):
    path = _write_creds(
        tmp_path / "credentials.json",
        access_token="kc_old",
        refresh_token="rt_old",
        expires_in=10,  # inside the 60s freshness window → must refresh
    )
    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/oauth/token"
        seen.append(req.content.decode())
        return httpx.Response(
            200,
            json={
                "access_token": "kc_new",
                "refresh_token": "rt_new",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "routes:read secrets:read",
                "tenant": "acme",
                "client_id": "kc_cli_real",
            },
        )

    async with _http(handler) as http:
        token = await fetch_token(
            token_endpoint=_TOKEN_ENDPOINT, bootstrap=StoredCredentials(), http=http
        )

    assert token.access_token.expose() == "kc_new"
    form = seen[0]
    assert "grant_type=refresh_token" in form
    assert "refresh_token=rt_old" in form
    assert "client_id=kc_cli_real" in form  # the REAL client id, not the alias
    assert "client_secret" not in form  # public client — no secret

    on_disk = read_profile(path, "default")
    assert on_disk["refresh_token"] == "rt_new"  # rotation persisted
    assert on_disk["access_token"] == "kc_new"
    assert on_disk["scope"] == "routes:read secrets:read"
    # atomic write: no temp-file or lock litter left behind
    leftovers = sorted(p.name for p in tmp_path.iterdir())
    assert leftovers == ["credentials.json"]


async def test_invalid_grant_raises_typed_error_with_relogin_hint(tmp_path):
    _write_creds(tmp_path / "credentials.json", expires_in=0)

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400, json={"error": "invalid_grant", "error_description": "family revoked"}
        )

    async with _http(handler) as http:
        with pytest.raises(AuthenticationError) as excinfo:
            await fetch_token(
                token_endpoint=_TOKEN_ENDPOINT, bootstrap=StoredCredentials(), http=http
            )
    assert "knoxcall login" in str(excinfo.value)
    assert excinfo.value.code == "invalid_grant"


# ── Lock: cross-process serialization + hygiene ──────────────────────────────


def test_concurrent_refresh_serialized_by_lock(tmp_path):
    """Two threads race an expired token: exactly ONE refresh POST happens —
    the loser re-reads the file under the lock and adopts the rotated token
    (single-use refresh tokens make a second POST a family revocation)."""
    path = _write_creds(
        tmp_path / "credentials.json",
        access_token="kc_old",
        refresh_token="rt_only",
        expires_in=0,
    )
    posts: list[str] = []
    posts_guard = threading.Lock()

    def handler(req: httpx.Request) -> httpx.Response:
        with posts_guard:
            posts.append(req.content.decode())
        time.sleep(0.3)  # hold the refresh so the other thread queues on the file lock
        return httpx.Response(
            200,
            json={
                "access_token": "kc_new",
                "refresh_token": "rt_rotated",
                "token_type": "Bearer",
                "expires_in": 3600,
            },
        )

    results: dict[int, object] = {}

    def worker(i: int) -> None:
        async def go():
            async with _http(handler) as http:
                return await fetch_token(
                    token_endpoint=_TOKEN_ENDPOINT,
                    bootstrap=StoredCredentials(path=path),
                    http=http,
                )

        results[i] = asyncio.run(go())

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    assert len(posts) == 1
    assert results[0].access_token.expose() == "kc_new"
    assert results[1].access_token.expose() == "kc_new"
    assert read_profile(path, "default")["refresh_token"] == "rt_rotated"
    assert not os.path.exists(path + ".lock")


def test_stale_lock_is_broken(tmp_path):
    target = tmp_path / "credentials.json"
    lock_file = tmp_path / "credentials.json.lock"
    lock_file.write_text("999 0 deadbeef\n", encoding="ascii")
    old = time.time() - 120  # well past the 60s staleness window
    os.utime(lock_file, (old, old))

    lock = CredentialsFileLock(str(target))
    start = time.monotonic()
    lock.acquire()
    try:
        assert time.monotonic() - start < 5  # broke the stale lock, no 10s wait
        assert lock_file.exists()  # we now hold a fresh lock of our own
    finally:
        lock.release()
    assert not lock_file.exists()


def test_lock_within_stale_window_is_not_broken(tmp_path):
    target = tmp_path / "credentials.json"
    lock_file = tmp_path / "credentials.json.lock"
    lock_file.write_text("123 now aabbcc\n", encoding="ascii")
    recent = time.time() - 45  # stale by the OLD 30s rule, fresh by the 60s window
    os.utime(lock_file, (recent, recent))
    lock = CredentialsFileLock(str(target), timeout=0.3, retry_interval=0.05)
    with pytest.raises(KnoxCallError):
        lock.acquire()
    assert lock_file.exists()  # the not-yet-stale lock was left intact


def test_release_never_deletes_a_peer_owned_lock(tmp_path):
    target = tmp_path / "credentials.json"
    lock_file = tmp_path / "credentials.json.lock"
    lock = CredentialsFileLock(str(target))
    lock.acquire()
    assert lock_file.exists()
    # Simulate our lock having been broken as stale and re-taken by a peer:
    # the on-disk owner tag no longer matches what we wrote.
    lock_file.write_text("4242 0 peerowned\n", encoding="ascii")
    lock.release()
    assert lock_file.exists()  # the peer's live lock must survive our release
    assert "peerowned" in lock_file.read_text(encoding="ascii")


def test_live_lock_times_out(tmp_path):
    target = tmp_path / "credentials.json"
    (tmp_path / "credentials.json.lock").write_text("123 now feed01\n", encoding="ascii")  # fresh
    lock = CredentialsFileLock(str(target), timeout=0.3, retry_interval=0.05)
    with pytest.raises(KnoxCallError):
        lock.acquire()


# ── Client seeding: file tenant/base_url, explicit always wins ───────────────


async def test_file_seeds_tenant_and_base_url_when_not_explicit(tmp_path):
    _write_creds(tmp_path / "credentials.json")  # tenant acme, api.example.test
    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(str(req.url))
        return httpx.Response(200, json={"data": {"ok": True}})

    async with KnoxCallAsync(http=_http(handler)) as client:  # zero-config
        await client.request(method="GET", path="/v1/ping")
        assert client.tenant == "acme"
        assert client.base_url == "https://api.example.test"
    assert seen == ["https://api.example.test/v1/ping"]


async def test_explicit_tenant_and_base_url_beat_file(tmp_path):
    _write_creds(tmp_path / "credentials.json")  # tenant acme, api.example.test

    async with KnoxCallAsync(
        tenant="zeta", base_url="https://explicit.example.test"
    ) as client:
        await client.authenticate()  # fast path — stored token is fresh, no HTTP
        assert client.tenant == "zeta"
        assert client.base_url == "https://explicit.example.test"


async def test_env_tenant_and_base_url_beat_file(tmp_path, monkeypatch):
    _write_creds(tmp_path / "credentials.json")
    monkeypatch.setenv("KNOXCALL_TENANT", "envcorp")
    monkeypatch.setenv("KNOXCALL_BASE_URL", "https://env.example.test")

    async with KnoxCallAsync() as client:
        await client.authenticate()
        assert client.tenant == "envcorp"
        assert client.base_url == "https://env.example.test"


# ── Env overrides for path + profile ─────────────────────────────────────────


async def test_credentials_file_env_override(tmp_path, monkeypatch):
    custom = tmp_path / "elsewhere" / "creds.json"
    _write_creds(custom, access_token="kc_custom_path")
    monkeypatch.setenv("KNOXCALL_CREDENTIALS_FILE", str(custom))

    bootstrap = await auto_detect_bootstrap()
    assert isinstance(bootstrap, StoredCredentials)
    token = await fetch_token(token_endpoint=_TOKEN_ENDPOINT, bootstrap=bootstrap)
    assert token.access_token.expose() == "kc_custom_path"


async def test_profile_env_override_selects_profile(tmp_path, monkeypatch):
    path = tmp_path / "credentials.json"
    _write_creds(path, profile="default", tenant="acme", access_token="kc_default")
    _write_creds(path, profile="work", tenant="globex", access_token="kc_work")
    monkeypatch.setenv("KNOXCALL_PROFILE", "work")

    token = await fetch_token(token_endpoint=_TOKEN_ENDPOINT, bootstrap=StoredCredentials())
    assert token.access_token.expose() == "kc_work"
    assert token.tenant == "globex"


async def test_expired_token_without_refresh_token_raises_relogin_hint(tmp_path):
    path = tmp_path / "credentials.json"
    write_profile(
        str(path),
        "default",
        {
            "tenant": "acme",
            "base_url": "https://api.example.test",
            "client_id": "kc_cli_real",
            "access_token": "kc_dead",
            "access_token_expires_at": format_expiry(time.time() - 10),
        },
    )
    with pytest.raises(AuthenticationError) as excinfo:
        await fetch_token(token_endpoint=_TOKEN_ENDPOINT, bootstrap=StoredCredentials())
    assert "knoxcall login" in str(excinfo.value)


def test_lock_acquires_when_parent_dir_missing(tmp_path):
    # First-ever login: ~/.knoxcall/ does not exist yet. O_CREAT on the lock
    # path used to raise FileNotFoundError, which _try_acquire swallowed as
    # contention — spinning for the full 10s timeout. Regression: acquire
    # must create the parent and succeed immediately.
    path = tmp_path / "fresh" / "nested" / "credentials.json"
    lock = CredentialsFileLock(str(path), timeout=2.0)
    start = time.monotonic()
    lock.acquire()
    try:
        assert time.monotonic() - start < 1.0
        assert os.path.exists(str(path) + ".lock")
    finally:
        lock.release()
    assert not os.path.exists(str(path) + ".lock")
    # And the full first-login write path works in the fresh dir too.
    write_profile(str(path), "default", {"tenant": "acme", "client_id": "kc_cli_x"})
    assert read_profile(str(path), "default")["tenant"] == "acme"
