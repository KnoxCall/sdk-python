"""Shared credentials file (``~/.knoxcall/credentials.json``) — read, write, lock, refresh.

The file is written by ``knoxcall login`` and consumed by every SDK through the
``StoredCredentials`` bootstrap. Format, lock protocol, and refresh rules are
cross-SDK identical (PARITY §2). The server's refresh tokens are SINGLE-USE
with family revocation on reuse, so any refresh MUST:

1. hold the sibling ``credentials.json.lock`` file (exclusive-create, 100ms
   retry up to 10s; a lock older than the stale window is broken by atomic
   rename and retried once — ownership-aware so a peer's live lock is never
   deleted, and the window stays above the bounded refresh timeout),
2. RE-READ the file after acquiring the lock (another process may have already
   refreshed), and
3. atomically (temp file + rename) write back the rotated refresh token before
   releasing the lock.
"""

from __future__ import annotations
import asyncio
import json
import os
import secrets
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from .._warn import warn_security
from ..errors import AuthenticationError, KnoxCallError, error_from_response
from ..redacted import Redacted
from .token_store import CachedToken

DEFAULT_PROFILE = "default"

# A stored access token is "fresh" while it has more than this much validity
# left; below the threshold the provider refreshes under the file lock.
_FRESH_WINDOW_SECONDS = 60.0

# The locked refresh HTTP call is bounded so the lock is provably released well
# within the lock's stale window (CredentialsFileLock stale_after) — otherwise
# a slow token endpoint could hold the lock long enough for a peer to break it
# and double-refresh the single-use token.
_REFRESH_TIMEOUT_SECONDS = 30.0

RELOGIN_MESSAGE = (
    "stored CLI credentials are no longer valid — run `knoxcall login` again"
)


# ── Path / profile resolution ────────────────────────────────────────────────


def resolve_credentials_path(override: str | os.PathLike[str] | None = None) -> str:
    """Credentials file path: explicit override > KNOXCALL_CREDENTIALS_FILE > default."""
    if override:
        return str(override)
    env = os.environ.get("KNOXCALL_CREDENTIALS_FILE")
    if env:
        return env
    return str(Path.home() / ".knoxcall" / "credentials.json")


def resolve_profile(override: str | None = None) -> str:
    """Profile name: explicit override > KNOXCALL_PROFILE > ``default``."""
    return str(override or os.environ.get("KNOXCALL_PROFILE") or DEFAULT_PROFILE)


# ── File primitives (atomic writes, tolerant reads) ─────────────────────────


def _warn_if_loose_permissions(path: str | os.PathLike[str]) -> None:
    """Warn (once) if the credentials file — which holds a refresh token — is
    readable by group/other. POSIX only; on Windows mode bits are advisory."""
    if os.name == "nt":
        return
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return
    if mode & 0o077:
        warn_security(
            f"KnoxCall credentials file {path} is accessible to group/other "
            f"(mode {oct(mode & 0o777)}) and holds a refresh token. Restrict it: chmod 600 {path}"
        )


def _read_document(path: str | os.PathLike[str]) -> dict[str, Any] | None:
    """Parse the whole file; None on missing/malformed/unexpected shape."""
    _warn_if_loose_permissions(path)
    try:
        with open(path, encoding="utf8") as f:
            doc = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict) or not isinstance(doc.get("profiles"), dict):
        return None
    return doc


def read_profile(path: str | os.PathLike[str], profile: str) -> dict[str, Any] | None:
    """One profile's record, or None (missing file, malformed JSON, unknown profile)."""
    doc = _read_document(path)
    if doc is None:
        return None
    record = doc["profiles"].get(profile)
    if not isinstance(record, dict):
        return None
    return dict(record)


def _write_document(path: str, doc: dict[str, Any]) -> None:
    """Atomic write: temp file in the same directory → fsync → rename over target.

    Directory is created 0700 and the file chmod'd 0600 (best-effort — the
    mode bits are advisory on Windows).
    """
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".credentials-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf8") as f:
            json.dump(doc, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(tmp_path, 0o600)
        except OSError:
            pass
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def write_profile(path: str | os.PathLike[str], profile: str, record: dict[str, Any]) -> None:
    """Merge one profile into the file (other profiles untouched), atomically."""
    doc = _read_document(path) or {"version": 1, "profiles": {}}
    doc.setdefault("version", 1)
    doc["profiles"][profile] = {k: v for k, v in record.items() if v is not None}
    _write_document(str(path), doc)


def remove_profile(path: str | os.PathLike[str], profile: str) -> bool:
    """Remove one profile; delete the file when it was the last one."""
    doc = _read_document(path)
    if doc is None or profile not in doc["profiles"]:
        return False
    del doc["profiles"][profile]
    if doc["profiles"]:
        _write_document(str(path), doc)
    else:
        try:
            os.unlink(path)
        except OSError:
            pass
    return True


def profile_available(path: str | os.PathLike[str], profile: str) -> bool:
    """Auto-detect presence check: file exists AND the selected profile parses."""
    return read_profile(path, profile) is not None


# ── Expiry formatting ────────────────────────────────────────────────────────


def format_expiry(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_expiry(value: Any) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


# ── Cross-process lock ───────────────────────────────────────────────────────


class CredentialsFileLock:
    """Sibling ``.lock`` file held by exclusive-create (O_CREAT|O_EXCL).

    Protocol (identical in every SDK): retry every 100ms up to 10s; a lock
    file older than the stale window is broken and retried once.

    Ownership-aware break/release: the lock file carries a unique owner tag
    (``pid time nonce``) written at acquire. A stale lock is broken by ATOMIC
    RENAME (only one racer wins the rename, so a competitor's freshly-created
    lock can never be deleted by path), and release only unlinks a lock whose
    on-disk content still matches what this instance wrote. This closes the
    double-acquire -> double-refresh race that would replay the single-use
    refresh token and trip server-side family revocation. The stale window is
    also kept safely above the bounded refresh HTTP timeout so a live-but-slow
    refresh is never mistaken for a dead holder.
    """

    def __init__(
        self,
        target: str | os.PathLike[str],
        *,
        timeout: float = 10.0,
        retry_interval: float = 0.1,
        stale_after: float = 60.0,
    ) -> None:
        self.lock_path = str(target) + ".lock"
        self._timeout = timeout
        self._retry_interval = retry_interval
        # Must exceed the bounded refresh HTTP timeout (_REFRESH_TIMEOUT_SECONDS)
        # so a legitimately in-flight refresh is never broken as "stale".
        self._stale_after = stale_after
        self._held = False
        self._own_content: str | None = None

    def _ensure_parent_dir(self) -> None:
        # First-ever login: ~/.knoxcall/ may not exist yet, and O_CREAT on the
        # lock path would raise FileNotFoundError — which _try_acquire treats
        # as contention, spinning until the 10s timeout. Create it up front.
        parent = os.path.dirname(self.lock_path)
        if parent:
            os.makedirs(parent, mode=0o700, exist_ok=True)

    def _try_acquire(self) -> bool:
        content = f"{os.getpid()} {time.time():.3f} {secrets.token_hex(8)}\n"
        try:
            fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except OSError:
            return False
        try:
            os.write(fd, content.encode("ascii"))
        finally:
            os.close(fd)
        self._own_content = content
        self._held = True
        return True

    def _break_stale(self) -> bool:
        """Break a stale lock via atomic rename. True when a retry is worthwhile.

        rename() has exactly one winner, so if a competitor already
        broke-and-recreated the lock, our rename fails (source gone) and we
        never touch their live lock.
        """
        try:
            age = time.time() - os.stat(self.lock_path).st_mtime
        except OSError:
            return True  # lock vanished between attempts — retry immediately
        if age <= self._stale_after:
            return False
        graveyard = f"{self.lock_path}.stale-{os.getpid()}-{secrets.token_hex(6)}"
        try:
            os.rename(self.lock_path, graveyard)
            os.unlink(graveyard)
        except OSError:
            pass  # someone else already broke it (or it vanished) — just retry
        return True

    def _timeout_error(self) -> KnoxCallError:
        return KnoxCallError(
            f"timed out waiting for the credentials file lock ({self.lock_path})"
        )

    def acquire(self) -> None:
        self._ensure_parent_dir()
        deadline = time.monotonic() + self._timeout
        stale_broken = False
        while True:
            if self._try_acquire():
                return
            if not stale_broken and self._break_stale():
                stale_broken = True
                if self._try_acquire():
                    return
            if time.monotonic() >= deadline:
                raise self._timeout_error()
            time.sleep(self._retry_interval)

    async def acquire_async(self) -> None:
        self._ensure_parent_dir()
        deadline = time.monotonic() + self._timeout
        stale_broken = False
        while True:
            if self._try_acquire():
                return
            if not stale_broken and self._break_stale():
                stale_broken = True
                if self._try_acquire():
                    return
            if time.monotonic() >= deadline:
                raise self._timeout_error()
            await asyncio.sleep(self._retry_interval)

    def release(self) -> None:
        if not self._held:
            return
        self._held = False
        own = self._own_content
        self._own_content = None
        # Only remove the lock if it is still OURS — if our lock was broken as
        # stale and re-taken by another process while we were suspended, unlink
        # by path would delete their live lock.
        try:
            with open(self.lock_path, encoding="ascii") as f:
                current = f.read()
            if own is not None and current == own:
                os.unlink(self.lock_path)
        except OSError:
            pass  # already gone or unreadable

    def __enter__(self) -> "CredentialsFileLock":
        self.acquire()
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.release()


# ── Token fetch (fast path + locked refresh) ─────────────────────────────────


def _cached_from_profile(record: dict[str, Any]) -> CachedToken | None:
    """The fresh-token fast path: use the stored access token while >60s valid."""
    token = record.get("access_token")
    expires_at = _parse_expiry(record.get("access_token_expires_at"))
    if not token or expires_at is None:
        return None
    if expires_at - time.time() <= _FRESH_WINDOW_SECONDS:
        return None
    scope = record.get("scope") or ""
    return CachedToken(
        access_token=Redacted(token),
        expires_at=expires_at,
        scope=scope.split() if isinstance(scope, str) else list(scope),
        token_type="Bearer",
        tenant=record.get("tenant") or None,
        # No refresh_token on purpose: the file is the sole refresh authority,
        # so no in-process fallback can ever replay a consumed (rotated) token.
    )


async def _refresh_and_write_back(
    record: dict[str, Any],
    *,
    path: str,
    profile: str,
    token_endpoint: str,
    http: httpx.AsyncClient | None,
) -> CachedToken:
    refresh_token = record.get("refresh_token")
    client_id = record.get("client_id")
    if not refresh_token or not client_id:
        raise AuthenticationError(RELOGIN_MESSAGE)

    form = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,  # the tenant's real CLI client (public, no secret)
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    own_client = http is None
    client = http or httpx.AsyncClient()
    try:
        res = await client.post(
            token_endpoint, data=form, headers=headers, timeout=_REFRESH_TIMEOUT_SECONDS
        )
    finally:
        if own_client:
            await client.aclose()

    try:
        body: Any = res.json()
    except ValueError:
        body = res.text or None
    resp_headers = {k.lower(): v for k, v in res.headers.items()}
    if res.status_code >= 400:
        err = error_from_response(res.status_code, body, resp_headers)
        if err.code == "invalid_grant":
            # Revoked family or expired refresh token — unrecoverable here.
            raise AuthenticationError(
                RELOGIN_MESSAGE,
                status=err.status,
                code=err.code,
                request_id=err.request_id,
                headers=resp_headers,
                body=body,
            )
        raise err
    if not isinstance(body, dict) or not body.get("access_token"):
        raise KnoxCallError(
            f"token endpoint returned an unexpected response (status {res.status_code})",
            status=res.status_code,
            headers=resp_headers,
            body=body,
        )

    try:
        expires_in = float(body.get("expires_in", 3600))
    except (TypeError, ValueError):
        expires_in = 3600.0
    now = time.time()

    # Write back the rotated refresh token BEFORE releasing the lock (caller
    # holds it) — the old one is already consumed server-side.
    updated = dict(record)
    updated["access_token"] = body["access_token"]
    updated["access_token_expires_at"] = format_expiry(now + expires_in)
    if body.get("refresh_token"):
        updated["refresh_token"] = body["refresh_token"]
    if body.get("scope"):
        updated["scope"] = body["scope"]
    if body.get("tenant"):  # extension member (RFC 6749 §5.1)
        updated["tenant"] = body["tenant"]
    if body.get("client_id"):  # extension member: the real per-tenant client id
        updated["client_id"] = body["client_id"]
    write_profile(path, profile, updated)

    scope = updated.get("scope") or ""
    return CachedToken(
        access_token=Redacted(body["access_token"]),
        expires_at=now + expires_in,
        lifetime=expires_in,
        scope=scope.split() if isinstance(scope, str) else list(scope),
        token_type="Bearer",
        tenant=updated.get("tenant") or None,
    )


async def fetch_stored_token(
    *,
    path: str,
    profile: str,
    token_endpoint: str,
    http: httpx.AsyncClient | None = None,
) -> CachedToken:
    """Produce a usable access token from the credentials file.

    Fast path: stored access token with >60s validity, no HTTP. Otherwise
    lock → re-read → re-check → refresh-token grant → atomic write-back.
    """
    record = read_profile(path, profile)
    if record is None:
        # Detection saw the profile but it has since vanished/corrupted.
        raise AuthenticationError(RELOGIN_MESSAGE)
    cached = _cached_from_profile(record)
    if cached is not None:
        return cached

    lock = CredentialsFileLock(path)
    await lock.acquire_async()
    try:
        record = read_profile(path, profile)
        if record is None:
            raise AuthenticationError(RELOGIN_MESSAGE)
        cached = _cached_from_profile(record)
        if cached is not None:
            return cached  # another process refreshed while we waited
        return await _refresh_and_write_back(
            record, path=path, profile=profile, token_endpoint=token_endpoint, http=http
        )
    finally:
        lock.release()
