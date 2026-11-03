"""Two small on-disk caches the default-on interceptor needs, in
``~/.knoxcall/`` beside the credentials file.

Both exist for the same reason: the startup hook (``knoxcall_autostart``) must do no
network I/O at interpreter start, and a short-lived process (``python
script.py``) must not pay a manifest round trip on its first outbound call.

- **The manifest cache** (``intercept-manifest.json``) holds what
  ``GET /v1/wrap/intercept-manifest`` last returned, keyed by the identity the
  answer depends on (base URL + profile + environment + mode). It holds HOSTS,
  BASE PATHS, SLUGS and FLAGS — the same fields a ``GET /v1/routes`` caller
  already sees. It holds NO credential, ever: tokens live in
  ``credentials.json`` and nowhere else (``auth/credentials_file.py`` is the
  sole writer of credential material).
- **The autostart state** (``autostart.json``) records that a user DECLINED or
  timed out of the one-time login prompt, so the hook asks once rather than on
  every process start.

Every operation here is BEST-EFFORT and silent. A missing file, a corrupt file,
an unwritable home directory and a permission error are all "no cached state" —
they must never fail, slow or alter the application's request. That is why
nothing in this module raises: the caller has no recovery to perform, because
the cache is an optimisation and the state file is a courtesy.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

# Keep the cache bounded: one entry per (base_url, profile, environment, mode)
# a machine actually talks to. A developer with a handful of profiles stays
# well inside this; the cap stops an unbounded file if something generates
# keys (a per-request environment override, say).
MAX_MANIFEST_ENTRIES = 12

_MANIFEST_FILE = "intercept-manifest.json"
_AUTOSTART_FILE = "autostart.json"


def _state_dir() -> Path:
    """``~/.knoxcall`` — or the directory of ``KNOXCALL_CREDENTIALS_FILE`` when
    set, so a caller that relocated its credentials keeps all of its KnoxCall
    state together (and a test that points at a temp dir gets both)."""
    override = os.environ.get("KNOXCALL_CREDENTIALS_FILE")
    if override:
        parent = os.path.dirname(override)
        if parent:
            return Path(parent)
    return Path.home() / ".knoxcall"


def manifest_cache_path() -> str:
    return str(_state_dir() / _MANIFEST_FILE)


def autostart_state_path() -> str:
    return str(_state_dir() / _AUTOSTART_FILE)


# ── atomic, mode-0600 JSON ────────────────────────────────────────────────────


def read_json(path: str) -> dict[str, Any] | None:
    """Parse the file, or ``None`` for anything that is not a JSON object."""
    try:
        with open(path, encoding="utf8") as f:
            doc = json.load(f)
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def write_json(path: str, doc: Mapping[str, Any]) -> bool:
    """Temp file in the same directory, fsync, rename over the target; 0700 on
    the directory and 0600 on the file (advisory on Windows). ``False`` when it
    could not be written — the caller carries on without the cache."""
    directory = os.path.dirname(path) or "."
    tmp_path: str | None = None
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix=".knoxcall-", suffix=".tmp", dir=directory)
        with os.fdopen(fd, "w", encoding="utf8") as f:
            json.dump(doc, f, separators=(",", ":"))
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(tmp_path, 0o600)
        except OSError:
            pass
        os.replace(tmp_path, path)
        return True
    except (OSError, ValueError, TypeError):
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        return False


# ── the manifest cache ───────────────────────────────────────────────────────


def manifest_cache_key(
    *, base_url: str, profile: str, environment: str | None, sandbox: bool
) -> str:
    """A stable, non-reversible key for the identity the manifest depends on.

    Hashed rather than spelled out because a base URL can name a tenant
    (``<tenant>.knoxcall.com``) and the key is the one part of this file a
    casual reader sees. The VALUE still names hosts — the cache is not a
    confidentiality mechanism, only tidy."""
    raw = "\x00".join([base_url or "", profile or "", environment or "", "1" if sandbox else "0"])
    return hashlib.sha256(raw.encode("utf8")).hexdigest()[:32]


def read_cached_manifest(key: str, *, path: str | None = None) -> tuple[Mapping[str, Any], float] | None:
    """The cached manifest for ``key`` and its age in seconds, or ``None``.

    Age is wall-clock (the file outlives the process, so ``time.monotonic`` is
    meaningless across runs). A clock that has stepped BACKWARDS gives a
    negative age, which is clamped to 0 — a manifest is never treated as
    fresher than the TTL it was fetched with."""
    doc = read_json(path or manifest_cache_path())
    if doc is None:
        return None
    entries = doc.get("entries")
    if not isinstance(entries, dict):
        return None
    entry = entries.get(key)
    if not isinstance(entry, dict):
        return None
    manifest = entry.get("manifest")
    fetched_at = entry.get("fetched_at")
    if not isinstance(manifest, dict) or not isinstance(fetched_at, (int, float)):
        return None
    if not manifest.get("version") or not isinstance(manifest.get("routes"), list):
        return None  # not the manifest shape — treat as absent
    return manifest, max(0.0, time.time() - float(fetched_at))


def write_cached_manifest(key: str, manifest: Mapping[str, Any], *, path: str | None = None) -> bool:
    """Store ``manifest`` under ``key``, evicting the oldest entries past the cap."""
    target = path or manifest_cache_path()
    doc = read_json(target) or {}
    entries = doc.get("entries")
    if not isinstance(entries, dict):
        entries = {}
    entries[key] = {"fetched_at": time.time(), "manifest": dict(manifest)}
    if len(entries) > MAX_MANIFEST_ENTRIES:
        ordered = sorted(
            entries.items(),
            key=lambda kv: kv[1].get("fetched_at", 0) if isinstance(kv[1], dict) else 0,
            reverse=True,
        )
        entries = dict(ordered[:MAX_MANIFEST_ENTRIES])
    return write_json(target, {"version": 1, "entries": entries})


# ── the autostart state (the "we already asked" record) ──────────────────────


def read_autostart_state(profile: str, *, path: str | None = None) -> dict[str, Any]:
    """This profile's autostart record (``{}`` when there is none)."""
    doc = read_json(path or autostart_state_path())
    if doc is None:
        return {}
    profiles = doc.get("profiles")
    if not isinstance(profiles, dict):
        return {}
    record = profiles.get(profile)
    return dict(record) if isinstance(record, dict) else {}


def write_autostart_state(profile: str, record: Mapping[str, Any], *, path: str | None = None) -> bool:
    """Merge one profile's record in; other profiles are untouched."""
    target = path or autostart_state_path()
    doc = read_json(target) or {}
    profiles = doc.get("profiles")
    if not isinstance(profiles, dict):
        profiles = {}
    profiles[profile] = dict(record)
    return write_json(target, {"version": 1, "profiles": profiles})


def login_declined(profile: str, *, path: str | None = None) -> bool:
    """Whether this profile already declined (or timed out of) the one-time
    login prompt. Cleared by a successful ``knoxcall login``, or by deleting
    the state file."""
    return bool(read_autostart_state(profile, path=path).get("login_declined_at"))


def record_login_declined(profile: str, reason: str, *, path: str | None = None) -> bool:
    """Remember that we asked and did not get a login, so we ask once only."""
    return write_autostart_state(
        profile,
        {
            "login_declined_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "reason": reason,
        },
        path=path,
    )


def clear_login_declined(profile: str, *, path: str | None = None) -> bool:
    """Forget the decline AND the no-credential verdict — called after a
    successful login so the hook starts working again without the user having to
    find a state file."""
    record = read_autostart_state(profile, path=path)
    if not record:
        return True
    for key in ("login_declined_at", "reason", "no_credential_until"):
        record.pop(key, None)
    return write_autostart_state(profile, record, path=path)


# How long a "nothing is configured" verdict stands before it is re-checked.
# Short on purpose: it exists to stop EVERY process in a loop (a test suite, a
# shell for-loop) repeating the detection, not to remember a decision. It
# self-heals, and a successful `knoxcall login` clears it outright.
NO_CREDENTIAL_TTL_SECONDS = 600.0


def no_credential_recorded(profile: str, *, path: str | None = None) -> bool:
    """Whether a recent process already established that this machine has no
    KnoxCall credential at all.

    Why this is cached and the rest of the chain is not: ONE slot of
    ``auth/bootstrap.py``'s detection — GCP instance metadata — is an UNGATED
    network probe, so proving "nothing is configured" costs a DNS failure and
    a connect attempt every time (measured ~0.7 s on a Windows dev box, where
    the NXDOMAIN is slow). Every other slot is an environment variable or a
    file. Without this, an unconfigured machine pays that on the first outbound
    request of every process it runs."""
    until = read_autostart_state(profile, path=path).get("no_credential_until")
    if not isinstance(until, (int, float)):
        return False
    return time.time() < float(until)


def record_no_credential(profile: str, *, path: str | None = None) -> bool:
    record = read_autostart_state(profile, path=path)
    record["no_credential_until"] = time.time() + NO_CREDENTIAL_TTL_SECONDS
    return write_autostart_state(profile, record, path=path)
