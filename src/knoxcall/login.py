"""Interactive first-run authentication — TTY-gated, and never on a ``.call()``.

The persistent credential (``knoxcall login`` → ``~/.knoxcall/credentials.json``,
rotating refresh token) already survives restarts; these helpers just let the
SDK *initiate* that login programmatically.

WHO CALLS THESE, as of 1.2.0. Two callers, and the guards below are what make
the second one safe:

1. **Application code**, explicitly — the original contract, unchanged.
   ``KnoxCall(...)`` construction, ``.call()`` and every other API method never
   trigger a browser or device flow; they raise
   :class:`NotAuthenticatedError` when no credential is found. The flow is
   reachable from the API surface ONLY through the four helpers here.
2. **The default-on interception hook** (``knoxcall_autostart``), once, at the
   moment the process first tries to egress to a third-party host with no
   credential available. THIS REVERSES THE PREVIOUS POLICY, which was "OPT-IN,
   and NEVER on the request path", and the reversal is deliberate: installing
   the SDK is meant to be enough to get interception, ``pip`` cannot prompt
   during a wheel install, and prompting at interpreter start would mean
   ``python -c pass`` could open a browser. The first outbound request is the
   first moment the question is relevant.

   What keeps that safe is :func:`_interactive_guard`, unchanged and mandatory:
   no TTY, ``CI``, or ``KNOXCALL_NO_INTERACTIVE`` means no prompt at all — the
   hook prints one hint line and the process carries on with no interception.
   The hook also asks ONCE: a decline or a timeout is recorded in
   ``~/.knoxcall/autostart.json`` and never asked again, and
   ``KNOXCALL_AUTOSTART=off`` stops the hook installing in the first place.
   An embedded SDK in someone else's production process therefore still never
   sees a browser flow, which is what the old policy was protecting.

Both forms are exposed so either a sync or an async caller can use them:

- ``login`` / ``ensure_login`` — async, return a :class:`KnoxCallAsync`.
- ``login_sync`` / ``ensure_login_sync`` — sync, return the sync facade client.

Mirrors ``knoxcall-node``'s ``src/login.ts`` (package-level ``login`` /
``ensureLogin``); reuses the CLI's already-tested auth-code+PKCE loopback /
RFC 8628 device flow and ``persist_login``.
"""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any, Callable, TYPE_CHECKING

from .auth.bootstrap import StoredCredentials
from .auth.credentials_file import (
    profile_available,
    resolve_credentials_path,
    resolve_profile,
)
from .cli._common import persist_login
from .cli.login import auth_code_flow, device_flow
from .client import KnoxCall, KnoxCallAsync
from .core import _default_base_url
from .errors import KnoxCallError, NotAuthenticatedError

if TYPE_CHECKING:
    from .client import _KnoxCallSync

_MODES = ("auto", "browser", "device")


# ── Guards ────────────────────────────────────────────────────────────────────


def _interactive_guard(allow_non_interactive: bool) -> None:
    """Refuse to pop a browser or block on a device code where doing so is
    unsafe: a non-interactive process (no TTY), CI, or an explicit opt-out.
    The caller can override with ``allow_non_interactive`` when they know it
    is safe.

    Also called by the default-on interception hook (``knoxcall_autostart``),
    which never passes ``allow_non_interactive`` — this is the whole of what
    stops a prompt reaching a server, a container or a CI job, so a change here
    changes that too.
    """
    if allow_non_interactive:
        return
    if os.environ.get("KNOXCALL_NO_INTERACTIVE") or os.environ.get("CI"):
        raise NotAuthenticatedError(
            "interactive login is disabled here (KNOXCALL_NO_INTERACTIVE or CI is set). "
            "Provision a non-interactive credential (client_id/secret or workload OIDC) instead."
        )
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise NotAuthenticatedError(
            "no interactive terminal detected — run `knoxcall login` in a terminal, "
            "or provision a non-interactive credential (client_id/secret or workload OIDC)."
        )


def _has_desktop_browser() -> bool:
    # Headless CI is already blocked by _interactive_guard, so this only chooses
    # browser-vs-device on a real TTY. On Linux, require a display server.
    if sys.platform.startswith("linux"):
        return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    return True


# ── Shared plumbing ───────────────────────────────────────────────────────────


def _resolve_flow(
    *,
    sandbox: bool,
    base_url: str | None,
    profile: str | None,
    mode: str,
    allow_non_interactive: bool,
) -> tuple[str, str, bool]:
    """Run the guard, validate ``mode``, and resolve (base_url, profile,
    use_device). Raises before any browser/device flow starts."""
    _interactive_guard(allow_non_interactive)
    if mode not in _MODES:
        raise KnoxCallError(f'mode must be one of {_MODES} (got {mode!r})')
    resolved_base = (base_url or _default_base_url(sandbox)).rstrip("/")
    resolved_profile = resolve_profile(profile)
    use_device = mode == "device" or (mode == "auto" and not _has_desktop_browser())
    return resolved_base, resolved_profile, use_device


def _run_flow_blocking(
    resolved_base: str,
    use_device: bool,
    *,
    tenant: str | None,
    open_browser: Callable[[str], Any] | None,
    timeout: float,
) -> dict[str, Any]:
    """Drive the (blocking) CLI auth-code loopback or device-code flow."""
    if use_device:
        return device_flow(resolved_base)
    kwargs: dict[str, Any] = {"tenant": tenant, "timeout": timeout}
    if open_browser is not None:
        kwargs["open_browser"] = open_browser
    return auth_code_flow(resolved_base, **kwargs)


def _async_client_from_profile(
    profile: str, *, sandbox: bool, client_options: dict[str, Any] | None
) -> KnoxCallAsync:
    opts = dict(client_options or {})
    opts["bootstrap"] = StoredCredentials(profile=profile)
    opts["sandbox"] = sandbox
    return KnoxCallAsync(**opts)


def _sync_client_from_profile(
    profile: str, *, sandbox: bool, client_options: dict[str, Any] | None
) -> "_KnoxCallSync":
    opts = dict(client_options or {})
    opts["bootstrap"] = StoredCredentials(profile=profile)
    opts["sandbox"] = sandbox
    return KnoxCall(sync=True, **opts)  # type: ignore[return-value]


# ── Async helpers ─────────────────────────────────────────────────────────────


async def login(
    *,
    tenant: str | None = None,
    sandbox: bool = False,
    base_url: str | None = None,
    profile: str | None = None,
    mode: str = "auto",
    open_browser: Callable[[str], Any] | None = None,
    timeout: float = 300.0,
    allow_non_interactive: bool = False,
    client_options: dict[str, Any] | None = None,
) -> KnoxCallAsync:
    """Run the interactive browser (loopback) or device-code login, persist the
    credential to ``~/.knoxcall/credentials.json``, and return a ready async
    client. The caller explicitly asked to log in, so blocking + a browser is
    expected. ``mode``: ``auto`` (browser on a desktop TTY, else device) |
    ``browser`` | ``device``.
    """
    resolved_base, resolved_profile, use_device = _resolve_flow(
        sandbox=sandbox,
        base_url=base_url,
        profile=profile,
        mode=mode,
        allow_non_interactive=allow_non_interactive,
    )
    # The CLI flows block (loopback server / device polling); keep the event
    # loop free by running them on a worker thread.
    token_body = await asyncio.to_thread(
        _run_flow_blocking,
        resolved_base,
        use_device,
        tenant=tenant,
        open_browser=open_browser,
        timeout=timeout,
    )
    persist_login(
        path=resolve_credentials_path(),
        profile=resolved_profile,
        base_url=resolved_base,
        token_body=token_body,
        fallback_tenant=tenant,
    )
    return _async_client_from_profile(
        resolved_profile, sandbox=sandbox, client_options=client_options
    )


async def ensure_login(
    *,
    tenant: str | None = None,
    sandbox: bool = False,
    base_url: str | None = None,
    profile: str | None = None,
    mode: str = "auto",
    open_browser: Callable[[str], Any] | None = None,
    timeout: float = 300.0,
    allow_non_interactive: bool = False,
    client_options: dict[str, Any] | None = None,
) -> KnoxCallAsync:
    """Return an async client from an already-stored credential for the profile
    if one exists (no prompt, no network), otherwise run the interactive
    :func:`login` once. The ergonomic "make sure I'm authenticated, then give
    me a client" entry point.
    """
    resolved_profile = resolve_profile(profile)
    if profile_available(resolve_credentials_path(), resolved_profile):
        return _async_client_from_profile(
            resolved_profile, sandbox=sandbox, client_options=client_options
        )
    return await login(
        tenant=tenant,
        sandbox=sandbox,
        base_url=base_url,
        profile=profile,
        mode=mode,
        open_browser=open_browser,
        timeout=timeout,
        allow_non_interactive=allow_non_interactive,
        client_options=client_options,
    )


# ── Sync helpers ──────────────────────────────────────────────────────────────


def login_sync(
    *,
    tenant: str | None = None,
    sandbox: bool = False,
    base_url: str | None = None,
    profile: str | None = None,
    mode: str = "auto",
    open_browser: Callable[[str], Any] | None = None,
    timeout: float = 300.0,
    allow_non_interactive: bool = False,
    client_options: dict[str, Any] | None = None,
) -> "_KnoxCallSync":
    """Synchronous :func:`login` — returns the sync facade client. Safe to call
    from ordinary (non-async) code; the CLI flows are themselves blocking."""
    resolved_base, resolved_profile, use_device = _resolve_flow(
        sandbox=sandbox,
        base_url=base_url,
        profile=profile,
        mode=mode,
        allow_non_interactive=allow_non_interactive,
    )
    token_body = _run_flow_blocking(
        resolved_base,
        use_device,
        tenant=tenant,
        open_browser=open_browser,
        timeout=timeout,
    )
    persist_login(
        path=resolve_credentials_path(),
        profile=resolved_profile,
        base_url=resolved_base,
        token_body=token_body,
        fallback_tenant=tenant,
    )
    return _sync_client_from_profile(
        resolved_profile, sandbox=sandbox, client_options=client_options
    )


def ensure_login_sync(
    *,
    tenant: str | None = None,
    sandbox: bool = False,
    base_url: str | None = None,
    profile: str | None = None,
    mode: str = "auto",
    open_browser: Callable[[str], Any] | None = None,
    timeout: float = 300.0,
    allow_non_interactive: bool = False,
    client_options: dict[str, Any] | None = None,
) -> "_KnoxCallSync":
    """Synchronous :func:`ensure_login` — returns the sync facade client from an
    existing profile without prompting, else runs :func:`login_sync` once."""
    resolved_profile = resolve_profile(profile)
    if profile_available(resolve_credentials_path(), resolved_profile):
        return _sync_client_from_profile(
            resolved_profile, sandbox=sandbox, client_options=client_options
        )
    return login_sync(
        tenant=tenant,
        sandbox=sandbox,
        base_url=base_url,
        profile=profile,
        mode=mode,
        open_browser=open_browser,
        timeout=timeout,
        allow_non_interactive=allow_non_interactive,
        client_options=client_options,
    )
