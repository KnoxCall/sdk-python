"""Default-on route-aware interception — the module the shipped ``.pth`` file
imports at interpreter start.

GOAL: installing the SDK is enough. No ``import knoxcall``, no
``knox.wrap.intercept()``, no other change in the application; outbound calls
to hosts an intercept-enabled Route covers go through KnoxCall, and the user is
asked to log in once.

TURNING IT OFF — the first thing to know:

- ``KNOXCALL_AUTOSTART=off`` — this hook does not install at all. Nothing is
  patched, nothing is imported beyond this module, no prompt is ever shown.
- ``KNOXCALL_INTERCEPT=off`` — the per-request kill switch, unchanged: every
  interceptor and route-aware transport becomes pass-through.
- ``KNOXCALL_AUTOSTART_VERBOSE=1`` — print what the hook decided and why.
  **The hook is SILENT by default** (operator decision, 2026-10-08): it never
  announces that you are not signed in, and never reports its own failure,
  because an unprompted line costs every customer's CI log one copy of it
  forever — and the documentation is what tells people to run
  ``knoxcall login``. This is the only way to debug "interception is not
  working", so the README names it beside the off switches. (It does not
  affect the SDK's ``KnoxCallSecurityWarning``s, which are Python warnings
  — use ``PYTHONWARNINGS`` for those.)

  THE ONE THING THAT STILL PRINTS WITHOUT IT is the interactive login: the
  line before the browser opens, and the outcome afterwards. Both require a
  TTY, so neither can reach a CI log, and a browser window appearing unbidden
  needs a reason on screen. The rule is: **the hook is silent unless you
  asked it something.**
- ``KNOXCALL_AUTOSTART_HOSTS=a.example,b.example`` — additionally cover hosts
  that NO Route covers, through the ephemeral proxy. Empty by default: there is
  no built-in host list, and a host with no Route stays untouched.

WHY A ``.pth`` AND NOT ``sitecustomize.py``: Debian and Ubuntu ship their own
``/usr/lib/python3.x/sitecustomize.py``, which sits ahead of a venv's
site-packages on ``sys.path`` and wins. A ``.pth`` line is executed by
``site.py`` for every site-packages directory, so the venv's copy always runs.

THREE STAGES, SO THE INTERPRETER NEVER PAYS FOR WHAT IT DOES NOT USE. The
demo shim this replaces blocked EVERY interpreter start on a token fetch plus a
manifest GET (~0.75 s measured), which is why it needed a hand-kept list of
tools to skip. Nothing here is hand-kept, because nothing is paid up front:

1. **Interpreter start** — this module is imported. It reads a few environment
   variables and puts one finder on ``sys.meta_path``. It imports nothing but
   ``os`` and ``sys``, touches no disk beyond its own ``.pyc``, and performs no
   network I/O. A process that never does HTTP (``pip``, ``pytest``,
   ``python -m venv``, ``python -c pass``) stops here.
2. **First import of ``httpx`` or ``urllib3``** — the finder notices and
   installs a thin shim on the two class-level seams. Still no client, no
   thread, no network, no credential read.
3. **First outbound request to a non-KnoxCall host** — the shim promotes:
   resolve a credential (prompting for login once, under the guards below),
   build the client, seed the manifest from the on-disk cache
   (``_local_state.py``), and hand the seams over to the real interceptor
   (``install_intercept``). The shims remove themselves first, so the real
   patch captures the true originals and this module is out of the request path
   for good.

There is therefore NO tooling skip list, and none is needed: the thing worth
skipping — the credential and manifest work — is never reached by a process
that does not make an outbound HTTP request in the first place.

THE LOGIN PROMPT fires at stage 3, not stage 1, for the same reason. "Prompt on
install" is not available to us (``pip`` runs no code from a wheel), and
prompting at interpreter start would mean ``python -c pass`` could open a
browser. Stage 3 is the first moment the process has demonstrably asked to talk
to a third party, which is the first moment the question is relevant. The
guards are ``login.py``'s own ``_interactive_guard`` — no TTY, ``CI``, or
``KNOXCALL_NO_INTERACTIVE`` means no prompt, one hint line at most, and the
process carries on with no interception.

NOT A SECURITY BOUNDARY. This changes WHICH code path installs the interceptor,
not what the interceptor is: a convenience that patches process-global classes,
composes with APM agents in install order, and is no defence against hostile
in-process code. KnoxCall's own hosts are never intercepted, route-around rules
still go direct, and host matching is still exact. See ``_intercept_patch.py``.
"""

from __future__ import annotations

import os
import sys

# NO module-scope imports beyond `os` and `sys` -- and that includes
# `typing`. This module is imported by a .pth at the start of EVERY Python
# process in the environment, `pip` and `pytest` included. It is also why it
# is a TOP-LEVEL module rather than `knoxcall._autostart`: importing a
# submodule executes the package's `__init__.py`, which imports the client
# and therefore httpx and cryptography -- measured at ~250 ms of interpreter
# start, for every process on the machine.
# `from __future__ import annotations` makes every annotation below a string
# that is never evaluated, so the names in them cost nothing at runtime.
TYPE_CHECKING = False
if TYPE_CHECKING:  # pragma: no cover
    from typing import Any, Callable

# The two stacks the default install covers — the same pair an explicit
# `KnoxCall(...).wrap.intercept()` patches. `aiohttp` is deliberately absent:
# it must be installed from `KnoxCallAsync` (it awaits the pipeline on the
# caller's event loop), so it cannot be a default of a sync-facade install.
_TARGET_MODULES = ("httpx", "urllib3")

# How long the one-time login flow may block the first outbound request before
# it is recorded as declined. Deliberately shorter than `login.py`'s own 300 s
# default: this prompt interrupts an application's request rather than a
# command the user just typed.
_LOGIN_TIMEOUT_SECONDS = 120.0

# Stages, as module state. There is exactly one install per process.
_PENDING = 0  # shims armed (or not yet armed); promotion not attempted
_READY = 1  # the real interceptor is installed
_DISABLED = 2  # no usable credential, or promotion failed: never try again

_state = _PENDING
_handle: "Any" = None
_client: "Any" = None
_restorers: "list[Callable[[], None]]" = []
_lock: "Any" = None
_finder: "Any" = None
_hinted = False

# Bound at arm time from `._intercept`, so this module never re-implements the
# host contract (normalisation, the platform-host rule, the kill switch). The
# "a control exists on one path and is simply absent on the parallel path"
# failure is exactly what a local copy of `normalise_host` would be.
_normalise_host: "Any" = None
_is_platform_host: "Any" = None
_kill_switch: "Any" = None


# ── environment ───────────────────────────────────────────────────────────────


# The SAME off-spellings as `_intercept.intercept_kill_switch` (PARITY §21.1),
# character for character and deliberately not a superset. A switch that
# accepted `no` where the kill switch next to it did not would be a difference
# nobody could predict from the documentation. The two are pinned together by
# `tests/test_autostart.py::test_the_off_grammar_matches_the_kill_switch`
# rather than by a shared constant, because this module may not import
# `_intercept` at module scope (see above) and a constant imported lazily would
# not be consulted by `install()`.
_OFF_VALUES = ("off", "0", "false")


def _is_off(name: str) -> bool:
    v = os.environ.get(name)
    return isinstance(v, str) and v.strip().lower() in _OFF_VALUES


def disabled_by_env() -> bool:
    """``KNOXCALL_AUTOSTART=off`` — do not install the hook at all.

    ``KNOXCALL_INTERCEPT`` is deliberately NOT read here: it is documented as a
    per-REQUEST kill switch, and reading it at interpreter start would quietly
    make it a per-process one."""
    return _is_off("KNOXCALL_AUTOSTART")


def verbose() -> bool:
    """``KNOXCALL_AUTOSTART_VERBOSE=1`` — opt IN to the hook's diagnostics.

    The inverse of the switch this replaced, and the inversion is the point: a
    hook that announces itself costs every CI log in the world one line per
    process, forever, and nobody acts on it there (observed in this repo's own
    `pip-audit` step before the switch was inverted)."""
    v = os.environ.get("KNOXCALL_AUTOSTART_VERBOSE")
    return isinstance(v, str) and v.strip().lower() not in ("", "0", "false", "no", "off")


def extra_hosts() -> list[str]:
    """``KNOXCALL_AUTOSTART_HOSTS`` — hosts to cover that no Route covers (they
    go through the ephemeral proxy). The only way to list a host without code,
    and empty by default."""
    raw = os.environ.get("KNOXCALL_AUTOSTART_HOSTS") or ""
    return [h.strip() for h in raw.replace(";", ",").split(",") if h.strip()]


def _tell(message: str) -> None:
    """One line to stderr, ALWAYS. Reserved for output coupled to an interactive
    login the user is watching happen: the reason a browser is about to open,
    and what came of it. Both require a TTY, so neither reaches a CI log. Never
    stdout — a program's stdout is its output, and this is not part of it."""
    try:
        print(f"KnoxCall: {message}", file=sys.stderr)
    except Exception:  # noqa: BLE001 — best-effort: a closed stderr must not fail a request
        pass


def _diag(message: str) -> None:
    """One line to stderr, only under ``KNOXCALL_AUTOSTART_VERBOSE``. EVERYTHING
    the hook might say on its own initiative goes through here."""
    if verbose():
        _tell(message)


def _diag_once(message: str) -> None:
    global _hinted
    if _hinted:
        return
    _hinted = True
    _diag(message)


# ── stage 1: the import finder ────────────────────────────────────────────────


class _SeamArmer:
    """A ``sys.meta_path`` finder that arms the seams the moment ``httpx`` or
    ``urllib3`` is first imported, and never before.

    It claims nothing. For every other module name it returns ``None`` after a
    set lookup; for a target it finds the real spec through the remaining
    finders and wraps that spec's ``exec_module`` so the seam is installed
    AFTER the module's classes exist. It removes itself once both targets have
    been seen, and on any error at all — a finder that raises would break every
    subsequent import in the process, so it is written to be unable to."""

    __slots__ = ("_waiting",)

    def __init__(self, targets: tuple[str, ...]) -> None:
        self._waiting = set(targets)

    def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> Any:
        try:
            if fullname not in self._waiting:
                return None
            # Discard FIRST: finding the real spec re-enters the import
            # machinery, and this finder must be inert for that pass.
            self._waiting.discard(fullname)
            if not self._waiting:
                _remove_finder(self)
            spec = self._real_spec(fullname, path, target)
            if spec is None:
                return None
            loader = getattr(spec, "loader", None)
            # A namespace package has no loader; a loader that IS a class
            # (BuiltinImporter, FrozenImporter) would leak the wrapper onto
            # every module it ever loads. Neither target is either of those,
            # but the check is what makes that true by construction.
            if loader is None or isinstance(loader, type):
                return spec
            original = getattr(loader, "exec_module", None)
            if original is None:
                return spec

            def exec_module(module: Any, _original: Any = original, _name: str = fullname) -> None:
                _original(module)
                try:
                    _arm(_name)
                except BaseException:  # noqa: BLE001 — an import must never fail because of us
                    pass

            try:
                loader.exec_module = exec_module  # type: ignore[method-assign]
            except Exception:  # noqa: BLE001 — a read-only loader just means no seam
                pass
            return spec
        except BaseException:  # noqa: BLE001 — see the class docstring
            try:
                _remove_finder(self)
            except BaseException:
                pass
            return None

    def _real_spec(self, fullname: str, path: Any, target: Any) -> Any:
        """The spec the import system would have produced without us. Walks
        ``sys.meta_path`` directly rather than calling ``importlib.util.
        find_spec``, which would cost an ``importlib.util`` import at
        interpreter start for every Python process on the machine."""
        for finder in list(sys.meta_path):
            if finder is self:
                continue
            find = getattr(finder, "find_spec", None)
            if find is None:
                continue
            try:
                spec = find(fullname, path, target)
            except (ImportError, AttributeError, TypeError):
                continue
            if spec is not None:
                return spec
        return None


def _remove_finder(finder: Any) -> None:
    global _finder
    try:
        sys.meta_path.remove(finder)
    except ValueError:
        pass
    if _finder is finder:
        _finder = None


def install() -> bool:
    """Stage 1. Called by the shipped ``.pth`` at interpreter start, and safe to
    call by hand. Returns whether the hook is now armed."""
    global _finder
    if disabled_by_env() or _state is not _PENDING or _finder is not None:
        return False
    already = [m for m in _TARGET_MODULES if m in sys.modules]
    pending = tuple(m for m in _TARGET_MODULES if m not in sys.modules)
    if pending:
        _finder = _SeamArmer(pending)
        sys.meta_path.insert(0, _finder)
    # Imported before us (someone imported this module by hand rather than
    # through the .pth): arm those seams now.
    for name in already:
        try:
            _arm(name)
        except BaseException:  # noqa: BLE001
            pass
    return bool(pending or already)


# ── stage 2: the shims ────────────────────────────────────────────────────────


def _bind_host_contract() -> None:
    global _normalise_host, _is_platform_host, _kill_switch
    if _normalise_host is not None:
        return
    from knoxcall._intercept import intercept_kill_switch, is_platform_host, normalise_host

    _normalise_host = normalise_host
    _is_platform_host = is_platform_host
    _kill_switch = intercept_kill_switch


def _worth_promoting(host: Any) -> bool:
    """Whether this request is a reason to build a client. KnoxCall's own hosts
    never are — that is the anti-recursion rule, and it is also what keeps the
    SDK's own token and manifest calls from triggering a promotion."""
    if _state is not _PENDING:
        return False
    try:
        h = _normalise_host(host)
    except (ValueError, TypeError):
        return False
    if not h or _is_platform_host(h):
        return False
    return not _kill_switch()


def _arm(name: str) -> None:
    """Stage 2 for one stack. A no-op once promotion has happened: the real
    interceptor owns the seam from then on, and a shim layered over it would
    re-dispatch into it for ever."""
    if _state is not _PENDING or disabled_by_env():
        return
    _bind_host_contract()
    if name == "httpx":
        _arm_httpx()
    elif name == "urllib3":
        _arm_urllib3()


def _arm_httpx() -> None:
    import httpx

    orig_sync = httpx.HTTPTransport.handle_request
    orig_async = httpx.AsyncHTTPTransport.handle_async_request

    def shim_sync(self: Any, request: Any) -> Any:
        if _worth_promoting(request.url.host):
            replacement = _promote("httpx_sync")
            if replacement is not None:
                return replacement(self, request)
        return orig_sync(self, request)

    async def shim_async(self: Any, request: Any) -> Any:
        if _worth_promoting(request.url.host):
            replacement = await _promote_async("httpx_async")
            if replacement is not None:
                return await replacement(self, request)
        return await orig_async(self, request)

    httpx.HTTPTransport.handle_request = shim_sync  # type: ignore[method-assign]
    httpx.AsyncHTTPTransport.handle_async_request = shim_async  # type: ignore[method-assign]

    def restore() -> None:
        if httpx.HTTPTransport.handle_request is shim_sync:
            httpx.HTTPTransport.handle_request = orig_sync  # type: ignore[method-assign]
        if httpx.AsyncHTTPTransport.handle_async_request is shim_async:
            httpx.AsyncHTTPTransport.handle_async_request = orig_async  # type: ignore[method-assign]

    _restorers.append(restore)


def _arm_urllib3() -> None:
    from urllib3.connectionpool import HTTPConnectionPool

    orig_urlopen = HTTPConnectionPool.urlopen

    def shim_urlopen(self: Any, method: str, url: str, *args: Any, **kwargs: Any) -> Any:
        if _worth_promoting(getattr(self, "host", "")):
            replacement = _promote("urllib3")
            if replacement is not None:
                return replacement(self, method, url, *args, **kwargs)
        return orig_urlopen(self, method, url, *args, **kwargs)

    HTTPConnectionPool.urlopen = shim_urlopen  # type: ignore[method-assign]

    def restore() -> None:
        if HTTPConnectionPool.urlopen is shim_urlopen:
            HTTPConnectionPool.urlopen = orig_urlopen  # type: ignore[method-assign]

    _restorers.append(restore)


def _restore_shims() -> None:
    """Put the originals back, so the real interceptor patches THEM and this
    module leaves the request path entirely."""
    while _restorers:
        try:
            _restorers.pop()()
        except BaseException:  # noqa: BLE001 — a failed restore must not stop the others
            pass


# ── stage 3: promotion ────────────────────────────────────────────────────────


def _get_lock() -> Any:
    global _lock
    if _lock is None:
        import threading

        _lock = threading.Lock()
    return _lock


def _seam(which: str) -> Any:
    """The function now sitting on the seam that called us — the real
    interceptor's patch when its stack was installed, otherwise the untouched
    original (so the caller goes direct, which is the right answer)."""
    if which == "httpx_sync":
        import httpx

        return httpx.HTTPTransport.handle_request
    if which == "httpx_async":
        import httpx

        return httpx.AsyncHTTPTransport.handle_async_request
    if which == "urllib3":
        from urllib3.connectionpool import HTTPConnectionPool

        return HTTPConnectionPool.urlopen
    return None


def _promote(which: str) -> Any:
    """Stage 3, synchronous. Returns the seam's replacement, or ``None`` to pass
    this request through untouched.

    The lock is taken NON-BLOCKING on purpose, and that is load-bearing twice
    over. It means a second thread's request goes direct rather than waiting
    behind a browser login — and it is the re-entrancy guard: building the
    client and fetching its token performs HTTP, which re-enters these very
    shims, and the busy lock is what makes that inner request pass straight
    through instead of recursing."""
    global _state, _handle, _client
    if _state is _DISABLED:
        return None
    if _state is _READY:
        return _seam(which)
    lock = _get_lock()
    if not lock.acquire(blocking=False):
        return None
    try:
        if _state is _READY:
            return _seam(which)
        if _state is _DISABLED:
            return None
        # Provisional, BEFORE any import below: `_build` imports urllib3, which
        # would otherwise re-enter `_arm` and shim a seam the real interceptor
        # is about to patch.
        _state = _READY
        try:
            handle, client = _build()
        except BaseException as err:  # noqa: BLE001 — a failure here must never reach the app
            _state = _DISABLED
            _restore_shims()
            _diag_once(
                f"interception is off for this process ({type(err).__name__}: {err}). "
                "Set KNOXCALL_AUTOSTART=off to stop trying."
            )
            return None
        if handle is None:
            _state = _DISABLED
            _restore_shims()
            return None
        _handle, _client = handle, client
        return _seam(which)
    finally:
        lock.release()


async def _promote_async(which: str) -> Any:
    """Stage 3 from an async seam. ``_promote`` blocks — on a token fetch, and
    possibly on a browser login — so it runs on a worker thread and the
    caller's event loop stays free."""
    if _state is _DISABLED:
        return None
    if _state is _READY:
        return _seam(which)
    import asyncio

    return await asyncio.to_thread(_promote, which)


def _build() -> tuple[Any, Any]:
    """Resolve a credential, build the client, install the real interceptor.

    Returns ``(handle, client)``, or ``(None, None)`` when there is no usable
    credential and the user was not willing (or could not be asked) to log in.
    Raises only for a genuine failure, which the caller turns into one line and
    a permanently disabled hook."""
    from knoxcall._local_state import no_credential_recorded, record_no_credential
    from knoxcall.auth.credentials_file import profile_available, resolve_credentials_path, resolve_profile
    from knoxcall.client import KnoxCall
    from knoxcall.errors import AuthenticationError, NotAuthenticatedError

    profile = resolve_profile()
    if no_credential_recorded(profile):
        # A recent process already proved there is nothing to find. Skipping
        # straight to "off" keeps the ungated GCP metadata probe out of every
        # subsequent process's first request (see _local_state).
        return None, None
    stored_present = profile_available(resolve_credentials_path(), profile)

    client = KnoxCall(sync=True)
    try:
        # The ONLY credential enumeration is `auth/bootstrap.py`'s: letting it
        # raise is how this hook learns "nothing is configured" without keeping
        # a second copy of the chain that would go stale the day a provider is
        # added to it.
        client.authenticate()
    except (NotAuthenticatedError, AuthenticationError) as err:
        _close(client)
        # NotAuthenticated = nothing found at all. AuthenticationError with a
        # stored profile = the saved login is dead (a revoked family, an expired
        # refresh token) and re-login is the documented fix; with no stored
        # profile it is a misconfigured client_id/secret or API key, and a
        # browser flow is not the answer to that.
        if isinstance(err, AuthenticationError) and not stored_present:
            raise
        client = _login_and_build(profile)
        if client is None:
            if isinstance(err, NotAuthenticatedError):
                record_no_credential(profile)
            return None, None

    try:
        return _install(client), client
    except BaseException:
        _close(client)
        raise


def _login_and_build(profile: str) -> Any:
    """The one-time login prompt, under ``login.py``'s own guards. Returns a
    ready client, or ``None`` (no prompt was possible, or the user did not
    complete it)."""
    from knoxcall._local_state import clear_login_declined, login_declined, record_login_declined
    from knoxcall.errors import NotAuthenticatedError
    from knoxcall.login import _interactive_guard, ensure_login_sync

    if login_declined(profile):
        return None  # asked once already; `knoxcall login` is how they say yes later

    try:
        _interactive_guard(False)
    except NotAuthenticatedError:
        # No TTY, CI, or KNOXCALL_NO_INTERACTIVE. One line, then carry on with
        # no interception — never a prompt, never a hang.
        _diag_once(
            "not signed in, so outbound calls are not going through KnoxCall. "
            "Run `knoxcall login` to enable it, or set KNOXCALL_AUTOSTART=off."
        )
        return None

    # Said before the browser opens, and deliberately NOT behind the verbose
    # switch: a window appearing unbidden needs a reason on screen. It can only
    # happen on a TTY, so it never reaches a CI log.
    _tell(
        "signing you in once so outbound calls can go through KnoxCall "
        "(KNOXCALL_AUTOSTART=off disables this)."
    )

    try:
        client = ensure_login_sync(timeout=_LOGIN_TIMEOUT_SECONDS)
    except (KeyboardInterrupt, SystemExit):
        # They asked to stop, not to carry on without interception.
        record_login_declined(profile, "interrupted")
        raise
    except BaseException as err:  # noqa: BLE001 — a declined/failed login is not an app error
        record_login_declined(profile, type(err).__name__)
        _tell(
            f"sign-in did not complete ({type(err).__name__}). Continuing without interception; "
            "run `knoxcall login` when you are ready — you will not be asked again."
        )
        return None
    clear_login_declined(profile)
    _tell("signed in. Outbound calls to hosts an intercept-enabled Route covers now go through KnoxCall.")
    return client


def _install(client: Any) -> Any:
    """Install the real interceptor on this client, with the manifest seeded
    from disk so the first request decides without a round trip."""
    from knoxcall._intercept_patch import install_intercept

    store = _seeded_store(client)
    stacks = ["httpx"]
    if _module_available("urllib3"):
        stacks.append("urllib3")

    hosts = extra_hosts()
    # The shims come off BEFORE the real patch goes on, so `install_intercept`
    # captures the true originals and this module is out of the path for good.
    _restore_shims()
    handle = install_intercept(
        client=client._async,
        runner=client._run,
        stacks=stacks,
        hosts=hosts,
        host_options={},
        require_context=False,
        transport_opts={"routes": "auto", "store": store},
        autostart=True,
    )
    _register_exit_flush(handle)
    return handle


def _seeded_store(client: Any) -> Any:
    """A manifest store primed from ``~/.knoxcall/intercept-manifest.json`` and
    writing back to it. Best-effort throughout: no cache is slower, never
    wrong."""
    from knoxcall._intercept_store import InterceptManifestStore
    from knoxcall._local_state import manifest_cache_key, read_cached_manifest, write_cached_manifest
    from knoxcall.auth.credentials_file import resolve_profile
    from knoxcall.wrap_transport import _default_manifest_fetch, _wrap_refresh_hook

    inner = client._async
    try:
        key = manifest_cache_key(
            base_url=getattr(inner, "base_url", "") or "",
            profile=resolve_profile(),
            environment=getattr(inner, "environment", None),
            sandbox=bool(getattr(inner, "sandbox", False)),
        )
    except Exception:  # noqa: BLE001
        key = None

    def on_loaded(manifest: Any) -> None:
        if key is not None:
            write_cached_manifest(key, manifest)

    store = InterceptManifestStore(
        _default_manifest_fetch(inner),
        on_refresh=_wrap_refresh_hook(None),
        on_loaded=on_loaded,
    )
    if key is not None:
        try:
            cached = read_cached_manifest(key)
        except Exception:  # noqa: BLE001
            cached = None
        if cached is not None:
            store.seed(cached[0], age=cached[1])
    return store


def _module_available(name: str) -> bool:
    if name in sys.modules:
        return True
    try:
        import importlib.util

        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError, AttributeError):
        return False


def _register_exit_flush(handle: Any) -> None:
    """Flush the uncovered-egress buffer at exit, with a hard 2-second ceiling.

    A short-lived process (``python script.py``) would otherwise never report —
    the reporter's own timer is about a minute. The ceiling matters more than
    the flush: this runs during interpreter shutdown, so an unreachable network
    must cost the script two seconds, not a connect timeout."""
    import atexit

    def flush() -> None:
        import threading

        worker = threading.Thread(target=_safe_uninstall, args=(handle,), daemon=True)
        worker.start()
        worker.join(timeout=2.0)

    atexit.register(flush)


def _safe_uninstall(handle: Any) -> None:
    try:
        handle.uninstall()
    except BaseException:  # noqa: BLE001 — best-effort: telemetry at shutdown
        pass


def _close(client: Any) -> None:
    try:
        client.close()
    except BaseException:  # noqa: BLE001 — best-effort: we are already on an error path
        pass


# ── introspection (tests, and `knoxcall whoami`-style debugging) ──────────────


def state() -> str:
    """``"pending"`` | ``"ready"`` | ``"disabled"`` — what stage this process is at."""
    return {_PENDING: "pending", _READY: "ready", _DISABLED: "disabled"}[_state]


def handle() -> Any:
    """The installed :class:`InterceptHandle`, or ``None``."""
    return _handle


def _reset_for_tests() -> None:
    """Undo everything this module did, for a test that needs a clean process.
    Not part of the public API."""
    global _state, _handle, _client, _lock, _hinted, _normalise_host, _is_platform_host, _kill_switch
    if _handle is not None:
        _safe_uninstall(_handle)
    if _client is not None:
        _close(_client)
    _restore_shims()
    if _finder is not None:
        _remove_finder(_finder)
    _state = _PENDING
    _handle = None
    _client = None
    _lock = None
    _hinted = False
    _normalise_host = _is_platform_host = _kill_switch = None


# Stage 1 runs on import: the `.pth` line is `import knoxcall_autostart`, and
# a hook that needed a second call would be a hook the `.pth` could get wrong.
try:
    install()
except BaseException:  # noqa: BLE001 — site.py prints a traceback for a failing
    # .pth line, so this module must not have one. An interpreter that cannot
    # arm the hook is an interpreter with no interception, never a broken one.
    pass
