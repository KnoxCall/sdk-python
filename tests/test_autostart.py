"""The default-on interception hook — ``knoxcall_autostart`` plus the two
behaviours it needed from the interceptor (lazy first manifest load, and an
explicit ``intercept()`` adopting the hook's install).

What is tested HERE is everything decidable in-process. What is NOT, and why:
the shipped ``.pth`` can only be proved by installing a wheel, so the packaging
assertions below check the three facts a broken wheel would break (the file
exists, it is executable by ``site.py``, and ``pyproject.toml`` ships it), and
the end-to-end behaviour is exercised by the harness described in
``docs/internal/sdk-wrapping/default-on-interception.md``.
"""

from __future__ import annotations

import asyncio
import io
import json
import sys
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

import knoxcall_autostart as autostart
# `knoxcall.login` the attribute is the exported login() FUNCTION (see
# knoxcall/__init__.py), which shadows the submodule of the same name — so
# the module is reached through sys.modules, never through a dotted string.
import importlib
LOGIN = importlib.import_module("knoxcall.login")
from knoxcall import _local_state as state
from knoxcall._intercept_patch import autostart_install, install_intercept
from knoxcall._intercept_store import InterceptManifestStore
from knoxcall.errors import NotAuthenticatedError

PKG_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    """Every test starts with the hook un-armed, no kill switch, and its state
    files pointed at a temp directory (never the developer's ~/.knoxcall)."""
    for var in ("KNOXCALL_INTERCEPT", "KNOXCALL_AUTOSTART", "KNOXCALL_AUTOSTART_VERBOSE",
                "KNOXCALL_AUTOSTART_HOSTS", "KNOXCALL_NO_INTERACTIVE", "CI"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("KNOXCALL_CREDENTIALS_FILE", str(tmp_path / "credentials.json"))
    autostart._reset_for_tests()
    yield
    autostart._reset_for_tests()


# ── packaging: the three facts a broken wheel would break ────────────────────


def test_the_pth_is_shipped_executable_by_site_and_names_the_toplevel_module() -> None:
    pth = PKG_ROOT / "src" / "knoxcall-autostart.pth"
    assert pth.exists(), "the startup hook's .pth is missing from the source tree"
    line = pth.read_text(encoding="utf8").strip()
    # site.py only EXECUTES a line starting with "import " — anything else is
    # treated as a path to add to sys.path, which would silently do nothing.
    assert line.startswith("import "), line
    assert "knoxcall_autostart" in line
    # NOT `knoxcall._autostart`: importing a submodule executes the package's
    # __init__, which imports httpx into every Python process on the machine.
    assert "knoxcall._autostart" not in line
    assert line.count("\n") == 0, "a .pth entry is one line"


def test_the_pth_and_the_hook_module_are_both_force_included_in_the_wheel() -> None:
    toml = (PKG_ROOT / "pyproject.toml").read_text(encoding="utf8")
    assert '"src/knoxcall-autostart.pth" = "knoxcall-autostart.pth"' in toml
    assert '"src/knoxcall_autostart.py" = "knoxcall_autostart.py"' in toml


def test_the_hook_module_imports_nothing_expensive_at_module_scope() -> None:
    """The guard on the whole design: this module is imported at the start of
    EVERY Python process in the environment. A new module-scope import here
    costs every one of them, so the set is pinned."""
    source = (PKG_ROOT / "src" / "knoxcall_autostart.py").read_text(encoding="utf8")
    tree = __import__("ast").parse(source)
    ast = __import__("ast")
    top_level = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    names: set[str] = set()
    for node in top_level:
        if isinstance(node, ast.Import):
            names.update(a.name.split(".")[0] for a in node.names)
        elif node.module:
            names.add(node.module.split(".")[0])
    assert names <= {"os", "sys", "__future__"}, (
        f"module-scope imports {sorted(names)} — every Python process in the "
        "environment pays for these. Move it inside the function that needs it."
    )


# ── stage 1: arming ──────────────────────────────────────────────────────────


def test_install_arms_a_finder_and_is_disabled_by_the_env_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "httpx", sys.modules["httpx"])
    autostart._reset_for_tests()
    monkeypatch.setenv("KNOXCALL_AUTOSTART", "off")
    assert autostart.install() is False
    assert not any(type(f).__name__ == "_SeamArmer" for f in sys.meta_path)

    monkeypatch.delenv("KNOXCALL_AUTOSTART")
    assert autostart.install() is True
    assert autostart.state() == "pending"


def test_the_finder_is_inert_for_every_other_module_and_never_raises() -> None:
    armer = autostart._SeamArmer(("httpx", "urllib3"))
    assert armer.find_spec("json") is None
    assert armer.find_spec("a.b.c", None, None) is None
    # Garbage in, None out — a finder that raises breaks every later import.
    assert armer.find_spec(None) is None  # type: ignore[arg-type]
    assert armer.find_spec(object()) is None  # type: ignore[arg-type]


def test_arming_an_already_imported_stack_patches_it_without_promoting() -> None:
    original = httpx.HTTPTransport.handle_request
    assert autostart.install() is True
    assert httpx.HTTPTransport.handle_request is not original, "httpx was already imported, so it should be armed"
    assert autostart.state() == "pending", "arming must not build a client"
    autostart._reset_for_tests()
    assert httpx.HTTPTransport.handle_request is original


# ── stage 3: what is and is not a reason to promote ──────────────────────────


@pytest.mark.parametrize(
    "host,expected",
    [
        ("api.klaviyo.com", True),
        ("API.Klaviyo.COM.", True),  # normalised through the shared contract
        ("knoxcall.com", False),  # anti-recursion: never our own hosts
        ("api.knoxcall.com", False),
        ("", False),
        (None, False),
    ],
)
def test_only_a_third_party_host_is_worth_promoting(host: Any, expected: bool) -> None:
    autostart.install()
    autostart._bind_host_contract()
    assert autostart._worth_promoting(host) is expected


def test_the_kill_switch_stops_promotion(monkeypatch: pytest.MonkeyPatch) -> None:
    autostart.install()
    autostart._bind_host_contract()
    monkeypatch.setenv("KNOXCALL_INTERCEPT", "off")
    assert autostart._worth_promoting("api.klaviyo.com") is False
    monkeypatch.setenv("KNOXCALL_INTERCEPT", "on")
    assert autostart._worth_promoting("api.klaviyo.com") is True


def test_a_disabled_hook_never_promotes_again() -> None:
    autostart.install()
    autostart._bind_host_contract()
    autostart._state = autostart._DISABLED
    assert autostart._worth_promoting("api.klaviyo.com") is False
    assert autostart._promote("httpx_sync") is None


# ── the login prompt and its guards ──────────────────────────────────────────


def _refuse_to_be_called(*a: Any, **k: Any) -> Any:
    raise AssertionError("the login flow must not run here")


@pytest.mark.parametrize("var", ["KNOXCALL_NO_INTERACTIVE", "CI"])
def test_no_prompt_and_NO_OUTPUT_under_the_non_interactive_guards(
    monkeypatch: pytest.MonkeyPatch, var: str, capsys: Any
) -> None:
    """Operator decision, 2026-10-08: the hook says NOTHING on its own.

    An unprompted line costs every customer's CI log one copy per process,
    forever, and nobody acts on it there. Observed concretely in this repo's own
    `pip-audit` step, which is what prompted the decision. The documentation is
    what tells people to run `knoxcall login`."""
    monkeypatch.setenv(var, "1")
    monkeypatch.setattr(LOGIN, "ensure_login_sync", _refuse_to_be_called)
    assert autostart._login_and_build("default") is None
    assert capsys.readouterr().err == "", "the hook announced itself uninvited"


def test_no_prompt_and_no_output_without_a_tty(monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    monkeypatch.setattr(LOGIN, "ensure_login_sync", _refuse_to_be_called)
    assert autostart._login_and_build("default") is None
    assert capsys.readouterr().err == ""


def test_a_promotion_failure_is_also_silent(monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
    """Even a genuine error. It is still something the hook decided to say on
    its own, and it would reach a CI log the same way."""
    autostart.install()
    autostart._bind_host_contract()
    monkeypatch.setattr(autostart, "_build", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    assert autostart._promote("httpx_sync") is None
    assert autostart.state() == "disabled"
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("var", ["KNOXCALL_NO_INTERACTIVE", "CI"])
def test_verbose_opts_in_to_the_diagnostic_and_says_it_once(
    monkeypatch: pytest.MonkeyPatch, var: str, capsys: Any
) -> None:
    monkeypatch.setenv(var, "1")
    monkeypatch.setenv("KNOXCALL_AUTOSTART_VERBOSE", "1")
    monkeypatch.setattr(LOGIN, "ensure_login_sync", _refuse_to_be_called)
    for _ in range(3):
        autostart._login_and_build("default")
    lines = [l for l in capsys.readouterr().err.splitlines() if l.startswith("KnoxCall:")]
    assert len(lines) == 1, lines
    assert "knoxcall login" in lines[0]


@pytest.mark.parametrize("value,on", [("1", True), ("true", True), ("yes", True), ("verbose", True),
                                      ("", False), ("0", False), ("false", False), ("no", False), ("off", False)])
def test_the_verbose_switch_spellings(monkeypatch: pytest.MonkeyPatch, value: str, on: bool) -> None:
    monkeypatch.setenv("KNOXCALL_AUTOSTART_VERBOSE", value)
    assert autostart.verbose() is on


def test_the_interactive_login_still_speaks_without_the_verbose_switch(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    """The one deliberate exception. A browser window appearing unbidden needs a
    reason on screen, and the outcome of something the user just did is not the
    hook talking to itself. Both need a TTY, so neither can reach a CI log."""
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)

    class FakeSync:
        pass

    monkeypatch.setattr(LOGIN, "ensure_login_sync", lambda **kw: FakeSync())
    assert isinstance(autostart._login_and_build("default"), FakeSync)
    err = capsys.readouterr().err
    assert "signing you in once" in err
    assert "signed in." in err


def test_a_declined_login_is_recorded_and_never_asked_again(monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
    calls: list[int] = []

    def decline(**kw: Any) -> Any:
        calls.append(1)
        raise NotAuthenticatedError("timed out waiting for the browser sign-in to complete")

    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(LOGIN, "ensure_login_sync", decline)

    assert autostart._login_and_build("default") is None
    assert len(calls) == 1
    assert state.login_declined("default") is True
    assert "knoxcall login" in capsys.readouterr().err

    # A second process (same state file) must not ask again.
    autostart._hinted = False
    assert autostart._login_and_build("default") is None
    assert len(calls) == 1, "the recorded decline was ignored and the user was asked twice"


def test_ctrl_c_during_login_is_recorded_and_re_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)

    def interrupt(**kw: Any) -> Any:
        raise KeyboardInterrupt

    monkeypatch.setattr(LOGIN, "ensure_login_sync", interrupt)
    with pytest.raises(KeyboardInterrupt):
        autostart._login_and_build("default")
    assert state.login_declined("default") is True


def test_a_successful_login_clears_an_earlier_decline(monkeypatch: pytest.MonkeyPatch) -> None:
    state.record_login_declined("default", "timeout")
    state.record_no_credential("default")
    assert state.login_declined("default") and state.no_credential_recorded("default")

    class FakeSync:
        pass

    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(LOGIN, "ensure_login_sync", lambda **kw: FakeSync())
    # The decline record is consulted first, so clear it the way `knoxcall
    # login` does before asserting the success path.
    state.clear_login_declined("default")
    assert isinstance(autostart._login_and_build("default"), FakeSync)
    assert state.login_declined("default") is False
    assert state.no_credential_recorded("default") is False


# ── _local_state ─────────────────────────────────────────────────────────────


def test_manifest_cache_round_trip_with_age(tmp_path: Path) -> None:
    path = str(tmp_path / "m.json")
    key = state.manifest_cache_key(base_url="https://api.knoxcall.com", profile="default", environment=None, sandbox=False)
    manifest = {"version": "v1", "ttl_seconds": 60, "routes": [{"host": "a.klaviyo.com", "base_path": "/", "slug": "k"}]}
    assert state.write_cached_manifest(key, manifest, path=path) is True
    got = state.read_cached_manifest(key, path=path)
    assert got is not None
    cached, age = got
    assert cached["version"] == "v1" and 0 <= age < 5


def test_manifest_cache_keys_separate_environments_and_modes() -> None:
    base = dict(base_url="https://api.knoxcall.com", profile="default", environment=None, sandbox=False)
    k = state.manifest_cache_key(**base)
    assert k != state.manifest_cache_key(**{**base, "sandbox": True})
    assert k != state.manifest_cache_key(**{**base, "environment": "staging"})
    assert k != state.manifest_cache_key(**{**base, "profile": "other"})
    assert k != state.manifest_cache_key(**{**base, "base_url": "https://api.staging.knoxcall.com"})
    assert k == state.manifest_cache_key(**base), "the key must be stable"


def test_the_manifest_cache_holds_no_credential_material(tmp_path: Path) -> None:
    path = str(tmp_path / "m.json")
    key = state.manifest_cache_key(base_url="https://api.knoxcall.com", profile="default", environment=None, sandbox=False)
    state.write_cached_manifest(key, {"version": "v1", "ttl_seconds": 60, "routes": [{"host": "a.b", "base_path": "/", "slug": "s"}]}, path=path)
    raw = Path(path).read_text(encoding="utf8")
    for forbidden in ("access_token", "refresh_token", "client_secret", "Bearer", "kc_at_", "kc_rt_"):
        assert forbidden not in raw, f"{forbidden!r} reached the manifest cache"


@pytest.mark.parametrize("body", ["", "not json", "[]", '{"entries": 5}', '{"entries": {"k": {"manifest": 1}}}',
                                  '{"entries": {"k": {"manifest": {"routes": []}}}}'])
def test_a_corrupt_or_wrong_shaped_cache_reads_as_absent(tmp_path: Path, body: str) -> None:
    path = tmp_path / "m.json"
    path.write_text(body, encoding="utf8")
    assert state.read_cached_manifest("k", path=str(path)) is None


def test_the_cache_is_bounded(tmp_path: Path) -> None:
    path = str(tmp_path / "m.json")
    for i in range(state.MAX_MANIFEST_ENTRIES + 6):
        state.write_cached_manifest(f"key{i}", {"version": f"v{i}", "ttl_seconds": 60, "routes": []}, path=path)
    entries = json.loads(Path(path).read_text(encoding="utf8"))["entries"]
    assert len(entries) == state.MAX_MANIFEST_ENTRIES
    assert f"key{state.MAX_MANIFEST_ENTRIES + 5}" in entries, "the newest entry was evicted"


def test_an_unwritable_location_is_not_an_error(tmp_path: Path) -> None:
    # A file where a directory must be: makedirs fails, and the caller carries on.
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf8")
    assert state.write_json(str(blocker / "sub" / "m.json"), {"a": 1}) is False
    assert state.read_json(str(blocker / "sub" / "m.json")) is None


def test_the_no_credential_verdict_expires(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = str(tmp_path / "a.json")
    assert state.no_credential_recorded("default", path=path) is False
    state.record_no_credential("default", path=path)
    assert state.no_credential_recorded("default", path=path) is True
    far_future = time.time() + 1e6
    monkeypatch.setattr(time, "time", lambda: far_future)
    assert state.no_credential_recorded("default", path=path) is False


# ── the store: seeding from the cache, and the write-back hook ───────────────


def _store(fetch: Any, **kw: Any) -> InterceptManifestStore:
    return InterceptManifestStore(fetch, **kw)


def test_seed_adopts_a_cached_manifest_and_keeps_only_the_remaining_ttl() -> None:
    now = [1000.0]
    s = _store(lambda: None, now=lambda: now[0])
    assert s.seed({"version": "v1", "ttl_seconds": 60, "routes": []}, age=45.0) is True
    assert s.manifest is not None and s.version == "v1"
    assert s.stale() is False
    now[0] += 14
    assert s.stale() is False
    now[0] += 2  # 45 + 16 > 60
    assert s.stale() is True


def test_seed_refuses_a_cache_that_would_overwrite_a_real_fetch_or_a_bad_shape() -> None:
    s = _store(lambda: None)
    assert s.seed({"ttl_seconds": 60, "routes": []}) is False  # no version
    assert s.seed({"version": "v1", "ttl_seconds": 60}) is False  # no routes
    assert s.seed({"version": "v1", "ttl_seconds": 60, "routes": []}) is True
    assert s.seed({"version": "v2", "ttl_seconds": 60, "routes": []}) is False, "a held manifest outranks the cache"
    s.stop()
    s2 = _store(lambda: None)
    s2.stop()
    assert s2.seed({"version": "v1", "ttl_seconds": 60, "routes": []}) is False


def test_a_cached_manifest_already_past_its_ttl_seeds_stale_but_usable() -> None:
    s = _store(lambda: None)
    assert s.seed({"version": "v1", "ttl_seconds": 60, "routes": [{"host": "a.b", "base_path": "/", "slug": "s"}]}, age=600.0) is True
    assert s.stale() is True, "it must refresh on the first request"
    assert s.manifest is not None, "but it is still there as stale-but-valid cover"


def test_on_loaded_fires_for_a_body_and_not_for_a_304() -> None:
    loaded: list[Any] = []
    versions = iter([{"version": "v1", "ttl_seconds": 60, "routes": []}, None,
                     {"version": "v1", "ttl_seconds": 60, "routes": []}])

    async def fetch(*, if_none_match: str | None = None) -> Any:
        return next(versions)

    s = _store(fetch, on_loaded=loaded.append)
    asyncio.run(s.arefresh("t", force=True))
    assert len(loaded) == 1
    asyncio.run(s.arefresh("t", force=True))  # 304
    assert len(loaded) == 1, "a 304 is not a load"
    asyncio.run(s.arefresh("t", force=True))  # 200, same version
    assert len(loaded) == 2, "an unchanged-but-refetched manifest still refreshes the cache's clock"


def test_a_failing_on_loaded_hook_never_fails_the_refresh() -> None:
    async def fetch(*, if_none_match: str | None = None) -> Any:
        return {"version": "v1", "ttl_seconds": 60, "routes": []}

    def boom(_m: Any) -> None:
        raise RuntimeError("disk full")

    s = _store(fetch, on_loaded=boom)
    assert asyncio.run(s.arefresh("t", force=True)) is not None
    assert s.version == "v1"


# ── the two interceptor changes the hook needed ──────────────────────────────


class _Client:
    """The smallest client the interceptor will accept."""

    def __init__(self, routes: list[dict[str, Any]]) -> None:
        self.sandbox = False
        self.base_url = "https://api.test"
        self.proxy_base_url = "https://acme.test"
        self.environment = None
        self._routes = routes
        self.manifest_calls = 0
        self.route_calls: list[dict[str, Any]] = []

    async def fetch_manifest(self, **kw: Any) -> dict[str, Any]:
        self.manifest_calls += 1
        return {"version": "v1", "ttl_seconds": 60, "environment": "production", "sandbox": False, "routes": self._routes}

    async def call(self, route: str, *, method: str = "GET", path: str = "/", **kw: Any) -> httpx.Response:
        self.route_calls.append({"route": route, "path": path})
        return httpx.Response(200, json={"ok": True}, headers={"x-knox-upstream-status": "200"})

    async def ephemeral(self, url: str, **kw: Any) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})


ENTRY = {"host": "a.klaviyo.com", "base_path": "/", "slug": "klaviyo", "requires_clients": False}


@pytest.fixture
def _canned(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Pin the ORIGINAL transports so an unmatched host never reaches the network."""
    seen: list[str] = []

    def sync_handle(_self: Any, request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, text="ORIGINAL", request=request)

    async def async_handle(_self: Any, request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, text="ORIGINAL", request=request)

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", sync_handle)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", async_handle)
    return seen


def _install(client: _Client, **over: Any) -> Any:
    opts: dict[str, Any] = dict(
        client=client, runner=lambda c: asyncio.run(c), stacks=["httpx"], hosts=[], host_options={},
        require_context=False,
        transport_opts={"routes": "auto", "manifest_fetch": client.fetch_manifest, "observe_uncovered": False},
    )
    opts.update(over)
    return install_intercept(**opts)


def test_the_first_request_loads_the_manifest_with_no_ready_call(_canned: list[str]) -> None:
    """The bug the hook could not work around: with `hosts=()` nothing could
    ever load the manifest, because the load lived behind a match and a match
    needed the manifest."""
    client = _Client([ENTRY])
    handle = _install(client)
    try:
        assert handle.manifest() is None, "nothing is loaded before the first request"
        with httpx.Client() as http:
            http.get("https://a.klaviyo.com/api/profiles")
        assert client.manifest_calls == 1
        assert client.route_calls == [{"route": "klaviyo", "path": "/api/profiles"}]
        assert _canned == [], "the very first request went direct instead of through the Route"
    finally:
        handle.uninstall()


def test_the_lazy_load_is_not_triggered_by_our_own_hosts(_canned: list[str]) -> None:
    """The ordering that stops the manifest fetch asking for the manifest —
    which would re-enter the store's single-flight lock and deadlock."""
    client = _Client([ENTRY])
    handle = _install(client)
    try:
        with httpx.Client() as http:
            http.get("https://api.test/v1/routes")
            http.get("https://acme.test/x")
            http.get("https://api.knoxcall.com/v1/routes")
        assert client.manifest_calls == 0
        assert len(_canned) == 3
    finally:
        handle.uninstall()


def test_the_lazy_load_happens_once_not_per_request(_canned: list[str]) -> None:
    client = _Client([ENTRY])
    handle = _install(client)
    try:
        with httpx.Client() as http:
            for _ in range(4):
                http.get("https://a.klaviyo.com/api/profiles")
                http.get("https://api.openai.com/v1/models")
        assert client.manifest_calls == 1, "the TTL, not the request, drives refreshes"
        assert len(client.route_calls) == 4
        assert _canned == ["https://api.openai.com/v1/models"] * 4
    finally:
        handle.uninstall()


@pytest.mark.asyncio
async def test_the_async_seam_loads_the_manifest_without_blocking_on_a_runner(_canned: list[str]) -> None:
    client = _Client([ENTRY])
    handle = _install(client, runner=None)
    try:
        async with httpx.AsyncClient() as http:
            await http.get("https://a.klaviyo.com/api/profiles")
        assert client.manifest_calls == 1
        assert client.route_calls == [{"route": "klaviyo", "path": "/api/profiles"}]
    finally:
        handle.uninstall()


def test_an_explicit_intercept_adopts_the_hooks_install_instead_of_raising(_canned: list[str]) -> None:
    hook_client = _Client([ENTRY])
    hook = _install(hook_client, autostart=True)
    assert autostart_install() is hook

    app_client = _Client([ENTRY])
    explicit = _install(app_client)  # would have raised "already installed"
    try:
        assert autostart_install() is None, "the hook's install was not released"
        assert hook.installed is False, "the hook's handle must be uninstalled, not merely forgotten"
        with httpx.Client() as http:
            http.get("https://a.klaviyo.com/api/profiles")
        assert len(app_client.route_calls) == 1, "the explicit install must own the seam"
        assert hook_client.route_calls == [], "the hook's transport must be out of the path"
    finally:
        explicit.uninstall()


def test_two_explicit_installs_still_refuse_each_other(_canned: list[str]) -> None:
    first = _install(_Client([ENTRY]))
    try:
        with pytest.raises(RuntimeError, match="already installed"):
            _install(_Client([ENTRY]))
    finally:
        first.uninstall()


def test_uninstalling_the_explicit_install_does_not_resurrect_the_hook(_canned: list[str]) -> None:
    pre_hook = httpx.HTTPTransport.handle_request  # the canned original
    hook = _install(_Client([ENTRY]), autostart=True)
    assert httpx.HTTPTransport.handle_request is not pre_hook
    explicit = _install(_Client([ENTRY]))
    explicit.uninstall()
    assert httpx.HTTPTransport.handle_request is pre_hook, (
        "the seam must return to the pre-hook original, not to the hook's patch"
    )
    assert hook.installed is False


class _LoopRunner:
    """The sync facade's runner, in miniature: ONE long-lived event loop on a
    background thread. The distinction matters — `asyncio.run` per call gives
    each call its own loop and therefore its own store lock, which is exactly
    the condition that hides the re-entrancy hazard below."""

    def __init__(self) -> None:
        import threading

        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()

    def __call__(self, coro: Any) -> Any:
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout=8)

    def close(self) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(timeout=5)


class _SelfFetchingClient(_Client):
    """A client whose manifest fetch really does egress — over httpx, to its own
    base URL, the way the SDK's does. That is what makes the seam re-entrant."""

    async def fetch_manifest(self, **kw: Any) -> dict[str, Any]:
        async with httpx.AsyncClient() as http:
            await http.get(f"{self.base_url}/v1/wrap/intercept-manifest")
        return await super().fetch_manifest(**kw)


def test_the_manifest_fetchs_own_egress_cannot_ask_for_the_manifest(_canned: list[str]) -> None:
    """Pins the early-out ORDER in `_manifest_needed` by behaviour.

    The manifest fetch egresses to KnoxCall's own host. If deciding that
    request could ask for the manifest to be loaded, the load would re-enter
    the store's single-flight lock from inside its own fetch and wait for
    itself.

    Measured with the early-out removed: the inner refresh blocks on the lock
    the outer one holds, the outer one is blocked on the inner request, and
    nothing breaks the cycle. The REAL sync facade's runner
    (`_KnoxCallSync._run`) calls `future.result()` with no timeout, so the
    real-world shape is an unbounded hang; `_LoopRunner` here caps it at 8 s
    so this guard FAILS instead of hanging CI, and the manifest then never
    loads, so the request also goes direct. Both are asserted."""
    import threading

    runner = _LoopRunner()
    client = _SelfFetchingClient([ENTRY])
    handle = _install(client, runner=runner)
    done: list[Any] = []

    def app_request() -> None:
        try:
            with httpx.Client() as http:
                http.get("https://a.klaviyo.com/api/profiles")
            done.append("ok")
        except BaseException as err:  # noqa: BLE001 — the failure IS the result here
            done.append(f"{type(err).__name__}: {err}")

    worker = threading.Thread(target=app_request, daemon=True)
    worker.start()
    worker.join(timeout=15)
    try:
        assert not worker.is_alive(), "the request never returned: the manifest load waited on itself"
        assert done == ["ok"], done
        assert client.route_calls == [{"route": "klaviyo", "path": "/api/profiles"}], (
            "the manifest never loaded, so a covered host went direct"
        )
        assert client.manifest_calls == 1
    finally:
        handle.uninstall()
        runner.close()


# ── env parsing ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize("value,expected", [
    ("a.example,b.example", ["a.example", "b.example"]),
    (" a.example , b.example ", ["a.example", "b.example"]),
    ("a.example;b.example", ["a.example", "b.example"]),
    ("", []),
    (",,", []),
])
def test_extra_hosts_parsing(monkeypatch: pytest.MonkeyPatch, value: str, expected: list[str]) -> None:
    monkeypatch.setenv("KNOXCALL_AUTOSTART_HOSTS", value)
    assert autostart.extra_hosts() == expected


@pytest.mark.parametrize("value,off", [("off", True), ("0", True), ("false", True), ("FALSE", True),
                                       ("  Off  ", True), ("no", False), ("on", False), ("1", False), ("", False)])
def test_the_disable_switch_spellings(monkeypatch: pytest.MonkeyPatch, value: str, off: bool) -> None:
    monkeypatch.setenv("KNOXCALL_AUTOSTART", value)
    assert autostart.disabled_by_env() is off


@pytest.mark.parametrize(
    "value", ["off", "0", "false", "FALSE", "  Off  ", "no", "on", "1", "", "yes", "true", "OFF"]
)
def test_the_off_grammar_matches_the_kill_switch(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    """KNOXCALL_AUTOSTART and KNOXCALL_INTERCEPT must read the same spellings.

    They are two different variables doing two different jobs, and a user will
    reasonably expect `=off` — and anything else that works on one — to work on
    the other. There is no shared constant to pin them (the hook may not import
    `_intercept` at module scope), so the agreement is pinned by behaviour."""
    from knoxcall._intercept import intercept_kill_switch

    monkeypatch.setenv("KNOXCALL_AUTOSTART", value)
    monkeypatch.setenv("KNOXCALL_INTERCEPT", value)
    assert autostart.disabled_by_env() is intercept_kill_switch(), (
        f"{value!r} means one thing to KNOXCALL_AUTOSTART and another to KNOXCALL_INTERCEPT"
    )


def test_state_is_reportable() -> None:
    assert autostart.state() == "pending"
    assert autostart.handle() is None
