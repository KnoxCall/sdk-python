"""CLI tests — `knoxcall login/logout/whoami` (PKCE, loopback, device flow).

All HTTP is mocked (httpx.MockTransport); the loopback callback server binds
127.0.0.1:0 and is hit locally. Credentials files live under tmp_path only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import string
import threading
import time
import urllib.request
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from knoxcall.auth.credentials_file import format_expiry, read_profile, write_profile
from knoxcall.cli import build_parser, main
from knoxcall.cli._common import CLIError, persist_login
from knoxcall.cli.init import run_init
from knoxcall.cli.login import (
    LoopbackServer,
    auth_code_flow,
    build_authorize_url,
    generate_pkce_pair,
    poll_device_token,
    run_login,
)
from knoxcall.cli.logout import run_logout

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
    "KNOXCALL_WRAP_SECRET",
)

_BASE = "https://api.example.test"


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch, tmp_path):
    for var in _ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("KNOXCALL_CREDENTIALS_FILE", str(tmp_path / "credentials.json"))


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def _parse(argv: list[str]):
    return build_parser().parse_args(argv)


# ── PKCE ─────────────────────────────────────────────────────────────────────


def test_pkce_pair_is_s256_and_urlsafe():
    verifier, challenge = generate_pkce_pair()
    assert 43 <= len(verifier) <= 128  # RFC 7636 §4.1
    allowed = set(string.ascii_letters + string.digits + "-_")
    assert set(verifier) <= allowed
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
    assert challenge == expected
    assert "=" not in challenge
    # fresh entropy per call
    assert generate_pkce_pair()[0] != verifier


def test_authorize_url_uses_cli_alias_and_s256():
    url = build_authorize_url(
        _BASE,
        redirect_uri="http://127.0.0.1:51234/callback",
        state="st_1",
        code_challenge="chal",
        tenant="acme",
    )
    query = parse_qs(urlsplit(url).query)
    assert url.startswith(f"{_BASE}/oauth/authorize?")
    assert query["client_id"] == ["knoxcall-cli"]
    assert query["response_type"] == ["code"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["redirect_uri"] == ["http://127.0.0.1:51234/callback"]
    assert query["state"] == ["st_1"]
    assert query["tenant"] == ["acme"]


# ── Loopback callback server ─────────────────────────────────────────────────


def _hit(url: str) -> None:
    with urllib.request.urlopen(url, timeout=5) as res:
        res.read()


def test_loopback_callback_success():
    server = LoopbackServer()
    try:
        t = threading.Thread(
            target=_hit, args=(f"http://127.0.0.1:{server.port}/callback?code=abc123&state=st1",)
        )
        t.start()
        code = server.wait_for_code(expected_state="st1", timeout=5)
        t.join()
    finally:
        server.close()
    assert code == "abc123"


def test_loopback_callback_error_param():
    server = LoopbackServer()
    try:
        t = threading.Thread(
            target=_hit,
            args=(
                f"http://127.0.0.1:{server.port}/callback"
                "?error=access_denied&error_description=nope&state=st1",
            ),
        )
        t.start()
        with pytest.raises(CLIError) as excinfo:
            server.wait_for_code(expected_state="st1", timeout=5)
        t.join()
    finally:
        server.close()
    assert "nope" in str(excinfo.value)


def test_loopback_callback_state_mismatch():
    server = LoopbackServer()
    try:
        t = threading.Thread(
            target=_hit,
            args=(f"http://127.0.0.1:{server.port}/callback?code=abc123&state=EVIL",),
        )
        t.start()
        with pytest.raises(CLIError) as excinfo:
            server.wait_for_code(expected_state="st1", timeout=5)
        t.join()
    finally:
        server.close()
    assert "state" in str(excinfo.value).lower()


# ── Auth-code flow end-to-end (fake browser, mocked token endpoint) ──────────


def test_auth_code_flow_exchanges_code_with_verifier(capsys):
    exchanged: dict[str, str] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/oauth/token"
        exchanged["form"] = req.content.decode()
        return httpx.Response(
            200,
            json={
                "access_token": "kc_ac",
                "refresh_token": "rt_ac",
                "token_type": "Bearer",
                "expires_in": 3600,
                "tenant": "acme",
                "client_id": "kc_cli_real",
            },
        )

    def fake_browser(url: str):
        query = parse_qs(urlsplit(url).query)
        assert query["client_id"] == ["knoxcall-cli"]
        redirect = query["redirect_uri"][0]
        state = query["state"][0]
        threading.Thread(target=_hit, args=(f"{redirect}?code=authcode1&state={state}",)).start()
        return True

    with _client(handler) as http:
        body = auth_code_flow(_BASE, http=http, open_browser=fake_browser, timeout=10)

    assert body["access_token"] == "kc_ac"
    form = exchanged["form"]
    assert "grant_type=authorization_code" in form
    assert "code=authcode1" in form
    assert "code_verifier=" in form
    assert "client_id=knoxcall-cli" in form
    # the token never hits stdout
    assert "kc_ac" not in capsys.readouterr().out


# ── Device flow polling ──────────────────────────────────────────────────────


def test_device_poll_honors_interval_and_slow_down():
    responses = [
        (400, {"error": "authorization_pending"}),
        (400, {"error": "slow_down"}),
        (400, {"error": "authorization_pending"}),
        (200, {"access_token": "kc_dev", "refresh_token": "rt", "expires_in": 3600}),
    ]
    calls: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        status, body = responses[len(calls)]
        calls.append(req.content.decode())
        return httpx.Response(status, json=body)

    sleeps: list[float] = []
    with _client(handler) as http:
        body = poll_device_token(
            _BASE, "dev_code_1", interval=5, expires_in=900, http=http, sleep=sleeps.append
        )

    assert body["access_token"] == "kc_dev"
    # 5s until slow_down, then bumped by +5 per RFC 8628 §3.5
    assert sleeps == [5, 5, 10, 10]
    assert all("device_code=dev_code_1" in c for c in calls)
    assert "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code" in calls[0]


@pytest.mark.parametrize(
    ("error", "fragment"),
    [("access_denied", "denied"), ("expired_token", "knoxcall login")],
)
def test_device_poll_terminal_errors(error, fragment):
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": error})

    with _client(handler) as http:
        with pytest.raises(CLIError) as excinfo:
            poll_device_token(_BASE, "dev_code_1", http=http, sleep=lambda s: None)
    assert fragment in str(excinfo.value)


# ── Profile write / merge / persist ──────────────────────────────────────────


def test_profile_write_and_merge(tmp_path):
    path = str(tmp_path / "credentials.json")
    write_profile(path, "default", {"tenant": "acme", "refresh_token": "rt1"})
    write_profile(path, "work", {"tenant": "globex", "refresh_token": "rt2"})

    with open(path, encoding="utf8") as f:
        doc = json.load(f)
    assert doc["version"] == 1
    assert set(doc["profiles"]) == {"default", "work"}

    # overwriting one profile leaves the other intact
    write_profile(path, "default", {"tenant": "acme", "refresh_token": "rt3"})
    assert read_profile(path, "default")["refresh_token"] == "rt3"
    assert read_profile(path, "work")["refresh_token"] == "rt2"


def test_persist_login_records_extension_members(tmp_path):
    path = str(tmp_path / "credentials.json")
    persist_login(
        path=path,
        profile="default",
        base_url=_BASE,
        token_body={
            "access_token": "kc_a",
            "refresh_token": "rt_a",
            "expires_in": 3600,
            "scope": "routes:read",
            "tenant": "acme",
            "client_id": "kc_cli_real",  # extension member: real per-tenant client
        },
    )
    on_disk = read_profile(path, "default")
    assert on_disk["client_id"] == "kc_cli_real"
    assert on_disk["tenant"] == "acme"
    assert on_disk["base_url"] == _BASE
    assert on_disk["refresh_token"] == "rt_a"
    assert on_disk["access_token_expires_at"].endswith("Z")


# ── login command (device path, fully mocked) ────────────────────────────────


@pytest.mark.parametrize("flag", ["--device", "--no-browser"])
def test_login_device_flow_writes_profile(tmp_path, flag, capsys):
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/oauth/device_authorization":
            assert "client_id=knoxcall-cli" in req.content.decode()
            return httpx.Response(
                200,
                json={
                    "device_code": "dc1",
                    "user_code": "ABCD-EFGH",
                    "verification_uri": f"{_BASE}/oauth/activate",
                    "verification_uri_complete": f"{_BASE}/oauth/activate?user_code=ABCD-EFGH",
                    "expires_in": 900,
                    "interval": 5,
                },
            )
        return httpx.Response(
            200,
            json={
                "access_token": "kc_dev",
                "refresh_token": "rt_dev",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "routes:read",
                "tenant": "acme",
                "client_id": "kc_cli_real",
            },
        )

    args = _parse(["login", flag, "--base-url", _BASE])
    with _client(handler) as http:
        rc = run_login(args, http=http, sleep=lambda s: None)
    assert rc == 0

    record = read_profile(str(tmp_path / "credentials.json"), "default")
    assert record["client_id"] == "kc_cli_real"
    assert record["refresh_token"] == "rt_dev"
    assert record["tenant"] == "acme"
    assert record["base_url"] == _BASE

    out = capsys.readouterr().out
    assert "ABCD-EFGH" in out  # user code shown prominently
    assert "acme" in out
    assert "kc_dev" not in out and "rt_dev" not in out  # tokens never printed


def test_login_respects_profile_flag(tmp_path):
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/oauth/device_authorization":
            return httpx.Response(
                200, json={"device_code": "dc1", "user_code": "X", "verification_uri": "u"}
            )
        return httpx.Response(
            200,
            json={"access_token": "kc_p", "refresh_token": "rt_p", "expires_in": 3600,
                  "tenant": "acme", "client_id": "kc_cli_real"},
        )

    args = _parse(["login", "--device", "--base-url", _BASE, "--profile", "staging"])
    with _client(handler) as http:
        assert run_login(args, http=http, sleep=lambda s: None) == 0
    path = str(tmp_path / "credentials.json")
    assert read_profile(path, "staging")["access_token"] == "kc_p"
    assert read_profile(path, "default") is None


# ── logout ───────────────────────────────────────────────────────────────────


def _seed_profiles(path) -> None:
    for name, rt in (("default", "rt_default"), ("work", "rt_work")):
        write_profile(
            str(path),
            name,
            {
                "tenant": "acme",
                "base_url": _BASE,
                "client_id": "kc_cli_real",
                "refresh_token": rt,
                "access_token": "kc_x",
                "access_token_expires_at": format_expiry(time.time() + 3600),
            },
        )


def test_logout_revokes_and_removes_profile(tmp_path, capsys):
    path = tmp_path / "credentials.json"
    _seed_profiles(path)
    seen: list[tuple[str, str]] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.url.path, req.content.decode()))
        return httpx.Response(200, json={})

    with _client(handler) as http:
        rc = run_logout(_parse(["logout", "--profile", "work"]), http=http)
    assert rc == 0
    assert seen[0][0] == "/oauth/revoke"
    assert "token=rt_work" in seen[0][1]
    assert "client_id=kc_cli_real" in seen[0][1]
    assert read_profile(str(path), "work") is None
    assert read_profile(str(path), "default") is not None  # other profile kept

    # removing the last profile deletes the file
    with _client(handler) as http:
        assert run_logout(_parse(["logout"]), http=http) == 0
    assert not path.exists()


def test_logout_removes_profile_even_when_revoke_fails(tmp_path):
    path = tmp_path / "credentials.json"
    _seed_profiles(path)

    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("server unreachable")

    with _client(handler) as http:
        assert run_logout(_parse(["logout", "--profile", "work"]), http=http) == 0
    assert read_profile(str(path), "work") is None


def test_logout_without_credentials_is_a_noop(capsys):
    assert run_logout(_parse(["logout"])) == 0
    assert "nothing to do" in capsys.readouterr().out


# ── init command ──────────────────────────────────────────────────────────────


def _init_http(handler) -> httpx.AsyncClient:
    """An AsyncClient whose transport is a sync MockTransport handler — the sync
    KnoxCall client drives it on its background loop thread."""
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_init_scaffold_prints_quickstart_and_makes_no_writes(tmp_path, capsys):
    _seed_profiles(tmp_path / "credentials.json")
    paths: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        paths.append(req.url.path)
        return httpx.Response(200, json={"data": {"slug": "acme", "name": "Acme Inc"}, "meta": {}})

    rc = run_init(_parse(["init"]), http=_init_http(handler))
    assert rc == 0
    out = capsys.readouterr().out
    assert "Signed in as Acme Inc" in out
    assert "Wrap a provider SDK through KnoxCall" in out
    assert "knoxcall init --provider stripe" in out
    assert "/v1/wrap/credentials" not in paths  # scaffold writes nothing


def test_init_escrow_moves_key_into_custody_and_prints_base_url(tmp_path, capsys):
    _seed_profiles(tmp_path / "credentials.json")
    paths: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        paths.append(req.url.path)
        if req.url.path == "/v1/wrap/credentials":
            return httpx.Response(200, json={"data": {
                "secret_id": "sec_1", "name": "wrap-stripe", "provider": "stripe",
                "allowed_hosts": ["api.stripe.com"], "sandbox": False,
            }, "meta": {}})
        if req.url.path == "/v1/wrap/tokens":
            return httpx.Response(200, json={"data": {
                "id": "tok_1", "token": "wkt_x",
                "base_url": "https://api.knoxcall.com/wg/wkt_x/api.stripe.com",
                "base_url_style": "path", "host": "api.stripe.com",
                "secret_id": "sec_1", "sandbox": False, "expires_at": None,
            }, "meta": {}})
        return httpx.Response(200, json={"data": {"slug": "acme", "name": "Acme Inc"}, "meta": {}})

    rc = run_init(
        _parse(["init", "--provider", "stripe", "--secret-name", "wrap-stripe",
                "--host", "api.stripe.com"]),
        http=_init_http(handler),
        env={"KNOXCALL_WRAP_SECRET": "sk_live_SECRET"},
    )
    assert rc == 0
    assert "/v1/wrap/credentials" in paths
    assert "/v1/wrap/tokens" in paths
    out = capsys.readouterr().out
    assert "in KnoxCall custody" in out
    assert "https://api.knoxcall.com/wg/wkt_x/api.stripe.com" in out
    assert "sk_live_SECRET" not in out  # the raw provider key is never printed


def test_init_escrow_requires_key_in_env_not_a_flag(tmp_path):
    _seed_profiles(tmp_path / "credentials.json")

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"slug": "acme", "name": "Acme Inc"}, "meta": {}})

    with pytest.raises(CLIError, match="KNOXCALL_WRAP_SECRET"):
        run_init(
            _parse(["init", "--provider", "stripe", "--secret-name", "wrap-stripe",
                    "--host", "api.stripe.com"]),
            http=_init_http(handler),
            env={},
        )


def test_init_errors_with_relogin_hint_when_not_logged_in():
    with pytest.raises(CLIError, match="knoxcall login"):
        run_init(_parse(["init"]))


def test_init_appears_in_top_level_help(capsys):
    with pytest.raises(SystemExit) as excinfo:
        build_parser().parse_args(["--help"])
    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    assert "{login,logout,whoami,init,ai}" in out
    assert "init" in out


# ── main() dispatch + human-first errors ─────────────────────────────────────


def test_main_prints_human_error_and_exits_1(capsys):
    rc = main(["whoami"])  # no stored credentials in the isolated env
    assert rc == 1
    err = capsys.readouterr().err
    assert "knoxcall login" in err
    assert "Traceback" not in err


def test_main_logout_exit_zero(capsys):
    assert main(["logout"]) == 0
