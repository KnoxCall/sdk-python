"""CLI tests — `knoxcall ai` (exchange + the control-plane sub-commands).

The python CLI is PARITY §13's reference implementation, so these assertions are
the contract the other four mirror: the subject token comes from the environment
and never from argv, a host is required rather than guessed, stdout carries the
token and nothing else, and the exit codes are 0 / 1 / 2.

AIGW-162 added five control-plane sub-commands below `ai exchange`; their block
starts at "control-plane sub-commands" and mirrors
sdk/knoxcall-node/test/cli-ai.test.ts assertion for assertion.
"""

from __future__ import annotations

import argparse
import time

import httpx
import pytest

from knoxcall.auth.credentials_file import format_expiry, write_profile
from knoxcall.cli import CLIError, build_parser, main
from knoxcall.cli.ai import SUBJECT_TOKEN_ENV, run_ai_exchange
from knoxcall.cli.ai_control import (
    run_ai_agents,
    run_ai_create_agent,
    run_ai_gateways,
    run_ai_mint,
    run_ai_usage,
)

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


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch, tmp_path):
    """No test may read the developer's real ~/.knoxcall/credentials.json, and
    none may inherit a KNOXCALL_* var from the shell that ran pytest."""
    for var in _ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("KNOXCALL_CREDENTIALS_FILE", str(tmp_path / "credentials.json"))
    return tmp_path


OK = {
    "access_token": "kc_live_agt_deadbeef",
    "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
    "token_type": "Bearer",
    "expires_in": 900,
}


def _args(**overrides):
    parser = build_parser()
    argv = ["ai", "exchange"]
    for key, value in overrides.items():
        flag = "--" + key.replace("_", "-")
        if value is True:
            argv.append(flag)
        elif value is not None and value is not False:
            argv.extend([flag, value])
    return parser.parse_args(argv)


def test_parser_registers_ai_exchange():
    args = _args(tenant="acme")
    assert args.command == "ai"
    assert args.ai_command == "exchange"
    assert args.tenant == "acme"


def test_subject_token_is_not_a_flag():
    # An argv value lands in shell history, ps output and the CI log line, so
    # there must be no way to pass one. This asserts the ABSENCE of a flag —
    # adding `--subject-token` later would fail here.
    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["ai", "exchange", "--subject-token", "a.b.c"])
    assert exc.value.code == 2


def test_refuses_when_the_environment_variable_is_unset(monkeypatch, capsys):
    monkeypatch.delenv(SUBJECT_TOKEN_ENV, raising=False)
    code = main(["ai", "exchange", "--tenant", "acme"])
    assert code == 1
    err = capsys.readouterr().err
    assert SUBJECT_TOKEN_ENV in err
    assert err.startswith("error: ")


def test_refuses_to_guess_a_host(monkeypatch, capsys):
    # api.knoxcall.com answers 401 for this request — the endpoint is not served
    # there — and that 401 reads as "your CI token was rejected".
    monkeypatch.setenv(SUBJECT_TOKEN_ENV, "a.b.c")
    code = main(["ai", "exchange"])
    assert code == 1
    err = capsys.readouterr().err
    assert "--tenant" in err
    assert "401" in err


def test_prints_only_the_token_on_stdout(monkeypatch, capsys):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        return httpx.Response(200, json=OK)

    monkeypatch.setenv(SUBJECT_TOKEN_ENV, "header.payload.sig")
    monkeypatch.setattr(
        "knoxcall.cli.ai.exchange_token_sync",
        lambda **kwargs: _run_with(handler, **kwargs),
    )

    code = run_ai_exchange(_args(tenant="acme"))
    assert code == 0

    out = capsys.readouterr()
    # stdout is captured with $(...), so it must be exactly the token.
    assert out.out == "kc_live_agt_deadbeef\n"
    assert "agent token" in out.err
    assert seen["url"] == "https://acme.knoxcall.com/v1/oauth/token"


def test_resource_narrows_the_token_and_is_reported(monkeypatch, capsys):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=OK)

    monkeypatch.setenv(SUBJECT_TOKEN_ENV, "a.b.c")
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return _run_with(handler, **kwargs)

    monkeypatch.setattr("knoxcall.cli.ai.exchange_token_sync", fake)

    assert run_ai_exchange(_args(tenant="acme", resource="https://acme.knoxcall.com/v1/mcp/gh")) == 0
    assert captured["resource"] == "https://acme.knoxcall.com/v1/mcp/gh"
    assert "tool (MCP, resource-bound)" in capsys.readouterr().err


def test_resource_is_omitted_when_not_asked_for(monkeypatch):
    monkeypatch.setenv(SUBJECT_TOKEN_ENV, "a.b.c")
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return dict(OK)

    monkeypatch.setattr("knoxcall.cli.ai.exchange_token_sync", fake)
    run_ai_exchange(_args(tenant="acme"))
    # Not `resource=None`: the SDK distinguishes absent from empty, and an empty
    # one is a server refusal rather than "no resource".
    assert "resource" not in captured


def test_server_refusal_exits_1_without_a_traceback(monkeypatch, capsys):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400,
            json={"error": "invalid_grant", "error_description": "No tenant bindings registered"},
        )

    monkeypatch.setenv(SUBJECT_TOKEN_ENV, "a.b.c")
    monkeypatch.setattr(
        "knoxcall.cli.ai.exchange_token_sync",
        lambda **kwargs: _run_with(handler, **kwargs),
    )

    code = main(["ai", "exchange", "--tenant", "acme"])
    assert code == 1
    err = capsys.readouterr().err
    assert err.startswith("error: ")
    assert "No tenant bindings" in err
    assert "Traceback" not in err


def _run_with(handler, **kwargs):
    """Call the real SDK helper with a mock transport injected."""
    from knoxcall.resources.token_exchange import exchange_token_sync

    kwargs.pop("http", None)
    return exchange_token_sync(http=httpx.AsyncClient(transport=httpx.MockTransport(handler)), **kwargs)


# ── AIGW-162 — the control-plane sub-commands ────────────────────────────────
#
# `exchange` is the data-plane door and needs no login; these act as the
# signed-in tenant. They exist because there was no CLI golden path at all: the
# five SDK CLIs shipped `exchange` alone, and the capable standalone `cli/` was
# unpublished, untested, un-CI'd, and could not create a secret, a gateway or an
# agent — so it could not reach a first call either.

_BASE = "https://api.example.test"


def _parse(argv: list[str]):
    return build_parser().parse_args(argv)


def _seed_profile(tmp_path, name: str = "default") -> None:
    write_profile(
        str(tmp_path / "credentials.json"),
        name,
        {
            "tenant": "acme",
            "base_url": _BASE,
            "client_id": "kc_cli_real",
            "refresh_token": "rt_x",
            "access_token": "kc_x",
            "access_token_expires_at": format_expiry(time.time() + 3600),
        },
    )


def _http(handler) -> httpx.AsyncClient:
    """An AsyncClient whose transport is a sync MockTransport handler — the sync
    KnoxCall client drives it on its background loop thread."""
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _page(rows: list[dict]) -> dict:
    return {
        "data": rows,
        "meta": {"total": len(rows), "page": 1, "per_page": 100, "total_pages": 1},
    }


def _gateway(gid: str = "gw_1", slug: str = "default", name: str = "Default") -> dict:
    return {"id": gid, "slug": slug, "name": name}


def _agent(aid: str = "ag_1", slug: str = "copilot") -> dict:
    return {
        "id": aid,
        "slug": slug,
        "name": slug,
        "gateway_id": "gw_1",
        "agent_url": f"https://acme.knoxcall.com/v1/ai/{slug}",
    }


# ── parsing ──────────────────────────────────────────────────────────────────


def test_parses_every_sub_command_with_its_own_flag_table():
    gw = _parse(["ai", "agents", "--gateway", "gw_1"])
    assert gw.ai_command == "agents"
    assert gw.gateway == "gw_1"

    created = _parse([
        "ai", "create-agent", "--slug", "copilot", "--provider", "anthropic",
        "--secret-from-env", "ANTHROPIC_API_KEY", "--model", "claude-sonnet-5",
    ])
    assert created.ai_command == "create-agent"
    assert created.slug == "copilot"
    assert created.provider == "anthropic"
    assert created.secret_from_env == "ANTHROPIC_API_KEY"
    assert created.model == "claude-sonnet-5"

    mint = _parse(["ai", "mint", "--agent", "ag_1", "--kind", "read"])
    assert mint.ai_command == "mint"
    assert mint.agent == "ag_1"
    assert mint.kind == "read"

    usage = _parse(["ai", "usage", "--period", "7d"])
    assert usage.ai_command == "usage"
    assert usage.period == "7d"

    gateways = _parse(["ai", "gateways", "--profile", "work", "--sandbox"])
    assert gateways.ai_command == "gateways"
    assert gateways.profile == "work"
    assert gateways.sandbox is True


@pytest.mark.parametrize(
    "argv",
    [
        ["ai", "exchange", "--period", "30d"],
        ["ai", "gateways", "--agent", "ag_1"],
        ["ai", "mint", "--provider", "anthropic"],
        ["ai", "usage", "--secret-from-env", "X"],
    ],
)
def test_the_flag_table_is_per_sub_command_not_shared_across_the_ai_group(argv):
    # One flat table would accept `ai exchange --period 30d` and silently ignore
    # it, which is the opposite of what every other command does with an unknown
    # flag. Each of these is a flag that exists on a DIFFERENT ai sub-command,
    # so a shared table would let all four through.
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(argv)
    assert exc.value.code == 2


def test_has_no_flag_that_would_put_a_provider_key_in_argv():
    # Same rule as --subject-token: the key is read from the environment named
    # by --secret-from-env. Asserting the ABSENCE means adding --secret-value
    # later fails here rather than in someone's shell history.
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(
            ["ai", "create-agent", "--slug", "x", "--secret-value", "sk-ant-live"]
        )
    assert exc.value.code == 2


@pytest.mark.parametrize("argv", [["ai", "agents", "gw_1"], ["ai", "mint", "ag_1"]])
def test_takes_ids_as_flags_never_positionals(argv):
    # Four of the five SDK CLIs hand-roll their parser and reject positionals
    # outright, so a positional id would be a surface that differs by language.
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(argv)
    assert exc.value.code == 2


def _sub_parser(*names: str):
    """Walk down to a nested sub-parser (`ai` -> `create-agent`)."""
    parser = build_parser()
    for name in names:
        action = next(
            a for a in parser._actions if isinstance(a, argparse._SubParsersAction)
        )
        parser = action.choices[name]
    return parser


@pytest.mark.parametrize("name", ["agents", "create-agent", "mint"])
def test_a_hand_written_usage_line_names_every_flag(name):
    # These three carry a hand-written `usage=` because their required flags are
    # enforced in ai_control.py (CLIError, exit 1, with the reason) rather than
    # by argparse (exit 2, no reason) — so argparse would render `--gateway` in
    # square brackets and tell the user it is optional. The cost of writing the
    # line by hand is that it can go stale; this is the guard that stops it.
    parser = _sub_parser("ai", name)
    usage = parser.format_usage()
    for action in parser._actions:
        for flag in action.option_strings:
            if flag in ("-h", "--help"):
                continue
            assert flag in usage, (
                f"`knoxcall ai {name}` accepts {flag} but its hand-written usage line "
                f"does not mention it — update the `usage=` in cli/__init__.py"
            )


@pytest.mark.parametrize(
    ("name", "fragment"),
    [
        ("agents", "--gateway GATEWAY"),
        ("create-agent", "--slug SLUG --provider PROVIDER"),
        ("create-agent", "(--secret SECRET | --secret-from-env VAR)"),
        ("mint", "--agent AGENT"),
    ],
)
def test_required_flags_are_not_rendered_as_optional(name, fragment):
    # `[--slug SLUG]` would tell the user the flag is optional. It is not: the
    # command refuses without it, in all five SDK CLIs.
    usage = _sub_parser("ai", name).format_usage()
    assert fragment in usage
    for flag in fragment.replace("(", "").replace(")", "").split():
        if flag.startswith("--"):
            assert f"[{flag}" not in usage


def test_ai_help_lists_every_sub_command(capsys):
    # The group grew from one sub-command to six. The help is the only place a
    # user discovers them, so it is asserted rather than assumed.
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["ai", "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "{exchange,gateways,agents,create-agent,mint,usage}" in out
    for sub in ("exchange", "gateways", "agents", "create-agent", "mint", "usage"):
        assert sub in out


# ── refusals (exit 1, `error: <msg>`) ────────────────────────────────────────


def test_refuses_to_create_an_agent_with_no_upstream_credential(capsys):
    # The API ACCEPTS this and stores an agent whose first data-plane call 502s
    # (AIGW-161). A command whose whole purpose is reaching a working call must
    # not be able to produce one.
    code = main(["ai", "create-agent", "--slug", "copilot", "--provider", "anthropic"])
    assert code == 1
    err = capsys.readouterr().err
    assert "--secret or --secret-from-env is required" in err
    assert "502s on its first call" in err
    assert err.startswith("error: ")


def test_requires_provider_on_create_agent(capsys):
    code = main(["ai", "create-agent", "--slug", "copilot", "--secret", "sec_1"])
    assert code == 1
    assert "--provider is required" in capsys.readouterr().err


def test_requires_agent_on_mint_and_gateway_on_agents(capsys):
    # Checked before the credential, so this is the message you get on a machine
    # that has never run `knoxcall login` too.
    assert main(["ai", "mint"]) == 1
    assert "--agent is required" in capsys.readouterr().err
    assert main(["ai", "agents"]) == 1
    assert "--gateway is required" in capsys.readouterr().err


def test_control_plane_commands_require_a_login(capsys):
    assert main(["ai", "gateways"]) == 1
    err = capsys.readouterr().err
    assert "not logged in (profile 'default')" in err
    assert "knoxcall login" in err


def test_create_agent_env_var_unset_names_the_variable_and_the_missing_flag(tmp_path, capsys):
    _seed_profile(tmp_path)

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_page([_gateway()]))

    with pytest.raises(CLIError, match="ANTHROPIC_API_KEY"):
        run_ai_create_agent(
            _parse(["ai", "create-agent", "--slug", "copilot", "--provider", "anthropic",
                    "--secret-from-env", "ANTHROPIC_API_KEY"]),
            http=_http(handler),
            env={},
        )


# ── wired behaviour ──────────────────────────────────────────────────────────


def test_gateways_lists_id_slug_name(tmp_path, capsys):
    _seed_profile(tmp_path)

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/v1/ai-gateway/gateways"
        return httpx.Response(200, json=_page([_gateway("gw_1", "default", "Default")]))

    assert run_ai_gateways(_parse(["ai", "gateways"]), http=_http(handler)) == 0
    assert capsys.readouterr().out == "gw_1  default  Default\n"


def test_agents_prints_the_agent_url_as_the_third_column(tmp_path, capsys):
    _seed_profile(tmp_path)

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/v1/ai-gateway/gateways/gw_1/agents"
        return httpx.Response(200, json=_page([_agent()]))

    rc = run_ai_agents(_parse(["ai", "agents", "--gateway", "gw_1"]), http=_http(handler))
    assert rc == 0
    # agent_url is on every projection since AIGW-161, so the list alone is
    # enough to point an SDK at an existing agent.
    assert capsys.readouterr().out == (
        "ag_1  copilot  https://acme.knoxcall.com/v1/ai/copilot\n"
    )


def test_create_agent_bootstraps_a_gateway_escrows_the_key_and_prints_only_the_id(
    tmp_path, capsys
):
    _seed_profile(tmp_path)
    seen: list[tuple[str, str]] = []
    bodies: dict[str, str] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        key = f"{req.method} {req.url.path}"
        seen.append((req.method, req.url.path))
        bodies[key] = req.content.decode() if req.content else ""
        if key == "GET /v1/ai-gateway/gateways":
            return httpx.Response(200, json=_page([]))          # a fresh tenant
        if key == "POST /v1/ai-gateway/gateways":
            return httpx.Response(200, json={"data": _gateway("gw_new"), "meta": {}})
        if key == "GET /v1/secrets":
            return httpx.Response(200, json=_page([]))
        if key == "POST /v1/secrets":
            return httpx.Response(200, json={"data": {
                "id": "sec_new", "name": "ai-gateway-copilot-key",
                "secret_type": "api_key", "base_environment": "production",
                "collection_id": None,
            }, "meta": {}})
        if key == "POST /v1/ai-gateway/gateways/gw_new/agents":
            return httpx.Response(200, json={"data": _agent(), "meta": {}})
        raise AssertionError(f"unexpected request {key}")

    rc = run_ai_create_agent(
        _parse(["ai", "create-agent", "--slug", "copilot", "--provider", "anthropic",
                "--secret-from-env", "ANTHROPIC_API_KEY"]),
        http=_http(handler),
        env={"ANTHROPIC_API_KEY": "sk-ant-SECRET"},
    )
    assert rc == 0

    captured = capsys.readouterr()
    # stdout is captured with $(...), so it must be exactly the agent id.
    assert captured.out == "ag_1\n"
    # Everything a human needs next — including the literal next command.
    assert "knoxcall ai mint --agent ag_1" in captured.err
    assert "https://acme.knoxcall.com/v1/ai/copilot" in captured.err
    assert "in KnoxCall custody" in captured.err
    # The provider key is never echoed back at the operator.
    assert "sk-ant-SECRET" not in captured.out
    assert "sk-ant-SECRET" not in captured.err

    assert ("POST", "/v1/ai-gateway/gateways") in seen       # bootstrapped a gateway
    assert ("POST", "/v1/secrets") in seen                   # escrowed the key
    created = bodies["POST /v1/ai-gateway/gateways/gw_new/agents"]
    assert '"provider": "anthropic"' in created or '"provider":"anthropic"' in created
    assert "sec_new" in created                              # the upstream credential
    assert "sk-ant-SECRET" in bodies["POST /v1/secrets"]      # …and only there


def test_create_agent_reuses_a_secret_of_the_same_name(tmp_path, capsys):
    _seed_profile(tmp_path)
    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        key = f"{req.method} {req.url.path}"
        seen.append(key)
        if key == "GET /v1/ai-gateway/gateways":
            return httpx.Response(200, json=_page([_gateway()]))
        if key == "GET /v1/secrets":
            return httpx.Response(200, json=_page([
                {"id": "sec_old", "name": "ai-gateway-copilot-key"},
            ]))
        if key == "POST /v1/ai-gateway/gateways/gw_1/agents":
            return httpx.Response(200, json={"data": _agent(), "meta": {}})
        raise AssertionError(f"unexpected request {key}")

    rc = run_ai_create_agent(
        _parse(["ai", "create-agent", "--slug", "copilot", "--provider", "anthropic",
                "--secret-from-env", "ANTHROPIC_API_KEY"]),
        http=_http(handler),
        env={"ANTHROPIC_API_KEY": "sk-ant-SECRET"},
    )
    assert rc == 0
    # Re-running must not leave a second copy of the same credential behind.
    assert "POST /v1/secrets" not in seen
    assert "reusing secret 'ai-gateway-copilot-key' (sec_old)" in capsys.readouterr().err


def test_create_agent_refuses_to_pick_among_several_gateways(tmp_path, capsys):
    _seed_profile(tmp_path)

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.method == "GET" and req.url.path == "/v1/ai-gateway/gateways"
        return httpx.Response(200, json=_page([
            _gateway("gw_1", "prod", "Prod"), _gateway("gw_2", "lab", "Lab"),
        ]))

    # "whichever sorts first" is how the quickstart wizard silently landed a
    # second agent in the wrong gateway.
    with pytest.raises(CLIError, match="--gateway is required"):
        run_ai_create_agent(
            _parse(["ai", "create-agent", "--slug", "copilot", "--provider", "anthropic",
                    "--secret", "sec_1"]),
            http=_http(handler),
        )


def test_create_agent_resolves_a_gateway_by_slug(tmp_path, capsys):
    _seed_profile(tmp_path)

    def handler(req: httpx.Request) -> httpx.Response:
        key = f"{req.method} {req.url.path}"
        if key == "GET /v1/ai-gateway/gateways":
            return httpx.Response(200, json=_page([
                _gateway("gw_1", "prod", "Prod"), _gateway("gw_2", "lab", "Lab"),
            ]))
        if key == "POST /v1/ai-gateway/gateways/gw_2/agents":
            return httpx.Response(200, json={"data": _agent(), "meta": {}})
        raise AssertionError(f"unexpected request {key}")

    rc = run_ai_create_agent(
        _parse(["ai", "create-agent", "--slug", "copilot", "--provider", "anthropic",
                "--secret", "sec_1", "--gateway", "lab"]),
        http=_http(handler),
    )
    assert rc == 0
    assert "gateway:   gw_2" in capsys.readouterr().err


def test_create_agent_names_the_gateways_it_knows_when_the_flag_matches_none(tmp_path):
    _seed_profile(tmp_path)

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_page([_gateway("gw_1", "prod", "Prod")]))

    with pytest.raises(CLIError, match=r"no gateway 'nope'"):
        run_ai_create_agent(
            _parse(["ai", "create-agent", "--slug", "copilot", "--provider", "anthropic",
                    "--secret", "sec_1", "--gateway", "nope"]),
            http=_http(handler),
        )


def test_mint_prints_only_the_token_on_stdout(tmp_path, capsys):
    _seed_profile(tmp_path)

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/v1/ai-gateway/agents/ag_1/tokens"
        return httpx.Response(200, json={"data": {
            "id": "tok_1", "name": "ci", "kind": "read", "prefix": "kc_live_agt_",
            "token": "kc_live_agt_deadbeef", "dpop_required": False,
            "expires_at": "2026-10-07T00:00:00.000Z",
        }, "meta": {}})

    rc = run_ai_mint(
        _parse(["ai", "mint", "--agent", "ag_1", "--kind", "read", "--name", "ci"]),
        http=_http(handler),
    )
    assert rc == 0
    captured = capsys.readouterr()
    # `> token.txt` must capture the token and nothing else.
    assert captured.out == "kc_live_agt_deadbeef\n"
    assert "Save this token now" in captured.err
    assert "kind:     read" in captured.err


def test_usage_prints_totals_and_the_by_model_table(tmp_path, capsys):
    _seed_profile(tmp_path)

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/v1/ai-gateway/usage"
        assert req.url.params["period"] == "7d"
        return httpx.Response(200, json={"data": {
            "period_days": 7,
            "totals": {"requests": 12, "input_tokens": 3400, "output_tokens": 900,
                       "cost_usd": 1.23456, "unpriced_requests": 1},
            "by_model": [{"provider": "anthropic", "model": "claude-sonnet-5",
                          "requests": 12, "input_tokens": 3400, "output_tokens": 900,
                          "cost_usd": 1.23456}],
        }, "meta": {}})

    assert run_ai_usage(_parse(["ai", "usage", "--period", "7d"]), http=_http(handler)) == 0
    out = capsys.readouterr().out
    assert "Usage — last 7 days" in out
    assert "requests:      12" in out
    assert "cost (USD):    1.2346" in out
    assert "anthropic/claude-sonnet-5  12 req  in 3400  out 900  $1.2346" in out


def test_usage_says_so_when_the_period_is_empty(tmp_path, capsys):
    _seed_profile(tmp_path)

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {
            "period_days": 30,
            "totals": {"requests": 0, "input_tokens": 0, "output_tokens": 0,
                       "cost_usd": 0, "unpriced_requests": 0},
            "by_model": [],
        }, "meta": {}})

    assert run_ai_usage(_parse(["ai", "usage"]), http=_http(handler)) == 0
    assert "No usage in this period." in capsys.readouterr().out
