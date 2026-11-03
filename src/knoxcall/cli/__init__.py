"""KnoxCall CLI — ``knoxcall login`` / ``logout`` / ``whoami`` / ``init`` / ``ai``.

Console-script entry point (``knoxcall = knoxcall.cli:main``). Credentials
are stored in the cross-SDK ``~/.knoxcall/credentials.json`` file and picked
up automatically by every KnoxCall SDK (auto-detect slot 2).
"""

from __future__ import annotations
import argparse
import sys

from ..errors import KnoxCallError
from ._common import CLIError

__all__ = ["main", "build_parser", "CLIError"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="knoxcall",
        description="KnoxCall command-line interface — sign in once, every SDK on this machine picks it up.",
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="{login,logout,whoami,init,ai}")

    login = sub.add_parser(
        "login", help="sign in with your browser and store credentials locally"
    )
    login.add_argument("--tenant", help="tenant slug hint for the sign-in page")
    login.add_argument(
        "--base-url",
        help="management API base URL (default https://api.knoxcall.com, or KNOXCALL_BASE_URL)",
    )
    login.add_argument(
        "--sandbox", action="store_true", help="log in against the sandbox environment"
    )
    login.add_argument(
        "--profile", help="credentials profile name (default: KNOXCALL_PROFILE or 'default')"
    )
    login.add_argument(
        "--device",
        action="store_true",
        help="use the device-code flow (headless/SSH machines)",
    )
    login.add_argument(
        "--no-browser",
        action="store_true",
        help="never open a browser (implies the device-code flow)",
    )
    login.set_defaults(func=_run_login)

    logout = sub.add_parser("logout", help="revoke and remove stored credentials")
    logout.add_argument(
        "--profile", help="credentials profile name (default: KNOXCALL_PROFILE or 'default')"
    )
    logout.set_defaults(func=_run_logout)

    whoami = sub.add_parser("whoami", help="show the signed-in tenant")
    whoami.add_argument(
        "--profile", help="credentials profile name (default: KNOXCALL_PROFILE or 'default')"
    )
    whoami.set_defaults(func=_run_whoami)

    init = sub.add_parser(
        "init",
        help="get started wrapping a provider SDK (escrow a key)",
        description=(
            "Get started wrapping a provider SDK through KnoxCall. Works against the "
            "tenant you are already signed in to — it does NOT provision a tenant. With "
            "no --provider it prints a quickstart; with --provider it escrows a key "
            "(read from the KNOXCALL_WRAP_SECRET env var, never a flag) and prints the "
            "gateway base_url."
        ),
    )
    init.add_argument(
        "--profile", help="credentials profile name (default: KNOXCALL_PROFILE or 'default')"
    )
    init.add_argument(
        "--base-url", help="management API base URL (default https://api.knoxcall.com)"
    )
    init.add_argument(
        "--sandbox", action="store_true", help="operate against the sandbox environment"
    )
    init.add_argument(
        "--provider",
        help="provider to escrow a key for (e.g. stripe); enables escrow mode",
    )
    init.add_argument(
        "--secret-name", help="name for the escrowed credential (required with --provider)"
    )
    init.add_argument(
        "--host", help="upstream host to pin the credential to (required with --provider)"
    )
    init.set_defaults(func=_run_init)

    ai = sub.add_parser(
        "ai",
        help="AI gateway operations",
        description=(
            "AI-gateway operations.\n\n"
            "From a tenant with nothing in it to a real streamed call, in two commands:\n\n"
            "    export ANTHROPIC_API_KEY=sk-ant-...\n"
            "    knoxcall ai create-agent --name copilot --slug copilot \\\n"
            "        --provider anthropic --secret-from-env ANTHROPIC_API_KEY\n"
            "    knoxcall ai mint --agent <id>"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ai_sub = ai.add_subparsers(
        dest="ai_command",
        required=True,
        metavar="{exchange,gateways,agents,create-agent,mint,usage}",
    )

    exchange = ai_sub.add_parser(
        "exchange",
        help="exchange a CI OIDC token for an AI-gateway capability token",
        description=(
            "Exchange a CI workload's OIDC id_token for a short-lived AI-gateway "
            "capability token (RFC 8693). Needs no KnoxCall credential and no "
            "`knoxcall login`: the subject token IS the credential.\n\n"
            "The subject token is read from the KNOXCALL_SUBJECT_TOKEN environment "
            "variable, never a flag — an argv value lands in shell history, ps output "
            "and the CI log.\n\n"
            "Only the token is printed to stdout, so it can be captured:\n"
            '    export KC_TOKEN="$(knoxcall ai exchange --tenant acme)"'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    exchange.add_argument(
        "--tenant",
        help="tenant slug; the data-plane host is https://{tenant}.knoxcall.com",
    )
    exchange.add_argument(
        "--sandbox",
        action="store_true",
        help="use the Test data space (sandbox-{tenant}.knoxcall.com)",
    )
    exchange.add_argument(
        "--base-url", help="full data-plane origin; overrides --tenant"
    )
    exchange.add_argument(
        "--resource",
        help="RFC 8707 resource indicator (an MCP server's `resource`); narrows the token to that one MCP server",
    )
    exchange.add_argument("--audience", help="defaults to knoxcall:gateway")
    exchange.set_defaults(func=_run_ai_exchange)

    # AIGW-162 — the CONTROL-plane sub-commands. Unlike `exchange` (whose
    # credential is the CI workload's own OIDC token) these act as the
    # signed-in tenant, through the profile `login` wrote.
    #
    # Each gets its OWN flag table rather than sharing one across the group: a
    # single flat table would accept `ai exchange --period 30d` and silently
    # ignore it, which is the opposite of what every other command here does
    # with an unknown flag (usage error, exit 2).
    #
    # Ids are FLAGS, never positionals. Four of the five SDK CLIs hand-roll
    # their parser and reject positionals outright; only argparse would hand
    # them to us free, and a surface that differs by language is not a surface.

    gateways = ai_sub.add_parser(
        "gateways",
        help="list AI gateways",
        description="List this tenant's AI gateways as `id  slug  name`.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_ai_common_arguments(gateways)
    gateways.set_defaults(func=_run_ai_gateways)

    # The usage LINE is written out for the three sub-commands that have a
    # required flag. argparse would render `[--gateway GATEWAY]` — square
    # brackets, i.e. "optional" — because the requirement is enforced in
    # ai_control.py as a CLIError (exit 1, with the reason) rather than by
    # argparse (exit 2, no reason). Generating a usage line that says the flag
    # is optional when it is not is the same lie in every language, and the
    # other four CLIs render these as required. `_add_ai_common_arguments`
    # keeps the tail identical; the drift guard is
    # tests/test_cli_ai.py::test_a_hand_written_usage_line_names_every_flag.
    agents = ai_sub.add_parser(
        "agents",
        help="list a gateway's agents",
        usage=(
            "knoxcall ai agents [-h] --gateway GATEWAY [--profile PROFILE]\n"
            "                          [--base-url BASE_URL] [--sandbox]"
        ),
        description=(
            "List a gateway's agents as `id  slug  agent_url`. The third column is\n"
            "the base_url to point an AI SDK at, so this is enough to wire up an\n"
            "existing agent without a second call."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    agents.add_argument("--gateway", help="gateway id")
    _add_ai_common_arguments(agents)
    agents.set_defaults(func=_run_ai_agents)

    create_agent = ai_sub.add_parser(
        "create-agent",
        help="create an agent with its upstream credential",
        usage=(
            "knoxcall ai create-agent [-h] --slug SLUG --provider PROVIDER\n"
            "                                (--secret SECRET | --secret-from-env VAR)\n"
            "                                [--name NAME] [--gateway GATEWAY] [--model MODEL]\n"
            "                                [--upstream URL] [--profile PROFILE]\n"
            "                                [--base-url BASE_URL] [--sandbox]"
        ),
        description=(
            "Create an agent wired to a provider credential, and print the command\n"
            "that follows. Works on a tenant with nothing in it: with no --gateway it\n"
            "uses your only gateway, or creates one when you have none. With several\n"
            "it refuses and lists them rather than picking one for you.\n\n"
            "The provider key is read from the environment named by --secret-from-env,\n"
            "never from a flag — an argv value lands in shell history, ps output and\n"
            "the CI log. There is deliberately no --secret-value.\n\n"
            "--provider and a credential are both required: the API accepts an agent\n"
            "with neither and stores one whose first data-plane call 502s.\n\n"
            "Only the agent id goes to stdout, so it can be captured:\n"
            '    AGENT="$(knoxcall ai create-agent --slug copilot --provider anthropic \\\n'
            '        --secret-from-env ANTHROPIC_API_KEY)"'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    create_agent.add_argument("--slug", help="url slug; the agent is served at /v1/ai/{slug}")
    create_agent.add_argument(
        "--provider",
        help=(
            "provider id (anthropic, openai, groq, bedrock, …). The catalog is "
            "server-side; an unknown value is a 400 that names the valid set."
        ),
    )
    create_agent.add_argument(
        "--secret", help="id of an existing KnoxCall secret holding the key"
    )
    create_agent.add_argument(
        "--secret-from-env",
        metavar="VAR",
        help=(
            "environment variable holding the key; escrows it as a new secret, "
            "reusing one of the same name if present"
        ),
    )
    create_agent.add_argument("--name", help="display name (defaults to --slug)")
    create_agent.add_argument("--gateway", help="gateway id or slug to create under")
    create_agent.add_argument(
        "--model", help="default model (required for openai-compatible)"
    )
    create_agent.add_argument(
        "--upstream",
        metavar="URL",
        help=(
            "upstream base URL; required for azure-openai, ollama, bedrock and "
            "openai-compatible"
        ),
    )
    _add_ai_common_arguments(create_agent)
    create_agent.set_defaults(func=_run_ai_create_agent)

    mint = ai_sub.add_parser(
        "mint",
        help="mint a capability token (shown once)",
        usage=(
            "knoxcall ai mint [-h] --agent AGENT [--kind KIND] [--name NAME]\n"
            "                        [--profile PROFILE] [--base-url BASE_URL] [--sandbox]"
        ),
        description=(
            "Mint a capability token for an agent. The plaintext is returned ONCE and\n"
            "is the only thing on stdout, so it can be captured:\n"
            '    TOKEN="$(knoxcall ai mint --agent ag_123)"'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    mint.add_argument("--agent", help="agent id")
    mint.add_argument("--kind", help="agent | read | tool | oneshot (default agent)")
    mint.add_argument("--name", help="label for the token")
    _add_ai_common_arguments(mint)
    mint.set_defaults(func=_run_ai_mint)

    usage = ai_sub.add_parser(
        "usage",
        help="cost + token usage by model",
        description="Cost and token usage by model.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    usage.add_argument("--period", help="7d | 30d | 90d (default 30d)")
    usage.add_argument("--agent", help="scope to one agent")
    _add_ai_common_arguments(usage)
    usage.set_defaults(func=_run_ai_usage)

    return parser


def _add_ai_common_arguments(parser: argparse.ArgumentParser) -> None:
    """The three flags every control-plane sub-command takes: they select WHICH
    tenant and WHICH stored login is acting."""
    parser.add_argument(
        "--profile", help="credentials profile name (default: KNOXCALL_PROFILE or 'default')"
    )
    parser.add_argument(
        "--base-url", help="management API base URL (default https://api.knoxcall.com)"
    )
    parser.add_argument(
        "--sandbox", action="store_true", help="operate against the Test data space"
    )


def _run_login(args: argparse.Namespace) -> int:
    from .login import run_login

    return run_login(args)


def _run_logout(args: argparse.Namespace) -> int:
    from .logout import run_logout

    return run_logout(args)


def _run_whoami(args: argparse.Namespace) -> int:
    from .whoami import run_whoami

    return run_whoami(args)


def _run_init(args: argparse.Namespace) -> int:
    from .init import run_init

    return run_init(args)


def _run_ai_exchange(args: argparse.Namespace) -> int:
    from .ai import run_ai_exchange

    return run_ai_exchange(args)


def _run_ai_gateways(args: argparse.Namespace) -> int:
    from .ai_control import run_ai_gateways

    return run_ai_gateways(args)


def _run_ai_agents(args: argparse.Namespace) -> int:
    from .ai_control import run_ai_agents

    return run_ai_agents(args)


def _run_ai_create_agent(args: argparse.Namespace) -> int:
    from .ai_control import run_ai_create_agent

    return run_ai_create_agent(args)


def _run_ai_mint(args: argparse.Namespace) -> int:
    from .ai_control import run_ai_mint

    return run_ai_mint(args)


def _run_ai_usage(args: argparse.Namespace) -> int:
    from .ai_control import run_ai_usage

    return run_ai_usage(args)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except (CLIError, KnoxCallError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("aborted", file=sys.stderr)
        return 1
