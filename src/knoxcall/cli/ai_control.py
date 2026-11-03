"""``knoxcall ai`` — the AI-gateway CONTROL plane from a terminal (AIGW-162).

``ai exchange`` (``ai.py``) is the data-plane door: it needs no login, because
the CI workload's OIDC token is the credential. Everything here is the opposite
— it acts as the signed-in tenant, through the same
``~/.knoxcall/credentials.json`` profile ``login`` writes and ``whoami`` reads.

WHY THIS EXISTS. Until now the five SDK CLIs shipped exactly one ``ai``
subcommand, ``exchange``. A capable ``knoxcall ai gateways|agents|mint|usage``
lived in a standalone ``cli/`` package that was never published, never tested,
never in CI and not in the workspaces — and it could not create a secret, a
gateway or an agent, so it could not get you to a first call either. So there
was no CLI golden path at all: the only way from "I have an API key" to "my app
is calling an LLM through KnoxCall" was the browser or hand-written HTTP.

The golden path these commands exist to make true, from a tenant with nothing
in it::

    export ANTHROPIC_API_KEY=sk-ant-...
    knoxcall ai create-agent --name copilot --slug copilot \\
        --provider anthropic --secret-from-env ANTHROPIC_API_KEY
    knoxcall ai mint --agent <id>
    curl "$AGENT_URL/v1/messages" -H "Authorization: Bearer $TOKEN" ...

Two commands, then a real streamed call. ``create-agent`` prints the agent id,
the ``agent_url`` and the exact next command, so the path is discoverable
without re-reading the docs.

THREE RULES, each one a bug this shape invites:

1. **A PROVIDER KEY IS NEVER AN ARGV VALUE.** ``--secret-from-env NAME`` names
   the environment variable to read; there is deliberately no
   ``--secret-value``. An argv value lands in shell history, in ``ps`` output
   and in the CI log line that echoes the command. Same rule ``ai exchange``
   applies to ``KNOXCALL_SUBJECT_TOKEN`` and ``init`` to
   ``KNOXCALL_WRAP_SECRET``.

2. **NO POSITIONAL ARGUMENTS.** Four of the five SDK CLIs hand-roll their
   parser and reject positionals outright; only python gets them free from
   argparse. Ids are flags (``--gateway``, ``--agent``) so the surface is the
   same in all five rather than "the same except in Go".

3. **AN AGENT WITHOUT AN UPSTREAM IS REFUSED HERE**, not at its first call. The
   API accepts ``create_agent`` with no ``provider``/``upstream_secret_id`` and
   stores an agent whose first data-plane request 502s (AIGW-161). A command
   whose entire purpose is "get me to a working call" must not be able to
   produce that, so ``--provider`` and one of ``--secret`` /
   ``--secret-from-env`` are required together.

A missing required flag here is a CLIError (exit 1, ``error: <msg>``), not an
argparse usage error (exit 2): the refusals above carry the REASON they exist,
and the same message and exit code have to come out of all five CLIs, four of
which have no argparse to defer to.
"""

from __future__ import annotations
import argparse
import os
import sys
from typing import Any, Mapping

import httpx

from ..auth.credentials_file import read_profile, resolve_credentials_path, resolve_profile
from ._common import CLIError


def _open_client(
    args: argparse.Namespace, http: httpx.AsyncClient | None = None
) -> Any:
    """A client acting as the signed-in tenant, or a message telling them to log in.

    Same acquisition path as ``whoami``/``init``: the stored profile, never a
    provisioning call. Returns the sync client as a context manager, so every
    caller reads ``with _open_client(args, http) as client:``.
    """
    path = resolve_credentials_path()
    profile = resolve_profile(args.profile)
    if read_profile(path, profile) is None:
        raise CLIError(f"not logged in (profile '{profile}') — run `knoxcall login`")

    from ..auth.bootstrap import StoredCredentials
    from ..client import KnoxCall

    kwargs: dict[str, Any] = {"bootstrap": StoredCredentials(path=path, profile=profile)}
    if http is not None:
        kwargs["http"] = http
    if getattr(args, "base_url", None):
        kwargs["base_url"] = args.base_url
    if getattr(args, "sandbox", False):
        kwargs["sandbox"] = True
    return KnoxCall(**kwargs)


def _required(value: str | None, flag: str) -> str:
    if not value:
        raise CLIError(f"{flag} is required")
    return value


def _known_gateways(rows: list[dict[str, Any]]) -> str:
    return ", ".join(f"{g.get('slug')} ({g.get('id')})" for g in rows)


# ── knoxcall ai gateways ─────────────────────────────────────────────────────


def run_ai_gateways(args: argparse.Namespace, *, http: httpx.AsyncClient | None = None) -> int:
    with _open_client(args, http) as client:
        page = client.ai_gateway.list_gateways(per_page=100)
    rows = page.get("data") or []
    if not rows:
        print(
            "No AI gateways. `knoxcall ai create-agent` will create one for you.",
            file=sys.stderr,
        )
        return 0
    for g in rows:
        print(f"{g.get('id')}  {g.get('slug')}  {g.get('name')}")
    return 0


# ── knoxcall ai agents --gateway ID ──────────────────────────────────────────


def run_ai_agents(args: argparse.Namespace, *, http: httpx.AsyncClient | None = None) -> int:
    # Checked BEFORE the credential, so `knoxcall ai agents` on a machine that
    # is not logged in still tells you about the flag you actually forgot.
    gateway_id = _required(args.gateway, "--gateway")
    with _open_client(args, http) as client:
        page = client.ai_gateway.list_agents(gateway_id, per_page=100)
    rows = page.get("data") or []
    if not rows:
        print("No agents in that gateway.", file=sys.stderr)
        return 0
    # agent_url is on every projection since AIGW-161, so a list is enough to
    # point an SDK at an existing agent — no follow-up GET.
    for a in rows:
        print(f"{a.get('id')}  {a.get('slug')}  {a.get('agent_url') or ''}")
    return 0


# ── knoxcall ai create-agent ─────────────────────────────────────────────────


def _resolve_gateway(client: Any, wanted: str | None) -> str:
    """Resolve the gateway to create under.

    ``--gateway`` takes an id OR a slug. With no ``--gateway``: use the tenant's
    only gateway, or create one when they have none — that is what makes the
    command work on a fresh tenant, which is the whole point. With SEVERAL and
    no flag it refuses and lists them rather than picking: "whichever sorts
    first" is how the quickstart wizard silently landed a second agent in the
    wrong gateway.
    """
    page = client.ai_gateway.list_gateways(per_page=100)
    rows = page.get("data") or []
    if wanted:
        for g in rows:
            if g.get("id") == wanted or g.get("slug") == wanted:
                return str(g["id"])
        raise CLIError(
            f"no gateway '{wanted}' — this tenant has: {_known_gateways(rows) or 'none'}"
        )
    if len(rows) == 1:
        return str(rows[0]["id"])
    if not rows:
        created = client.ai_gateway.create_gateway(name="Default", slug="default")
        print(f"created gateway {created.get('slug')} ({created.get('id')})", file=sys.stderr)
        return str(created["id"])
    raise CLIError(
        f"--gateway is required: this tenant has {len(rows)} gateways "
        f"({_known_gateways(rows)}). Picking one for you would put the agent "
        "somewhere you did not choose."
    )


def _resolve_secret(
    client: Any,
    args: argparse.Namespace,
    slug: str,
    environ: Mapping[str, str | None],
) -> str:
    """Resolve the upstream secret, escrowing one from the environment if asked.

    The key is read from ``environ[NAME]``, never from a flag — see rule 1.
    Re-running with the same ``--secret-from-env`` reuses the existing secret by
    name rather than creating a second copy of the same credential.
    """
    if args.secret:
        return str(args.secret)
    env_name = _required(args.secret_from_env, "--secret or --secret-from-env")
    value = (environ.get(env_name) or "").strip()
    if not value:
        raise CLIError(
            f"{env_name} is not set — put your provider key there. There is deliberately no "
            "--secret-value flag: an argv value lands in shell history, ps output and the CI log."
        )
    name = f"ai-gateway-{slug or 'agent'}-key"
    existing = client.secrets.list(per_page=100)
    for s in existing.get("data") or []:
        if s.get("name") == name:
            print(f"reusing secret '{name}' ({s.get('id')})", file=sys.stderr)
            return str(s["id"])
    # ``secret_type`` is optional in the node SDK and required here; a provider
    # key is an api_key, and guessing it wrong is a 400 rather than a wrong
    # secret, so it is pinned rather than threaded through as a flag.
    created = client.secrets.create(name=name, secret_type="api_key", value=value)
    print(
        f"escrowed secret '{name}' ({created.get('id')}) — the key is now in KnoxCall custody",
        file=sys.stderr,
    )
    return str(created["id"])


def run_ai_create_agent(
    args: argparse.Namespace,
    *,
    http: httpx.AsyncClient | None = None,
    env: Mapping[str, str | None] | None = None,
) -> int:
    environ = env if env is not None else os.environ
    slug = _required(args.slug, "--slug")
    # Rule 3: refuse here rather than let the API store an agent with no
    # upstream whose first data-plane call 502s.
    provider = _required(args.provider, "--provider")
    if not args.secret and not args.secret_from_env:
        raise CLIError(
            "one of --secret or --secret-from-env is required: an agent created without an "
            "upstream credential is accepted by the API and 502s on its first call."
        )

    with _open_client(args, http) as client:
        gateway_id = _resolve_gateway(client, args.gateway)
        secret_id = _resolve_secret(client, args, slug, environ)

        extra: dict[str, Any] = {}
        if args.upstream:
            extra["upstream"] = args.upstream
        if args.model:
            extra["default_model"] = args.model

        agent = client.ai_gateway.create_agent(
            gateway_id,
            name=args.name or slug,
            slug=slug,
            provider=provider,
            upstream_secret_id=secret_id,
            **extra,
        )

    # stdout: the agent id, so `$(...)` captures exactly that. Everything a
    # human needs next goes to stderr, including the command that follows.
    print(agent["id"])
    print(f"\n  agent:     {agent.get('slug')} ({agent.get('id')})", file=sys.stderr)
    print(f"  gateway:   {gateway_id}", file=sys.stderr)
    print(f"  provider:  {provider}", file=sys.stderr)
    if agent.get("agent_url"):
        print(f"  base_url:  {agent['agent_url']}", file=sys.stderr)
    print(f"\n  Next:  knoxcall ai mint --agent {agent['id']}", file=sys.stderr)
    return 0


# ── knoxcall ai mint --agent ID ──────────────────────────────────────────────


def run_ai_mint(args: argparse.Namespace, *, http: httpx.AsyncClient | None = None) -> int:
    agent_id = _required(args.agent, "--agent")
    with _open_client(args, http) as client:
        extra: dict[str, Any] = {}
        if args.kind:
            extra["kind"] = args.kind
        if args.name:
            extra["name"] = args.name
        minted = client.ai_gateway.mint_token(agent_id, **extra)

    token = minted.get("token")
    if not isinstance(token, str) or not token:
        raise CLIError("the mint returned no token")

    # The plaintext is returned ONCE. stdout carries only the token so
    # `> token.txt` captures the token and nothing else; the metadata and the
    # warning go to stderr.
    print(token)
    print(f"\n  id:       {minted.get('id')}", file=sys.stderr)
    print(f"  kind:     {minted.get('kind')}", file=sys.stderr)
    print(f"  prefix:   {minted.get('prefix')}", file=sys.stderr)
    print(f"  dpop:     {minted.get('dpop_required')}", file=sys.stderr)
    print(f"  expires:  {minted.get('expires_at') or 'never'}", file=sys.stderr)
    print("\n  Save this token now — it will not be shown again.", file=sys.stderr)
    return 0


# ── knoxcall ai usage ────────────────────────────────────────────────────────


def _usd(value: Any) -> str:
    try:
        return f"{float(value or 0):.4f}"
    except (TypeError, ValueError):
        return "0.0000"


def run_ai_usage(args: argparse.Namespace, *, http: httpx.AsyncClient | None = None) -> int:
    with _open_client(args, http) as client:
        extra: dict[str, Any] = {}
        if args.agent:
            extra["agent_id"] = args.agent
        usage = client.ai_gateway.usage(period=args.period or "30d", **extra)

    totals: dict[str, Any] = usage.get("totals") or {}
    scope = f" (agent {args.agent})" if args.agent else ""
    print(f"Usage — last {usage.get('period_days')} days{scope}")
    print(f"  requests:      {totals.get('requests')}")
    print(f"  input tokens:  {totals.get('input_tokens')}")
    print(f"  output tokens: {totals.get('output_tokens')}")
    print(f"  cost (USD):    {_usd(totals.get('cost_usd'))}")
    print(f"  unpriced:      {totals.get('unpriced_requests')}")

    by_model = usage.get("by_model") or []
    if not by_model:
        print("\nNo usage in this period.")
        return 0
    print("\nBy model:")
    for m in by_model:
        print(
            f"  {m.get('provider')}/{m.get('model')}  {m.get('requests')} req  "
            f"in {m.get('input_tokens')}  out {m.get('output_tokens')}  "
            f"${_usd(m.get('cost_usd'))}"
        )
    return 0
