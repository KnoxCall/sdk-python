"""``knoxcall ai exchange`` — RFC 8693 workload federation from a terminal.

The one KnoxCall command that needs no ``knoxcall login`` and no KnoxCall
credential at all: the CI workload's own OIDC id_token IS the credential, and
the server verifies it against the issuer's published JWKS.

    export KC_TOKEN="$(knoxcall ai exchange --tenant acme)"

Two rules this command exists to enforce, because both are easy to get wrong in
a CI script and neither fails in a way that names itself:

1. **The subject token is read from the environment, never a flag.** An argv
   value lands in shell history, in ``ps`` output, and in the CI log line that
   echoes the command. ``KNOXCALL_SUBJECT_TOKEN`` is the same rule
   ``knoxcall init`` applies to ``KNOXCALL_WRAP_SECRET``.

2. **The host is the tenant data plane, and there is no default.**
   ``POST /v1/oauth/token`` is dispatched to the proxy router only on a tenant
   host; on ``api.knoxcall.com`` it answers **401**, which reads as "my CI token
   was rejected" and sends people hunting through their issuer's JWKS. So
   ``--tenant`` (or ``--base-url``) is required, and the error says why.

Only the token goes to stdout, so ``$(...)`` captures exactly the token and
nothing else. Everything else goes to stderr.
"""

from __future__ import annotations
import argparse
import os
import sys

from ..resources.token_exchange import exchange_token_sync
from ._common import CLIError

#: The subject token is read from here, never from argv. See rule 1 above.
SUBJECT_TOKEN_ENV = "KNOXCALL_SUBJECT_TOKEN"


def run_ai_exchange(args: argparse.Namespace) -> int:
    subject_token = (os.environ.get(SUBJECT_TOKEN_ENV) or "").strip()
    if not subject_token:
        raise CLIError(
            f"{SUBJECT_TOKEN_ENV} is not set — put your CI provider's OIDC id_token there "
            "(a flag would land in shell history, ps output and the CI log). GitHub Actions: "
            'request one with `id-token: write` and the ACTIONS_ID_TOKEN_REQUEST_URL endpoint, '
            'audience "knoxcall:gateway".'
        )

    if not args.tenant and not args.base_url:
        raise CLIError(
            "one of --tenant or --base-url is required: POST /v1/oauth/token is served only on "
            "the tenant data-plane host (https://{tenant}.knoxcall.com). Pointing it at "
            "api.knoxcall.com answers 401, which reads like a rejected subject_token but means "
            "the endpoint is not there."
        )

    kwargs: dict[str, object] = {
        "subject_token": subject_token,
        "tenant": args.tenant,
        "sandbox": bool(args.sandbox),
        "base_url": args.base_url,
    }
    if args.audience:
        kwargs["audience"] = args.audience
    # Only pass `resource` when the caller asked for one: the SDK distinguishes
    # "absent" from an empty string, and an empty one is a server refusal rather
    # than "no resource" — see resources/token_exchange.py.
    if args.resource is not None:
        kwargs["resource"] = args.resource

    result = exchange_token_sync(**kwargs)  # type: ignore[arg-type]

    token = result.get("access_token")
    if not isinstance(token, str) or not token:
        raise CLIError("the exchange returned no access_token")

    # stdout: the token, nothing else. stderr: everything a human wants.
    print(token)
    expires_in = result.get("expires_in")
    kind = "tool (MCP, resource-bound)" if args.resource else "agent"
    print(
        f"exchanged for a {kind} token"
        + (f", valid {expires_in}s" if isinstance(expires_in, int) else ""),
        file=sys.stderr,
    )
    return 0
