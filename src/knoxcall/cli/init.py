"""``knoxcall init`` — get started wrapping a provider SDK through KnoxCall.

SAFE BY DESIGN — this does NOT provision a tenant. It works against the tenant
you are already signed in to (``knoxcall login``). Two modes:

    knoxcall init
        Scaffold mode: confirm who you're signed in as and print a two-step
        wrap quickstart. No writes.

    knoxcall init --provider stripe --secret-name wrap-stripe --host api.stripe.com
        One-shot escrow: move a provider key into KnoxCall custody and print the
        gateway base_url to point your SDK at. The KEY is read from the
        KNOXCALL_WRAP_SECRET env var (never a flag) so it stays out of your shell
        history/argv. Escrow is idempotent-ish server-side (409 on a dup name).

Tenant provisioning + a fully headless one-shot flow (phantom kind ``'o'``) are a
deliberate follow-up — a CLI that mints tenants is a bigger, riskier surface.
"""

from __future__ import annotations
import argparse
import os
from typing import Any, Mapping

import httpx

from ..auth.credentials_file import read_profile, resolve_credentials_path, resolve_profile
from ._common import CLIError


def run_init(
    args: argparse.Namespace,
    *,
    http: httpx.AsyncClient | None = None,
    env: Mapping[str, str | None] | None = None,
) -> int:
    environ = env if env is not None else os.environ

    # Auth: reuse the stored login. Never provision.
    path = resolve_credentials_path()
    profile = resolve_profile(args.profile)
    if read_profile(path, profile) is None:
        raise CLIError(f"not logged in (profile '{profile}') — run `knoxcall login` first")

    from ..auth.bootstrap import StoredCredentials
    from ..client import KnoxCall

    kwargs: dict[str, Any] = {"bootstrap": StoredCredentials(path=path, profile=profile)}
    if http is not None:
        kwargs["http"] = http
    if args.base_url:
        kwargs["base_url"] = args.base_url
    if args.sandbox:
        kwargs["sandbox"] = True

    with KnoxCall(**kwargs) as client:
        account: dict[str, Any] = client.account.get() or {}
        tenant = (
            account.get("name")
            or account.get("company_name")
            or account.get("slug")
            or "(unknown)"
        )
        print(f"Signed in as {tenant}.")

        # One-shot escrow mode: --provider selects it; the rest are then required.
        if args.provider:
            name = (args.secret_name or "").strip()
            host = (args.host or "").strip().lower()
            value = environ.get("KNOXCALL_WRAP_SECRET")
            if not name:
                raise CLIError("--secret-name is required with --provider")
            if not host:
                raise CLIError("--host is required with --provider")
            if not value:
                raise CLIError(
                    "set the provider key in the KNOXCALL_WRAP_SECRET env var (not a flag)"
                )

            client.wrap.escrow(provider=args.provider, name=name, value=value, hosts=[host])
            res = client.wrap.gateway_url(secret=name, host=host)
            print("")
            print(
                f"Escrowed '{name}' for {host} — your provider key is now in KnoxCall custody."
            )
            print("Point a base-URL-only SDK at:")
            print(f"  {res['base_url']}")
            print("")
            print("…or transport-wrap an SDK that takes an http_client:")
            print("  knox = KnoxCall()")
            print('  sdk  = SomeSDK("placeholder", http_client=knox.wrap.client())')
            return 0

        # Scaffold mode: print the two-step quickstart, no writes.
        print("")
        print("Wrap a provider SDK through KnoxCall in two steps:")
        print("")
        print("1) Move the provider key into custody (key via KNOXCALL_WRAP_SECRET):")
        print("   KNOXCALL_WRAP_SECRET=sk_live_… \\")
        print("   knoxcall init --provider stripe --secret-name wrap-stripe --host api.stripe.com")
        print("")
        print("2) Route your SDK through KnoxCall (the key never re-enters your process):")
        print("   knox = KnoxCall()")
        print('   sdk  = SomeSDK("placeholder", http_client=knox.wrap.client())')
        print("   # …or point a base-URL-only SDK at the base_url that step 1 prints.")
        return 0
