"""`knoxcall whoami` — show the signed-in tenant via the SDK client."""

from __future__ import annotations
import argparse
from typing import Any

from ..auth.credentials_file import read_profile, resolve_credentials_path, resolve_profile
from ._common import CLIError


def run_whoami(args: argparse.Namespace) -> int:
    path = resolve_credentials_path()
    profile = resolve_profile(args.profile)
    if read_profile(path, profile) is None:
        raise CLIError(f"not logged in (profile '{profile}') — run `knoxcall login`")

    from ..auth.bootstrap import StoredCredentials
    from ..client import KnoxCall

    with KnoxCall(bootstrap=StoredCredentials(path=path, profile=profile)) as client:
        account: dict[str, Any] = client.account.get() or {}

    slug = account.get("slug") or ""
    name = account.get("name") or account.get("company_name") or ""
    plan = account.get("plan") or account.get("subscription_plan") or ""
    print(f"Tenant: {name or slug or '(unknown)'}")
    if slug:
        print(f"Slug:   {slug}")
    if plan:
        print(f"Plan:   {plan}")
    print(f"Profile: {profile} ({path})")
    return 0
