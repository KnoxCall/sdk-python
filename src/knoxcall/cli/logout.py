"""`knoxcall logout` — best-effort revoke, then remove the stored profile."""

from __future__ import annotations
import argparse

import httpx

from ..auth.credentials_file import (
    CredentialsFileLock,
    read_profile,
    remove_profile,
    resolve_credentials_path,
    resolve_profile,
)
from ._common import CLI_CLIENT_ID, CLIError, post_form


def run_logout(args: argparse.Namespace, *, http: httpx.Client | None = None) -> int:
    path = resolve_credentials_path()
    profile = resolve_profile(args.profile)
    record = read_profile(path, profile)
    if record is None:
        print(f"No stored credentials for profile '{profile}' — nothing to do.")
        return 0

    refresh_token = record.get("refresh_token")
    base_url = str(record.get("base_url") or "").rstrip("/")
    if refresh_token and base_url:
        try:
            post_form(
                f"{base_url}/oauth/revoke",
                {
                    "token": refresh_token,
                    "token_type_hint": "refresh_token",
                    "client_id": record.get("client_id") or CLI_CLIENT_ID,
                },
                http,
            )
        except CLIError:
            pass  # best-effort: removal proceeds even when revocation is unreachable

    with CredentialsFileLock(path):
        remove_profile(path, profile)
    print(f"Logged out — removed profile '{profile}' from {path}.")
    return 0
