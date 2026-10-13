"""login() / ensure_login() — opt-in interactive auth (parity with node).

The underlying browser/device flow is covered by the CLI tests; here we cover
the wrapper: stored-profile reuse (no prompt) and the interactive guard.
"""

from __future__ import annotations
import datetime as _dt

import pytest

from knoxcall import NotAuthenticatedError, BootstrapError, ensure_login_sync, login_sync
from knoxcall.auth.credentials_file import write_profile


def _seed_profile(path: str) -> None:
    expires = (_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    write_profile(path, "default", {
        "tenant": "acme",
        "base_url": "https://api.example.test",
        "client_id": "kc_cli_real",
        "refresh_token": "rt_1",
        "access_token": "kc_live_stored",
        "access_token_expires_at": expires,
        "scope": "",
    })


def test_not_authenticated_error_is_bootstrap_subclass():
    assert issubclass(NotAuthenticatedError, BootstrapError)


def test_ensure_login_sync_uses_stored_profile_without_prompting(tmp_path, monkeypatch):
    creds = str(tmp_path / "credentials.json")
    monkeypatch.setenv("KNOXCALL_CREDENTIALS_FILE", creds)
    monkeypatch.delenv("KNOXCALL_NO_INTERACTIVE", raising=False)
    _seed_profile(creds)

    client = ensure_login_sync()
    try:
        # The sync facade wraps the async client; the stored profile seeded it.
        assert client._async.tenant == "acme"
        assert client._async.base_url == "https://api.example.test"
    finally:
        client.close()


def test_login_sync_refuses_when_no_interactive_env_set(tmp_path, monkeypatch):
    monkeypatch.setenv("KNOXCALL_CREDENTIALS_FILE", str(tmp_path / "credentials.json"))
    monkeypatch.setenv("KNOXCALL_NO_INTERACTIVE", "1")
    with pytest.raises(NotAuthenticatedError):
        login_sync()


def test_ensure_login_sync_refuses_in_ci_without_a_profile(tmp_path, monkeypatch):
    monkeypatch.setenv("KNOXCALL_CREDENTIALS_FILE", str(tmp_path / "credentials.json"))
    monkeypatch.delenv("KNOXCALL_NO_INTERACTIVE", raising=False)
    monkeypatch.setenv("CI", "true")
    with pytest.raises(NotAuthenticatedError):
        ensure_login_sync()
