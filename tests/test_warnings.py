"""Security misconfiguration warnings: plaintext http:// to a non-loopback host
(item 1) and a world-readable credentials file (item 2). Both warn-once via the
stdlib warnings module and never block."""

from __future__ import annotations
import os
import sys

import pytest

from knoxcall import KnoxCallAsync
from knoxcall._warn import KnoxCallSecurityWarning, is_insecure_remote_url
from knoxcall.auth.bootstrap import AccessToken
from knoxcall.auth.credentials_file import read_profile, write_profile


def test_is_insecure_remote_url():
    assert is_insecure_remote_url("http://api.example.com") is True
    assert is_insecure_remote_url("http://10.0.0.5:3000") is True
    assert is_insecure_remote_url("https://api.example.com") is False
    assert is_insecure_remote_url("http://localhost:3000") is False
    assert is_insecure_remote_url("http://127.0.0.1:3000") is False
    assert is_insecure_remote_url("http://foo.localhost") is False
    assert is_insecure_remote_url(None) is False


def test_http_non_loopback_base_url_warns():
    with pytest.warns(KnoxCallSecurityWarning, match="unencrypted"):
        KnoxCallAsync(tenant="acme", base_url="http://api.example.com",
                      proxy_base_url="https://acme.example.test", access_token="kc_live_x")


def test_http_localhost_does_not_warn(recwarn):
    KnoxCallAsync(tenant="acme", base_url="http://localhost:3000",
                  proxy_base_url="http://localhost:3000", access_token="kc_live_x")
    assert not any(isinstance(w.message, KnoxCallSecurityWarning) for w in recwarn)


@pytest.mark.skipif(os.name == "nt", reason="mode bits are advisory on Windows")
def test_loose_credentials_file_permissions_warn(tmp_path):
    path = str(tmp_path / "credentials.json")
    write_profile(path, "default", {
        "tenant": "acme", "client_id": "kc_cli", "refresh_token": "rt",
        "access_token": "kc_a", "access_token_expires_at": "2099-01-01T00:00:00Z", "scope": "",
    })
    os.chmod(path, 0o644)  # group/other readable
    with pytest.warns(KnoxCallSecurityWarning, match="chmod 600"):
        read_profile(path, "default")


@pytest.mark.skipif(os.name == "nt", reason="mode bits are advisory on Windows")
def test_tight_credentials_file_permissions_do_not_warn(tmp_path, recwarn):
    path = str(tmp_path / "credentials.json")
    write_profile(path, "default", {
        "tenant": "acme", "client_id": "kc_cli", "refresh_token": "rt",
        "access_token": "kc_a", "access_token_expires_at": "2099-01-01T00:00:00Z", "scope": "",
    })
    os.chmod(path, 0o600)
    read_profile(path, "default")
    assert not any(isinstance(w.message, KnoxCallSecurityWarning) for w in recwarn)
