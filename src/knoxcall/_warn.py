"""One-time warnings for security-relevant misconfigurations (plaintext
transport, world-readable credentials file). Uses the stdlib ``warnings``
module (deduped once per message by the default filter) with a dedicated
category so callers can silence or escalate them."""

from __future__ import annotations
import warnings
from urllib.parse import urlparse


class KnoxCallSecurityWarning(UserWarning):
    """A KnoxCall security misconfiguration warning (never blocks)."""


def warn_security(message: str) -> None:
    warnings.warn(message, KnoxCallSecurityWarning, stacklevel=3)


def is_insecure_remote_url(url: str | None) -> bool:
    """True for a plaintext http:// URL whose host is NOT loopback."""
    if not url or not url.lower().startswith("http://"):
        return False
    host = (urlparse(url).hostname or "").lower()
    loopback = (
        host == "localhost"
        or host.endswith(".localhost")
        or host == "0.0.0.0"
        or host == "::1"
        or host.startswith("127.")
    )
    return not loopback
