"""Account resource — mirrors account.ts."""

from __future__ import annotations
from typing import TYPE_CHECKING

from .._envelope import unwrap
from ..types import Account, AccountUsage

if TYPE_CHECKING:
    from ..core import APIClient


class AccountResource:
    def __init__(self, client: "APIClient") -> None:
        self._client = client

    async def get(self) -> Account:
        """Get tenant account info including subscription, trial, and billing details."""
        return unwrap(await self._client.request(method="GET", path="/v1/account"))

    async def get_usage(self) -> AccountUsage:
        """Get current usage stats — API calls, resource counts, plan limits."""
        return unwrap(await self._client.request(method="GET", path="/v1/account/usage"))
