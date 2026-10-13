"""Crypto / Transit resource — mirrors crypto-keys.ts (Vault-style encryption-as-a-service)."""

from __future__ import annotations
from typing import Any, Literal, Sequence, TYPE_CHECKING
from urllib.parse import quote

from .._envelope import unwrap
from ..types import (
    ClientTokenResult,
    DecryptDataResult,
    DecryptResult,
    EncryptDataResult,
    EncryptResult,
    InspectResult,
    JwtSignResult,
    JwtVerifyResult,
    KeyRotateResult,
    KeyUpdateResult,
    KeyVersionDestroyResult,
    PublicKeyResult,
    RewrapResult,
    SealingBundle,
    SignResult,
    TransitKey,
    TransitKeyListItem,
    VerifyResult,
    WebhookSignResult,
)

if TYPE_CHECKING:
    from ..core import APIClient


class CryptoResource:
    def __init__(self, client: "APIClient") -> None:
        self._client = client

    # ── Key management ────────────────────────────────────────────────────────

    async def list_keys(self) -> list[TransitKeyListItem]:
        """List crypto keys (bare array — not paginated)."""
        return unwrap(await self._client.request(method="GET", path="/v1/crypto/keys"))

    async def get_key(self, name: str) -> TransitKey:
        return unwrap(await self._client.request(
            method="GET", path=f"/v1/crypto/keys/{quote(name, safe='')}"
        ))

    async def create_key(
        self,
        *,
        name: str,
        mode: str,
        description: str | None = None,
        key_type: str | None = None,
        idempotency_key: str | None = None,
    ) -> TransitKey:
        """Create a crypto key.

        ``mode`` controls key usage:
        - ``"encrypt"`` — symmetric encryption (AES-256-GCM)
        - ``"sign"`` — asymmetric signing (RSA-2048, RSA-4096, Ed25519, P-256, P-384)
        - ``"hmac"`` — HMAC signing
        """
        body: dict[str, Any] = {"name": name, "mode": mode}
        if description is not None:
            body["description"] = description
        if key_type is not None:
            body["key_type"] = key_type
        return unwrap(await self._client.request(
            method="POST", path="/v1/crypto/keys", body=body, idempotency_key=idempotency_key
        ))

    async def update_key(
        self, name: str, *, deletion_allowed: bool, idempotency_key: str | None = None
    ) -> KeyUpdateResult:
        """Raise or lower the key's destroy safety latch (``deletion_allowed``).

        A version can only be destroyed while this is ``True``, and every new key
        ships with it ``False``. ``destroy_key_version`` on a key with the latch
        down is refused with a **409** (``deletion_not_allowed``) — a client
        error, never retry it unchanged. Raise the latch, destroy, lower it again.
        """
        return unwrap(await self._client.request(
            method="PATCH",
            path=f"/v1/crypto/keys/{quote(name, safe='')}",
            body={"deletion_allowed": deletion_allowed},
            idempotency_key=idempotency_key,
        ))

    async def rotate_key(self, name: str, *, idempotency_key: str | None = None) -> KeyRotateResult:
        """Generate a new key version. Older versions can still decrypt; new encryptions use the latest."""
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/crypto/keys/{quote(name, safe='')}/rotate",
            body={},
            idempotency_key=idempotency_key,
        ))

    async def destroy_key_version(
        self, name: str, version: int, *, idempotency_key: str | None = None
    ) -> KeyVersionDestroyResult:
        """Permanently destroy a specific key version. Cannot be undone."""
        return unwrap(await self._client.request(
            method="DELETE",
            path=f"/v1/crypto/keys/{quote(name, safe='')}/versions/{version}",
            idempotency_key=idempotency_key,
        ))

    async def get_public_key(self, name: str, *, version: int | None = None) -> PublicKeyResult:
        """Get the public key for an asymmetric key (PEM + JWK)."""
        query: dict[str, Any] = {}
        if version is not None:
            query["version"] = version
        return unwrap(await self._client.request(
            method="GET",
            path=f"/v1/crypto/keys/{quote(name, safe='')}/public-key",
            query=query or None,
        ))

    # ── Encryption / decryption ───────────────────────────────────────────────

    async def encrypt(
        self,
        name: str,
        *,
        plaintext: str | None = None,
        plaintext_b64: str | None = None,
        idempotency_key: str | None = None,
    ) -> EncryptResult:
        """Encrypt data. Returns ``ciphertext`` and ``key_version``.

        Pass either ``plaintext`` (UTF-8 string) or ``plaintext_b64`` (base64-encoded bytes).
        """
        body: dict[str, Any] = {}
        if plaintext is not None:
            body["plaintext"] = plaintext
        if plaintext_b64 is not None:
            body["plaintext_b64"] = plaintext_b64
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/crypto/keys/{quote(name, safe='')}/encrypt",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def decrypt(
        self,
        name: str,
        *,
        ciphertext: str,
        format: str | None = None,
        idempotency_key: str | None = None,
    ) -> DecryptResult:
        """Decrypt ciphertext. Returns ``plaintext_b64`` (or ``plaintext`` if ``format="utf8"``)."""
        body: dict[str, Any] = {"ciphertext": ciphertext}
        query = {"format": format} if format is not None else None
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/crypto/keys/{quote(name, safe='')}/decrypt",
            body=body,
            query=query,
            idempotency_key=idempotency_key,
        ))

    async def rewrap(
        self, name: str, *, ciphertext: str, idempotency_key: str | None = None
    ) -> RewrapResult:
        """Re-encrypt ciphertext under the current key version without exposing plaintext."""
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/crypto/keys/{quote(name, safe='')}/rewrap",
            body={"ciphertext": ciphertext},
            idempotency_key=idempotency_key,
        ))

    # ── Portable kc: encryption (structure-preserving, top-level /v1) ─────────
    # Distinct from the keyed transit encrypt() above: these take arbitrary
    # JSON and return the same shape with scalar leaves swapped for portable,
    # self-describing ``kc:`` ciphertext strings. Backed by ecdh-p256 keys.

    async def encrypt_data(
        self,
        data: Any,
        *,
        key: str | None = None,
        role: str | None = None,
        idempotency_key: str | None = None,
    ) -> EncryptDataResult:
        """Encrypt arbitrary JSON structure-preservingly (``POST /v1/encrypt``).

        Returns the same shape with scalar leaves replaced by ``kc:``
        ciphertext strings, plus the ``key`` name and ``key_version`` used.
        """
        body: dict[str, Any] = {"data": data}
        if key is not None:
            body["key"] = key
        if role is not None:
            body["role"] = role
        return unwrap(await self._client.request(
            method="POST", path="/v1/encrypt", body=body, idempotency_key=idempotency_key
        ))

    async def decrypt_data(
        self,
        data: Any,
        *,
        role: str | None = None,
        idempotency_key: str | None = None,
    ) -> DecryptDataResult:
        """Decrypt a structure containing ``kc:`` ciphertexts (``POST /v1/decrypt``)."""
        body: dict[str, Any] = {"data": data}
        if role is not None:
            body["role"] = role
        return unwrap(await self._client.request(
            method="POST", path="/v1/decrypt", body=body, idempotency_key=idempotency_key
        ))

    async def inspect(self, value: str) -> InspectResult:
        """Metadata about a single ``kc:`` ciphertext, no decryption (``POST /v1/inspect``)."""
        return unwrap(await self._client.request(
            method="POST", path="/v1/inspect", body={"value": value}
        ))

    async def mint_client_token(
        self,
        *,
        action: Literal["decrypt", "detokenize", "tokenize"],
        data: str | None = None,
        vault: str | None = None,
        origins: Sequence[str] | None = None,
        role: str | None = None,
        ttl_seconds: int | None = None,
        idempotency_key: str | None = None,
    ) -> ClientTokenResult:
        """Mint a single-use client-side capability token
        (``POST /v1/client-tokens``).

        Hand the returned ``token`` to a browser/agent so it can perform exactly
        one bound operation without an API key. Three actions, two bindings:

        ``decrypt`` / ``detokenize``
            Payload-pinned to the exact ``data`` (a ``kc:`` ciphertext or a
            vault token). The browser reveals it once via
            ``POST /v1/client/{decrypt,detokenize}``.

        ``tokenize``
            Bound to a ``vault`` (name or id) and ``origins`` — 1-10 exact
            ``https://host[:port]`` page origins, no wildcards in any form. The
            page puts a value INTO that vault via ``POST /v1/client/tokenize``
            from one of those origins, so the value never reaches your servers.
            ``data`` does not apply and is refused by the server.

        ``ttl_seconds`` defaults to 300 and is clamped at 600.

        The consume endpoints are browser operations and are deliberately not
        in this SDK — see ``sdk/PARITY.md``.
        """
        body: dict[str, Any] = {"action": action}
        if data is not None:
            body["data"] = data
        if vault is not None:
            body["vault"] = vault
        if origins is not None:
            body["origins"] = list(origins)
        if role is not None:
            body["role"] = role
        if ttl_seconds is not None:
            body["ttl_seconds"] = ttl_seconds
        return unwrap(await self._client.request(
            method="POST", path="/v1/client-tokens", body=body, idempotency_key=idempotency_key
        ))

    async def get_sealing_bundle(self, *, key: str | None = None) -> SealingBundle:
        """The public bits a browser needs to seal values client-side
        (``GET /v1/encrypt/sealing-bundle``): public key + key_ref, no private
        material. Omit ``key`` to use the tenant's default app key."""
        query = {"key": key} if key is not None else None
        return unwrap(await self._client.request(
            method="GET", path="/v1/encrypt/sealing-bundle", query=query
        ))

    # ── Signing / verification ────────────────────────────────────────────────

    async def sign(
        self,
        name: str,
        *,
        data: str | None = None,
        data_b64: str | None = None,
        rsa_padding: str | None = None,
        hash: str | None = None,
        idempotency_key: str | None = None,
    ) -> SignResult:
        """Sign data. Returns ``signature`` and ``key_version``."""
        body: dict[str, Any] = {}
        if data is not None:
            body["data"] = data
        if data_b64 is not None:
            body["data_b64"] = data_b64
        if rsa_padding is not None:
            body["rsa_padding"] = rsa_padding
        if hash is not None:
            body["hash"] = hash
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/crypto/keys/{quote(name, safe='')}/sign",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def verify(
        self,
        name: str,
        *,
        data: str | None = None,
        data_b64: str | None = None,
        signature: str,
        rsa_padding: str | None = None,
        hash: str | None = None,
    ) -> VerifyResult:
        """Verify a signature. Returns ``valid`` boolean and ``key_version``."""
        body: dict[str, Any] = {"signature": signature}
        if data is not None:
            body["data"] = data
        if data_b64 is not None:
            body["data_b64"] = data_b64
        if rsa_padding is not None:
            body["rsa_padding"] = rsa_padding
        if hash is not None:
            body["hash"] = hash
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/crypto/keys/{quote(name, safe='')}/verify",
            body=body,
        ))

    # ── JWT ───────────────────────────────────────────────────────────────────

    async def sign_jwt(
        self,
        name: str,
        *,
        claims: dict[str, Any],
        header_overrides: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> JwtSignResult:
        """Sign a JWT using the key. Returns ``token``, ``key_version``, ``alg``."""
        body: dict[str, Any] = {"claims": claims}
        if header_overrides is not None:
            body["header_overrides"] = header_overrides
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/crypto/keys/{quote(name, safe='')}/jwt",
            body=body,
            idempotency_key=idempotency_key,
        ))

    async def verify_jwt(
        self,
        name: str,
        *,
        token: str,
        expected: dict[str, Any] | None = None,
    ) -> JwtVerifyResult:
        """Verify a JWT. Returns ``valid``, ``claims``, ``key_version``, ``alg``."""
        body: dict[str, Any] = {"token": token}
        if expected is not None:
            body["expected"] = expected
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/crypto/keys/{quote(name, safe='')}/jwt/verify",
            body=body,
        ))

    # ── Webhook signing ───────────────────────────────────────────────────────

    async def sign_webhook(
        self,
        name: str,
        *,
        payload: str | None = None,
        payload_b64: str | None = None,
        timestamp_seconds: int | None = None,
        format: str | None = None,
        idempotency_key: str | None = None,
    ) -> WebhookSignResult:
        """Generate a Stripe-compatible webhook signature header."""
        body: dict[str, Any] = {}
        if payload is not None:
            body["payload"] = payload
        if payload_b64 is not None:
            body["payload_b64"] = payload_b64
        if timestamp_seconds is not None:
            body["timestamp_seconds"] = timestamp_seconds
        if format is not None:
            body["format"] = format
        return unwrap(await self._client.request(
            method="POST",
            path=f"/v1/crypto/keys/{quote(name, safe='')}/webhook-sign",
            body=body,
            idempotency_key=idempotency_key,
        ))
