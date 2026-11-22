"""DPoP proof generation (RFC 9449) — client side. Mirrors dpop.ts."""

from __future__ import annotations
import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_json(obj: Any) -> str:
    return _b64url(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def _ec_point_to_jwk(pub: ec.EllipticCurvePublicKey) -> dict[str, str]:
    nums = pub.public_numbers()
    x_bytes = nums.x.to_bytes(32, "big")
    y_bytes = nums.y.to_bytes(32, "big")
    return {"kty": "EC", "crv": "P-256", "x": _b64url(x_bytes), "y": _b64url(y_bytes)}


@dataclass
class DpopKeyPair:
    """ES256 keypair for DPoP proofs. Private key stays in this dataclass."""

    _private_key: ec.EllipticCurvePrivateKey
    public_jwk: dict[str, str]

    @classmethod
    def generate(cls) -> "DpopKeyPair":
        priv = ec.generate_private_key(ec.SECP256R1())
        return cls(_private_key=priv, public_jwk=_ec_point_to_jwk(priv.public_key()))

    def sign(
        self,
        *,
        method: str,
        url: str,
        access_token: str | None = None,
        nonce: str | None = None,
    ) -> str:
        """Sign a DPoP proof JWT for one specific request."""
        header = {"alg": "ES256", "typ": "dpop+jwt", "jwk": self.public_jwk}
        # Strip query string + fragment per RFC 9449 §4.3
        clean_url = url.split("#", 1)[0].split("?", 1)[0]
        payload: dict[str, Any] = {
            "htm": method.upper(),
            "htu": clean_url,
            "iat": int(time.time()),
            "jti": _b64url(os.urandom(16)),
        }
        if access_token is not None:
            payload["ath"] = _b64url(hashlib.sha256(access_token.encode()).digest())
        if nonce is not None:
            payload["nonce"] = nonce

        header_b64 = _b64url_json(header)
        payload_b64 = _b64url_json(payload)
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

        der_sig = self._private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_sig)
        p1363 = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return f"{header_b64}.{payload_b64}.{_b64url(p1363)}"

    def thumbprint(self) -> str:
        """RFC 7638 thumbprint — used as cnf.jkt on issued tokens."""
        canonical = json.dumps(
            {
                "crv": self.public_jwk["crv"],
                "kty": self.public_jwk["kty"],
                "x": self.public_jwk["x"],
                "y": self.public_jwk["y"],
            },
            separators=(",", ":"),
            sort_keys=False,
        )
        return _b64url(hashlib.sha256(canonical.encode("utf-8")).digest())
