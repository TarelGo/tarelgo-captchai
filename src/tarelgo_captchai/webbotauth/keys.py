"""Agent JWK handling for TarelGo CaptchAI (Ed25519, RFC 7517/7638/8032)."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class InvalidKeyError(ValueError):
    """Malformed or unsupported JWK."""


def b64url_decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded)


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638: SHA-256 of the canonical JSON of required fields, base64url no padding."""
    kty = jwk.get("kty")
    if kty == "OKP":
        canonical = {"crv": jwk.get("crv"), "kty": kty, "x": jwk.get("x")}
    elif kty == "RSA":
        canonical = {"e": jwk.get("e"), "kty": kty, "n": jwk.get("n")}
    else:
        raise InvalidKeyError(f"unsupported kty: {kty!r}")
    compact = json.dumps(canonical, separators=(",", ":"), sort_keys=True)
    digest = hashlib.sha256(compact.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def jwk_public_key(jwk: dict[str, Any]) -> Ed25519PublicKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise InvalidKeyError("expected an OKP/Ed25519 key")
    x = jwk.get("x")
    if not isinstance(x, str):
        raise InvalidKeyError("the key has no x field")
    raw = b64url_decode(x)
    if len(raw) != 32:
        raise InvalidKeyError("an Ed25519 public key must be exactly 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def jwk_matches_keyid(jwk: dict[str, Any], keyid: str) -> bool:
    """kid equals keyid OR the thumbprint equals keyid (RFC 7638)."""
    kid = jwk.get("kid")
    if isinstance(kid, str) and kid == keyid:
        return True
    try:
        return jwk_thumbprint(jwk) == keyid
    except InvalidKeyError:
        return False


def select_jwk(jwks: dict[str, Any], keyid: str) -> dict[str, Any] | None:
    """Select a key from a JWKS by keyid (kid or thumbprint), Ed25519 only."""
    keys = jwks.get("keys")
    if not isinstance(keys, list):
        return None
    for candidate in keys:
        if not isinstance(candidate, dict):
            continue
        if candidate.get("kty") != "OKP" or candidate.get("crv") != "Ed25519":
            continue
        use = candidate.get("use")
        if use not in (None, "sig"):
            continue
        if jwk_matches_keyid(candidate, keyid):
            return candidate
    return None
