"""One-shot capability tokens of TarelGo CaptchAI (best_effort mode, spec 6.2).

Wire format: tg1.<kidx>.<b64u(nonce)>.<exp>.<b64u(HMAC-SHA256)>
The MAC covers: format version, secret index, nonce, exp, client IP,
ua_sha256 and ja3. Comparison is strictly hmac.compare_digest (spec 10.1).
Secret rotation with overlap: the secret index is embedded in the token
(spec 10.2). Single-use semantics are enforced by the storage layer
(atomic INSERT ... ON CONFLICT DO NOTHING / INSERT IGNORE).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
from dataclasses import dataclass

TOKEN_VERSION = "tg1"  # noqa: S105 - wire format version tag, not a secret
TOKEN_NONCE_BYTES = 16
TOKEN_SKEW_S = 5


class TokenError(Exception):
    """Invalid token (reason goes to the log; the client gets a uniform 404)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(slots=True)
class TokenData:
    """Successful verification result: nonce hex + absolute expiry."""

    nonce_hex: str
    exp: int


def ua_hash(ua: str) -> str:
    return hashlib.sha256((ua or "").encode("utf-8")).hexdigest()


def _mac_input(kidx: int, nonce_b64: str, exp: int, ip: str, ua_sha: str, ja3: str) -> bytes:
    return "|".join(
        [TOKEN_VERSION, str(kidx), nonce_b64, str(exp), ip, ua_sha, ja3]
    ).encode("utf-8")


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64u_decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded)


def issue_token(
    secrets: list[bytes],
    ttl_s: int,
    ip: str,
    ua: str,
    ja3: str,
    now: int | None = None,
) -> str:
    """Issue a token for a client that passed the scoring gate."""
    if not secrets:
        raise TokenError("no_secrets")
    kidx = 0  # the first secret is always the active one
    nonce = os.urandom(TOKEN_NONCE_BYTES)
    nonce_b64 = _b64u(nonce)
    exp = int(now if now is not None else time.time()) + int(ttl_s)
    ua_sha = ua_hash(ua)
    mac = hmac.new(
        secrets[kidx],
        _mac_input(kidx, nonce_b64, exp, ip, ua_sha, ja3),
        hashlib.sha256,
    ).digest()
    return f"{TOKEN_VERSION}.{kidx}.{nonce_b64}.{exp}.{_b64u(mac)}"


def verify_token(
    token: str,
    secrets: list[bytes],
    ip: str,
    ua: str,
    ja3: str,
    now: int | None = None,
) -> TokenData:
    """Verify a token; raises TokenError on any failure. Constant-time MAC check."""
    if not secrets:
        raise TokenError("no_secrets")
    parts = token.split(".")
    if len(parts) != 5:
        raise TokenError("malformed")
    version, kidx_raw, nonce_b64, exp_raw, mac_b64 = parts
    if not hmac.compare_digest(version, TOKEN_VERSION):
        raise TokenError("bad_version")
    if not kidx_raw.isdigit() or len(kidx_raw) > 2:
        raise TokenError("bad_kidx")
    kidx = int(kidx_raw)
    if kidx >= len(secrets):
        raise TokenError("unknown_secret")
    try:
        nonce = _b64u_decode(nonce_b64)
        exp = int(exp_raw)
        mac = _b64u_decode(mac_b64)
    except (ValueError, TypeError) as exc:
        raise TokenError("malformed") from exc
    if len(mac) != 32:
        raise TokenError("bad_mac_length")
    ua_sha = ua_hash(ua)
    expected = hmac.new(
        secrets[kidx],
        _mac_input(kidx, nonce_b64, exp, ip, ua_sha, ja3),
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(expected, mac):
        # Rotation overlap: the secret may have moved to another position in
        # the list. Re-check with every other configured secret (same MAC
        # input, different key). Bounded by the number of secrets (2-3).
        for idx, secret in enumerate(secrets):
            if idx == kidx:
                continue
            rotated = hmac.new(
                secret, _mac_input(kidx, nonce_b64, exp, ip, ua_sha, ja3), hashlib.sha256
            ).digest()
            if hmac.compare_digest(rotated, mac):
                expected = rotated
                break
        else:
            raise TokenError("bad_mac")
    current = int(now if now is not None else time.time())
    if current > exp + TOKEN_SKEW_S:
        raise TokenError("expired")
    if exp - current > 86400:
        raise TokenError("ttl_too_long")
    return TokenData(nonce_hex=nonce.hex(), exp=exp)
