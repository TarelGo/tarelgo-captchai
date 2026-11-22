"""Capability token tests for TarelGo CaptchAI (spec sections 6.2 and 10)."""

from __future__ import annotations

import time

import pytest

from tarelgo_captchai.tokens import (
    TOKEN_VERSION,
    TokenError,
    issue_token,
    ua_hash,
    verify_token,
)

SECRETS = [b"a" * 32, b"b" * 32]


def test_roundtrip() -> None:
    token = issue_token(SECRETS, 120, "1.2.3.4", "UA/1.0", "")
    data = verify_token(token, SECRETS, "1.2.3.4", "UA/1.0", "")
    assert data.nonce_hex
    assert len(bytes.fromhex(data.nonce_hex)) == 16
    assert data.exp > int(time.time())


def test_format_has_brand_version() -> None:
    token = issue_token(SECRETS, 120, "1.2.3.4", "UA", "")
    assert token.startswith(TOKEN_VERSION + ".")
    assert len(token.split(".")) == 5


def test_expired_token_rejected() -> None:
    token = issue_token(SECRETS, 1, "1.2.3.4", "UA", "", now=int(time.time()) - 60)
    with pytest.raises(TokenError) as exc:
        verify_token(token, SECRETS, "1.2.3.4", "UA", "")
    assert exc.value.reason == "expired"


def test_tampered_mac_rejected() -> None:
    token = issue_token(SECRETS, 120, "1.2.3.4", "UA", "")
    parts = token.split(".")
    head = parts[4][0]
    alt = "A" if head != "A" else "B"
    tampered = ".".join(parts[:4] + [alt + parts[4][1:]])
    with pytest.raises(TokenError) as exc:
        verify_token(tampered, SECRETS, "1.2.3.4", "UA", "")
    assert exc.value.reason == "bad_mac"


def test_ip_binding() -> None:
    token = issue_token(SECRETS, 120, "1.2.3.4", "UA", "")
    with pytest.raises(TokenError) as exc:
        verify_token(token, SECRETS, "5.6.7.8", "UA", "")
    assert exc.value.reason == "bad_mac"


def test_ua_binding() -> None:
    token = issue_token(SECRETS, 120, "1.2.3.4", "UA/1.0", "")
    with pytest.raises(TokenError) as exc:
        verify_token(token, SECRETS, "1.2.3.4", "UA/2.0", "")
    assert exc.value.reason == "bad_mac"


def test_unbound_ua_matches_when_binding_disabled() -> None:
    """token_bind_ua=False is implemented by hashing an empty UA at both ends."""
    token = issue_token(SECRETS, 120, "1.2.3.4", "", "")
    data = verify_token(token, SECRETS, "1.2.3.4", "", "")
    assert data.nonce_hex


def test_secret_rotation_overlap() -> None:
    """Tokens issued with the old (second) secret stay valid during rotation."""
    token = issue_token([SECRETS[1]], 120, "1.2.3.4", "UA", "")
    data = verify_token(token, [SECRETS[0], SECRETS[1]], "1.2.3.4", "UA", "")
    assert data.nonce_hex


def test_unknown_secret_index_rejected() -> None:
    token = issue_token(SECRETS, 120, "1.2.3.4", "UA", "")
    parts = token.split(".")
    parts[1] = "5"
    with pytest.raises(TokenError) as exc:
        verify_token(".".join(parts), SECRETS, "1.2.3.4", "UA", "")
    assert exc.value.reason == "unknown_secret"


def test_ttl_too_long_rejected() -> None:
    token = issue_token(SECRETS, 90000, "1.2.3.4", "UA", "")
    with pytest.raises(TokenError) as exc:
        verify_token(token, SECRETS, "1.2.3.4", "UA", "")
    assert exc.value.reason == "ttl_too_long"


def test_malformed_tokens_rejected() -> None:
    for bad in ("", "x.y", "tg1.0.abc", "wrong.0.abc.123.def", "tg1.99.abc.123.def"):
        with pytest.raises(TokenError):
            verify_token(bad, SECRETS, "1.2.3.4", "UA", "")


def test_ua_hash_is_stable_sha256() -> None:
    assert ua_hash("UA") == ua_hash("UA")
    assert len(ua_hash("UA")) == 64
    assert ua_hash("") != ua_hash("UA")
