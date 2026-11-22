"""Web Bot Auth tests: RFC 8941 parsing, RFC 7638 thumbprints, RFC 9421
signature base construction and the full verification pipeline."""

from __future__ import annotations

import json
import time

import pytest

from tarelgo_captchai.storage import MemoryStorage
from tarelgo_captchai.webbotauth.base import (
    RequestParts,
    build_signature_base,
    field_values_map,
    normalize_authority,
)
from tarelgo_captchai.webbotauth.directory import AgentKeyResolver
from tarelgo_captchai.webbotauth.keys import jwk_thumbprint, select_jwk
from tarelgo_captchai.webbotauth.sfv import (
    SfError,
    SfToken,
    sf_parse_dictionary,
    sf_serialize_inner_list,
)
from tarelgo_captchai.webbotauth.verify import (
    VerifyInput,
    WbaError,
    parse_signature_agent,
    verify_web_bot_auth,
)

from .conftest import AGENT_ORIGIN, TEST_HOST, make_settings, sign_request

# --------------------------------------------------------------------- sfv


def test_sf_dictionary_with_inner_list_and_params() -> None:
    parsed = sf_parse_dictionary(
        'sig1=("@method" "@path");created=1700000000;keyid="k1";tag="web-bot-auth"'
    )
    assert set(parsed) == {"sig1"}
    items, params = parsed["sig1"]
    assert [value for value, _p in items] == ["@method", "@path"]
    assert params["created"] == 1700000000
    assert params["keyid"] == "k1"
    assert params["tag"] == "web-bot-auth"


def test_sf_byte_sequence_and_token() -> None:
    parsed = sf_parse_dictionary("sig=:AAEC:;type=cimd")
    value, params = parsed["sig"]
    assert value == b"\x00\x01\x02"
    assert isinstance(params["type"], SfToken)
    assert str(params["type"]) == "cimd"


def test_sf_re_serialization_is_stable() -> None:
    raw = 'sig1=("@method" "@authority");created=42;expires=99;keyid="ab";tag="web-bot-auth"'
    items, params = sf_parse_dictionary(raw)["sig1"]
    assert sf_serialize_inner_list(items, params) == raw.split("=", 1)[1]


@pytest.mark.parametrize(
    "bad",
    [
        "sig1=(",                # unterminated inner list
        "sig1=,:notb64:",        # invalid base64 byte sequence
        "a=1,,b=2",              # trailing comma
        'sig1="unterminated',    # unterminated string
        "1abc=1",                # key must start with lcalpha
    ],
)
def test_sf_errors(bad: str) -> None:
    with pytest.raises(SfError):
        sf_parse_dictionary(bad)


# -------------------------------------------------------------------- keys


def test_rfc8037_a3_thumbprint_vector() -> None:
    """Known-answer test from RFC 8037 Appendix A.3 (Ed25519 thumbprint)."""
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    }
    assert jwk_thumbprint(jwk) == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"


def test_select_jwk_by_thumbprint() -> None:
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    }
    jwks = {"keys": [jwk, {"kty": "EC", "crv": "P-256"}]}
    assert select_jwk(jwks, jwk_thumbprint(jwk)) is jwk
    assert select_jwk(jwks, "unknown") is None


def test_authority_normalization() -> None:
    assert normalize_authority("Example.COM", "https") == "example.com"
    assert normalize_authority("example.com:443", "https") == "example.com"
    assert normalize_authority("example.com:80", "https") == "example.com:80"
    assert normalize_authority("example.com:8080", "https") == "example.com:8080"
    assert normalize_authority("", "https") == ""


# ------------------------------------------------------- signature base


def test_signature_base_known_answer() -> None:
    """Exact RFC 9421 section 2.5 layout, verified against a literal string."""
    empty_sha256 = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
    covered = [
        ("@method", {}),
        ("@path", {}),
        ("@authority", {}),
        ("content-digest", {}),
    ]
    params_value = (
        '("@method" "@path" "@authority" "content-digest")'
        ';created=1700000000;keyid="k1";tag="web-bot-auth"'
    )
    parts = RequestParts(
        method="GET",
        scheme="https",
        authority=TEST_HOST,
        path="/b",
        query="?",
        target_uri=f"https://{TEST_HOST}/b",
        fields={"content-digest": [f"sha-256=:{empty_sha256}:"]},
    )
    expected = "\n".join(
        [
            '"@method": GET',
            '"@path": /b',
            f'"@authority": {TEST_HOST}',
            f'"content-digest": sha-256=:{empty_sha256}:',
            f'"@signature-params": {params_value}',
        ]
    )
    assert build_signature_base(covered, parts, params_value) == expected.encode("ascii")


def test_signature_base_rejects_duplicates_and_unknown_components() -> None:
    parts = RequestParts(
        method="GET", scheme="https", authority="x.test", path="/", query="?",
        target_uri="https://x.test/", fields={},
    )
    with pytest.raises(ValueError, match="twice"):
        build_signature_base(
            [("@method", {}), ("@method", {})], parts, '("@method" "@method")'
        )
    with pytest.raises(ValueError, match="unknown derived"):
        build_signature_base([("@status", {})], parts, '("@status")')


# ------------------------------------------------------- Signature-Agent


def test_signature_agent_forms() -> None:
    kind, entries = parse_signature_agent('"https://agent.example"')
    assert kind == "legacy" and entries[0].uri == AGENT_ORIGIN
    kind, entries = parse_signature_agent('sig1="https://agent.example/card";type=cimd')
    assert kind == "current" and entries[0].cimd is True
    with pytest.raises(WbaError):
        parse_signature_agent('"http://insecure.example"')


# ------------------------------------------------------------- full verify


async def _verify(agent_key, settings, headers, path="/b", host=TEST_HOST):
    resolver = AgentKeyResolver(MemoryStorage(), settings)
    payload = VerifyInput(
        method="GET",
        scheme="https",
        host=host,
        path=path,
        query="",
        headers=list(headers.items()),
    )
    return await verify_web_bot_auth(payload, resolver, settings)


async def test_verify_ok_roundtrip(agent_key, agent_keyid, monkey_directory) -> None:
    settings = make_settings()
    headers = sign_request(agent_key, keyid=agent_keyid)
    result = await _verify(agent_key, settings, headers)
    assert result.keyid == agent_keyid
    assert result.agent_uri == AGENT_ORIGIN
    assert result.created <= int(time.time()) + settings.wba_clock_skew


async def test_verify_current_dictionary_form(agent_key, monkey_directory) -> None:
    settings = make_settings()
    headers = sign_request(agent_key, agent_form="current", label="sig2")
    result = await _verify(agent_key, settings, headers)
    assert result.label == "sig2"


async def test_verify_rejects_tampered_path(agent_key, monkey_directory) -> None:
    settings = make_settings()
    headers = sign_request(agent_key, path="/b")
    with pytest.raises(WbaError) as exc:
        await _verify(agent_key, settings, headers, path="/other")
    assert exc.value.reason == "bad_signature"


async def test_verify_rejects_foreign_host(agent_key, monkey_directory) -> None:
    settings = make_settings()
    headers = sign_request(agent_key)
    with pytest.raises(WbaError) as exc:
        await _verify(agent_key, settings, headers, host="evil.test")
    assert exc.value.reason == "bad_signature"


async def test_verify_rejects_expired_signature(agent_key, monkey_directory) -> None:
    settings = make_settings(wba_max_age=600)
    headers = sign_request(agent_key, created=int(time.time()) - 10_000)
    with pytest.raises(WbaError) as exc:
        await _verify(agent_key, settings, headers)
    assert exc.value.reason == "signature_expired"


async def test_verify_rejects_bad_tag(agent_key, monkey_directory) -> None:
    settings = make_settings()
    headers = sign_request(agent_key, tag="something-else")
    with pytest.raises(WbaError) as exc:
        await _verify(agent_key, settings, headers)
    assert exc.value.reason == "bad_tag"


async def test_verify_rejects_bad_alg(agent_key, monkey_directory) -> None:
    settings = make_settings()
    headers = sign_request(agent_key, alg="rsa-pss-sha512")
    with pytest.raises(WbaError) as exc:
        await _verify(agent_key, settings, headers)
    assert exc.value.reason == "bad_alg"


async def test_verify_requires_signature_agent(agent_key, monkey_directory) -> None:
    settings = make_settings()
    headers = sign_request(agent_key, include_agent=False)
    with pytest.raises(WbaError) as exc:
        await _verify(agent_key, settings, headers)
    assert exc.value.reason == "missing_agent"


async def test_agent_less_thumbprint_keyid_needs_out_of_band_key(
    agent_key, monkey_directory
) -> None:
    """Protocol section 4.3: without Signature-Agent a thumbprint keyid only
    verifies when the verifier already holds the key. We never pre-share keys,
    so the request must be rejected with key_not_found (fail-closed)."""
    settings = make_settings(wba_require_agent=False)
    headers = sign_request(agent_key, include_agent=False)
    with pytest.raises(WbaError) as exc:
        await _verify(agent_key, settings, headers)
    assert exc.value.reason == "key_not_found"


async def test_agent_less_uri_keyid_uses_directory(
    agent_key, agent_jwk, monkey_directory
) -> None:
    """Legacy mode: keyid is a URI whose origin directory publishes the key."""
    settings = make_settings(wba_require_agent=False)
    keyid_uri = f"{AGENT_ORIGIN}/keys/1"
    jwks = json.dumps({"keys": [{**agent_jwk, "kid": keyid_uri}]})

    async def fake_fetch(self: AgentKeyResolver, url: str) -> bytes:
        del self, url
        return jwks.encode("utf-8")

    original = AgentKeyResolver._guarded_fetch
    AgentKeyResolver._guarded_fetch = fake_fetch  # type: ignore[method-assign]
    try:
        headers = sign_request(agent_key, keyid=keyid_uri, include_agent=False)
        result = await _verify(agent_key, settings, headers)
        assert result.agent_uri == AGENT_ORIGIN
        assert result.keyid == keyid_uri
    finally:
        AgentKeyResolver._guarded_fetch = original  # type: ignore[method-assign]


async def test_verify_requires_key_from_directory(
    agent_key, agent_keyid, monkey_directory
) -> None:
    """A signature by a key that is NOT in the directory must fail."""
    import base64 as b64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    settings = make_settings()
    stranger = Ed25519PrivateKey.generate()
    raw = stranger.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    stranger_x = b64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    stranger_keyid = jwk_thumbprint({"kty": "OKP", "crv": "Ed25519", "x": stranger_x})
    # Signed by the stranger key while the stub directory publishes only
    # agent_key's JWK: no matching keyid -> the request must be rejected.
    headers = sign_request(stranger, keyid=stranger_keyid)
    resolver = AgentKeyResolver(MemoryStorage(), settings)
    payload = VerifyInput(
        method="GET", scheme="https", host=TEST_HOST, path="/b", query="",
        headers=list(headers.items()),
    )
    with pytest.raises(WbaError) as exc:
        await verify_web_bot_auth(payload, resolver, settings)
    assert exc.value.reason == "key_not_found"


async def test_verify_rejects_missing_signature_headers(agent_key) -> None:
    settings = make_settings()
    with pytest.raises(WbaError) as exc:
        await _verify(agent_key, settings, {})
    assert exc.value.reason == "missing_signature_headers"


def test_field_values_map_multimap() -> None:
    fields = field_values_map([("A", "1"), ("a", "2"), ("B", "x")])
    assert fields == {"a": ["1", "2"], "b": ["x"]}
