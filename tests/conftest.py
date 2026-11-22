"""Shared fixtures and a Web Bot Auth test signer for TarelGo CaptchAI tests."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from collections.abc import AsyncIterator

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from httpx import ASGITransport, AsyncClient

from tarelgo_captchai.config import Settings
from tarelgo_captchai.main import create_app
from tarelgo_captchai.storage import MemoryStorage
from tarelgo_captchai.webbotauth.base import (
    RequestParts,
    build_signature_base,
    field_values_map,
)
from tarelgo_captchai.webbotauth.directory import AgentKeyResolver
from tarelgo_captchai.webbotauth.keys import jwk_thumbprint
from tarelgo_captchai.webbotauth.sfv import sf_serialize_inner_list

TEST_HOST = "tarelgo.test"
AGENT_ORIGIN = "https://agent.example"
TEST_SECRET = "unit-test-secret-0123456789abcdef-0123456789abcdef"


def make_settings(**overrides: object) -> Settings:
    base: dict = {
        "mode": "best_effort",
        "secrets": TEST_SECRET,
        "db_dsn": "",
        "allow_memory": True,
        "ratelimit_ai_token": "5/600",
        "ratelimit_b": "100/60",
        "ban_seconds": 60,
        "wba_max_age": 600,
        "wba_allow_private_keyhost": True,
        "metrics_private_only": False,
    }
    base.update(overrides)
    return Settings(**base)


@pytest.fixture
def agent_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def agent_jwk(agent_key: Ed25519PrivateKey) -> dict:
    raw = agent_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    x = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return {"kty": "OKP", "crv": "Ed25519", "x": x}


@pytest.fixture
def agent_jwks(agent_jwk: dict) -> str:
    return json.dumps({"keys": [agent_jwk]})


@pytest.fixture
def agent_keyid(agent_jwk: dict) -> str:
    return jwk_thumbprint(agent_jwk)


@pytest.fixture
def monkey_directory(monkeypatch: pytest.MonkeyPatch, agent_jwks: str) -> str:
    """Serve a stub agent directory instead of doing a network fetch."""
    async def fake_fetch(self: AgentKeyResolver, url: str) -> bytes:
        del self, url
        return agent_jwks.encode("utf-8")

    monkeypatch.setattr(AgentKeyResolver, "_guarded_fetch", fake_fetch)
    return AGENT_ORIGIN


def sign_request(
    key: Ed25519PrivateKey,
    method: str = "GET",
    path: str = "/b",
    authority: str = TEST_HOST,
    *,
    body: bytes = b"",
    scheme: str = "https",
    label: str = "sig1",
    keyid: str | None = None,
    agent_uri: str = AGENT_ORIGIN,
    agent_form: str = "legacy",
    include_agent: bool = True,
    created: int | None = None,
    expires: int | None = None,
    cover: list[str] | None = None,
    tag: str = "web-bot-auth",
    alg: str | None = None,
) -> dict[str, str]:
    """Build Signature / Signature-Input / Signature-Agent headers (agent side)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: F401

    if keyid is None:
        pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        x = base64.urlsafe_b64encode(pub).decode("ascii").rstrip("=")
        keyid = jwk_thumbprint({"kty": "OKP", "crv": "Ed25519", "x": x})

    components = cover or ["@method", "@path", "@authority"]
    if body:
        components = components + ["content-digest"]
    if include_agent:
        components = components + ["signature-agent"]
    covered = [(name, {}) for name in components]
    agent_component: tuple[str, dict] | None = None
    if include_agent:
        agent_component = (
            ("signature-agent", {})
            if agent_form == "legacy"
            else ("signature-agent", {"key": label})
        )
        covered[-1] = agent_component

    created = int(created if created is not None else time.time())
    expires = int(expires if expires is not None else created + 60)
    params: dict = {
        "created": created,
        "expires": expires,
        "keyid": keyid,
        "tag": tag,
    }
    if alg:
        params["alg"] = alg
    params_value = sf_serialize_inner_list(covered, params)

    parts = RequestParts(
        method=method.upper(),
        scheme=scheme,
        authority=authority,
        path=path,
        query="?",
        target_uri=f"{scheme}://{authority}{path}",
        fields=field_values_map([]),
    )
    # The signature-agent field value exactly as it appears on the wire:
    if include_agent:
        agent_header = (
            f'"{agent_uri}"' if agent_form == "legacy" else f'{label}="{agent_uri}"'
        )
        parts.fields = field_values_map([("signature-agent", agent_header)])
    for name, _cparams in covered:
        if name == "content-digest":
            digest = hashlib.sha256(body).digest()
            b64 = base64.b64encode(digest).decode("ascii")
            parts.fields["content-digest"] = [f"sha-256=:{b64}:"]

    base = build_signature_base(covered, parts, params_value)
    signature = base64.b64encode(key.sign(base)).decode("ascii")

    headers = {
        "signature": f"{label}=:{signature}:",
        "signature-input": f"{label}={params_value}",
    }
    if include_agent:
        headers["signature-agent"] = (
            f'"{agent_uri}"' if agent_form == "legacy" else f'{label}="{agent_uri}"'
        )
    if body:
        digest = hashlib.sha256(body).digest()
        headers["content-digest"] = "sha-256=:" + base64.b64encode(digest).decode("ascii") + ":"
    return headers


@pytest.fixture
def best_effort_app() -> object:
    return create_app(make_settings(), storage=MemoryStorage())


@pytest.fixture
async def client(best_effort_app) -> AsyncIterator[AsyncClient]:
    async with AsyncClient(
        transport=ASGITransport(app=best_effort_app),
        base_url=f"http://{TEST_HOST}",
    ) as http:
        yield http


def make_client(
    settings: Settings, storage: object | None = None
) -> AsyncClient:
    """Build a test client around a fresh app with the given settings."""
    app = create_app(settings, storage=storage or MemoryStorage())
    return AsyncClient(
        transport=ASGITransport(app=app), base_url=f"http://{TEST_HOST}"
    )
