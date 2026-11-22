"""Branch B access-control tests for TarelGo CaptchAI (spec sections 6.3, 11).

Covers: uniform 404 (no oracle), fail-closed on storage failure, fail-open on
branch A, one-shot token semantics and binding enforcement.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from tarelgo_captchai.main import create_app
from tarelgo_captchai.storage import MemoryStorage, StorageUnavailable

from .conftest import TEST_HOST, make_settings

IMPOSTOR_HEADERS = {
    "user-agent": "Mozilla/5.0 (compatible; ImpostorBot/2.0)",
    "accept": "text/html",
}


class BrokenStorage(MemoryStorage):
    """Storage that is always down - for fail-closed assertions."""

    async def ping(self) -> bool:
        return False

    async def ban_remaining(self, scope: str, subject: str) -> int:
        raise StorageUnavailable("down")

    async def rate_hit(self, scope: str, subject: str, limit: int, window_s: int):
        raise StorageUnavailable("down")

    async def mark_token_used(self, nonce: str, expires_at) -> bool:
        raise StorageUnavailable("down")


def make_client(settings) -> AsyncClient:
    app = create_app(settings, storage=MemoryStorage())
    return AsyncClient(transport=ASGITransport(app=app), base_url=f"http://{TEST_HOST}")


@pytest.mark.asyncio
async def test_strict_mode_rejects_unsigned() -> None:
    async with make_client(make_settings(mode="strict")) as client:
        response = await client.get("/b")
        assert response.status_code == 404


@pytest.mark.asyncio
async def test_strict_mode_ignores_tokens() -> None:
    async with make_client(make_settings(mode="strict")) as client:
        response = await client.get(
            "/b", headers={"authorization": "Bearer tg1.0.abc.123.def"}
        )
        assert response.status_code == 404


@pytest.mark.asyncio
async def test_best_effort_rejects_missing_token() -> None:
    async with make_client(make_settings()) as client:
        response = await client.get("/b")
        assert response.status_code == 404


@pytest.mark.asyncio
async def test_token_flow_grants_access_and_is_single_use() -> None:
    async with make_client(make_settings()) as client:
        issued = await client.post("/ai-token", headers=IMPOSTOR_HEADERS)
        assert issued.status_code == 200
        token = issued.json()["token"]

        first = await client.get(
            "/b", headers={**IMPOSTOR_HEADERS, "authorization": f"Bearer {token}"}
        )
        assert first.status_code == 200
        assert first.headers["x-tarelgo-branch"] == "B"
        assert "AI-only branch" in first.text

        replay = await client.get(
            "/b", headers={**IMPOSTOR_HEADERS, "authorization": f"Bearer {token}"}
        )
        assert replay.status_code == 404


@pytest.mark.asyncio
async def test_token_bound_to_client_ip() -> None:
    async with make_client(make_settings()) as client:
        issued = await client.post(
            "/ai-token", headers={**IMPOSTOR_HEADERS, "x-forwarded-for": "9.9.9.9"}
        )
        token = issued.json()["token"]
        response = await client.get(
            "/b",
            headers={
                **IMPOSTOR_HEADERS,
                "authorization": f"Bearer {token}",
                "x-forwarded-for": "8.8.8.8",
            },
        )
        assert response.status_code == 404


@pytest.mark.asyncio
async def test_token_bound_to_user_agent() -> None:
    async with make_client(make_settings()) as client:
        issued = await client.post("/ai-token", headers=IMPOSTOR_HEADERS)
        token = issued.json()["token"]
        response = await client.get(
            "/b",
            headers={
                "user-agent": "Mozilla/5.0 (compatible; DifferentBot/1.0)",
                "authorization": f"Bearer {token}",
            },
        )
        assert response.status_code == 404


@pytest.mark.asyncio
async def test_uniform_404_has_identical_body() -> None:
    """All branch B rejections share one body and headers (no oracle)."""
    async with make_client(make_settings()) as client:
        missing = await client.get("/b")
        tampered = await client.get("/b", headers={"authorization": "Bearer junk.junk.junk.junk"})
        replay = await client.get("/b", headers={"x-tarelgo-token": "tg1.0.abc.1.def"})

        for response in (missing, tampered, replay):
            assert response.status_code == 404
        assert missing.text == tampered.text == replay.text
        assert missing.headers["cache-control"] == "private, no-store"


@pytest.mark.asyncio
async def test_b_rate_limit_returns_uniform_404() -> None:
    async with make_client(make_settings(ratelimit_b="2/60")) as client:
        assert (await client.get("/b")).status_code == 404
        assert (await client.get("/b")).status_code == 404
        # Third hit exceeds the limit -> still the uniform 404, never 429.
        limited = await client.get("/b")
        assert limited.status_code == 404
        assert limited.text == (await client.get("/b")).text


@pytest.mark.asyncio
async def test_fail_closed_when_storage_down() -> None:
    app = create_app(make_settings(), storage=BrokenStorage())
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=f"http://{TEST_HOST}"
    ) as client:
        assert (await client.get("/b")).status_code == 404
        token_response = await client.post("/ai-token", headers=IMPOSTOR_HEADERS)
        assert token_response.status_code == 503


@pytest.mark.asyncio
async def test_fail_open_on_branch_a_when_storage_down() -> None:
    app = create_app(make_settings(), storage=BrokenStorage())
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=f"http://{TEST_HOST}"
    ) as client:
        response = await client.get("/")
        assert response.status_code == 200
        assert response.headers["x-tarelgo-branch"] == "A"


@pytest.mark.asyncio
async def test_alternative_token_header_accepted() -> None:
    async with make_client(make_settings()) as client:
        issued = await client.post("/ai-token", headers=IMPOSTOR_HEADERS)
        token = issued.json()["token"]
        response = await client.get(
            "/b", headers={**IMPOSTOR_HEADERS, "x-tarelgo-token": token}
        )
        assert response.status_code == 200


@pytest.mark.asyncio
async def test_low_score_gets_403_not_404() -> None:
    async with make_client(make_settings()) as client:
        response = await client.post("/ai-token", headers={"user-agent": "curl/8.5.0"})
        assert response.status_code == 403
