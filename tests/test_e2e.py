"""End-to-end scenarios for TarelGo CaptchAI (spec section 13, 12 scenarios).

Runs against the fully assembled ASGI application (middleware + routes +
storage + Web Bot Auth) exactly as it would be deployed on the VPS.

Scenario map:
  1.  Real browser        -> GET /  -> branch A (200 HTML).
  2.  curl + GPTBot       -> GET /  -> branch A (score 2 < threshold).
  3.  Browser impostor    -> POST /ai-token -> token -> GET /b -> branch B.
  4.  Token replay        -> GET /b -> uniform 404.
  5.  /ai-token flood     -> 429 + Retry-After, then a ban.
  6.  strict mode         -> /ai-token 404; unsigned /b 404.
  7.  strict + Web Bot Auth signature -> GET /b -> branch B (200).
  8.  strict + tampered signature     -> GET /b -> uniform 404.
  9.  GET / with a valid signature     -> branch B content directly (no 302,
      because a redirect would break the RFC 9421 signature over @path).
  10. robots.txt forbids /b and llms.txt documents the token flow + tarelgo.com.
  11. /healthz ok and /metrics exposes tarelgo_captchai_decisions_total.
  12. All branch B rejections return byte-identical bodies (anti-oracle).
"""

from __future__ import annotations

import base64

import pytest

from .conftest import TEST_HOST, make_client, make_settings, sign_request

BROWSER_HEADERS = {
    "user-agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/126.0.0.0 Safari/537.36"
    ),
    "sec-fetch-site": "none",
    "sec-fetch-mode": "navigate",
    "sec-fetch-dest": "document",
    "sec-ch-ua": '"Chromium";v="126"',
    "accept": "text/html,application/xhtml+xml",
    "accept-language": "en-US,en;q=0.9",
}
IMPOSTOR_HEADERS = {
    "user-agent": "Mozilla/5.0 (compatible; ImpostorBot/2.0)",
    "accept": "text/html",
}
CURL_GPTBOT_HEADERS = {"user-agent": "curl/8.5.0 GPTBot/1.0"}


# -------------------------------------------------------------- 1. browser -> A
@pytest.mark.asyncio
async def test_scenario_1_human_browser_sees_branch_a(client) -> None:
    response = await client.get("/", headers=BROWSER_HEADERS)
    assert response.status_code == 200
    assert response.headers["x-tarelgo-branch"] == "A"
    assert "<html" in response.text.lower()
    assert "TarelGo CaptchAI" in response.text
    assert "tarelgo.com" in response.text


# --------------------------------------------------------- 2. curl+GPTBot -> A
@pytest.mark.asyncio
async def test_scenario_2_declared_bot_without_proof_stays_on_a(client) -> None:
    response = await client.get("/", headers=CURL_GPTBOT_HEADERS)
    assert response.status_code == 200
    assert response.headers["x-tarelgo-branch"] == "A"


# ------------------------------------------------ 3. impostor token flow -> B
@pytest.mark.asyncio
async def test_scenario_3_impostor_reaches_b_via_token(client) -> None:
    issued = await client.post("/ai-token", headers=IMPOSTOR_HEADERS)
    assert issued.status_code == 200
    payload = issued.json()
    assert payload["token_type"] == "capability"
    assert payload["expires_in"] == 120

    branch = await client.get(
        "/b", headers={**IMPOSTOR_HEADERS, "authorization": f"Bearer {payload['token']}"}
    )
    assert branch.status_code == 200
    assert branch.headers["x-tarelgo-branch"] == "B"
    assert branch.headers["x-robots-tag"] == "noindex, nofollow"
    assert branch.text.startswith("# TarelGo CaptchAI")


# ------------------------------------------------------------- 4. replay -> 404
@pytest.mark.asyncio
async def test_scenario_4_token_is_single_use(client) -> None:
    token = (await client.post("/ai-token", headers=IMPOSTOR_HEADERS)).json()["token"]
    first = await client.get(
        "/b", headers={**IMPOSTOR_HEADERS, "authorization": f"Bearer {token}"}
    )
    replay = await client.get(
        "/b", headers={**IMPOSTOR_HEADERS, "authorization": f"Bearer {token}"}
    )
    assert first.status_code == 200
    assert replay.status_code == 404


# ------------------------------------------------------------ 5. rate limit 429
@pytest.mark.asyncio
async def test_scenario_5_ai_token_flood_is_banned() -> None:
    async with make_client(make_settings(ratelimit_ai_token="3/600", ban_seconds=60)) as client:
        statuses = [
            (await client.post("/ai-token", headers=IMPOSTOR_HEADERS)).status_code
            for _ in range(4)
        ]
        assert statuses[:3] == [200, 200, 200]
        assert statuses[3] == 429
        flood = await client.post("/ai-token", headers=IMPOSTOR_HEADERS)
        assert flood.status_code == 429
        assert "retry-after" in flood.headers


# ------------------------------------------------------------- 6. strict mode
@pytest.mark.asyncio
async def test_scenario_6_strict_mode_has_no_token_endpoint() -> None:
    async with make_client(make_settings(mode="strict")) as client:
        assert (await client.post("/ai-token", headers=IMPOSTOR_HEADERS)).status_code == 404
        assert (await client.get("/b")).status_code == 404
        # Branch A keeps working for everyone.
        assert (await client.get("/", headers=BROWSER_HEADERS)).status_code == 200


# ------------------------------------------------ 7. strict + valid signature
@pytest.mark.asyncio
async def test_scenario_7_strict_accepts_web_bot_auth(
    agent_key, agent_keyid, monkey_directory
) -> None:
    async with make_client(make_settings(mode="strict")) as client:
        headers = sign_request(agent_key, keyid=agent_keyid, authority=TEST_HOST)
        response = await client.get("/b", headers=headers)
        assert response.status_code == 200
        assert response.headers["x-tarelgo-branch"] == "B"


# --------------------------------------------- 8. strict + tampered signature
@pytest.mark.asyncio
async def test_scenario_8_strict_rejects_tampered_signature(
    agent_key, agent_keyid, monkey_directory
) -> None:
    async with make_client(make_settings(mode="strict")) as client:
        headers = sign_request(agent_key, keyid=agent_keyid)
        raw = base64.b64decode(headers["signature"].split(":")[1])
        broken = base64.b64encode(raw[:-1] + bytes([raw[-1] ^ 0xFF])).decode()
        headers["signature"] = f"sig1=:{broken}:"
        response = await client.get("/b", headers=headers)
        assert response.status_code == 404


# ---------------------------------------- 9. GET / with signature -> B content
@pytest.mark.asyncio
async def test_scenario_9_signed_request_at_root_gets_branch_b(
    agent_key, agent_keyid, monkey_directory
) -> None:
    async with make_client(make_settings(mode="strict")) as client:
        # The signature covers @path, so it must be made for the actual
        # target ("/"): this is also why a 302 redirect would break it.
        headers = sign_request(agent_key, keyid=agent_keyid, path="/")
        response = await client.get("/", headers=headers)
        assert response.status_code == 200
        assert response.headers["x-tarelgo-branch"] == "B"
        assert response.text.startswith("# TarelGo CaptchAI")


# ------------------------------------------------------- 10. robots + llms.txt
@pytest.mark.asyncio
async def test_scenario_10_robots_and_llms_policy(client) -> None:
    robots = await client.get("/robots.txt")
    assert robots.status_code == 200
    assert "Disallow: /b" in robots.text
    assert "tarelgo.com" in robots.text

    llms = await client.get("/llms.txt")
    assert llms.status_code == 200
    assert "/ai-token" in llms.text
    assert "Web Bot Auth" in llms.text
    assert "tarelgo.com" in llms.text


# --------------------------------------------------------- 11. health + metrics
@pytest.mark.asyncio
async def test_scenario_11_healthz_and_metrics(client) -> None:
    health = await client.get("/healthz")
    assert health.status_code == 200
    body = health.json()
    assert body["status"] == "ok"
    assert body["storage"] is True
    assert body["mode"] == "best_effort"

    # Generate some traffic so the counters are non-empty.
    await client.get("/", headers=BROWSER_HEADERS)
    metrics = await client.get("/metrics")
    assert metrics.status_code == 200
    assert "tarelgo_captchai_decisions_total" in metrics.text


# -------------------------------------------------------------- 12. anti-oracle
@pytest.mark.asyncio
async def test_scenario_12_uniform_rejection_bodies(client) -> None:
    missing = await client.get("/b")
    bad_format = await client.get("/b", headers={"authorization": "Bearer garbage"})
    missing_agent = await client.get(
        "/b",
        headers={
            "signature": "sig1=:::",
            "signature-input": "sig1=(x)",
        },
    )
    bodies = {missing.text, bad_format.text, missing_agent.text}
    assert len(bodies) == 1
    statuses = {missing.status_code, bad_format.status_code, missing_agent.status_code}
    assert statuses == {404}
