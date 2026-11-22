"""Rate limiting for TarelGo CaptchAI (spec section 7).

Implemented as a fixed window stored in the SQL database: an atomic
INSERT ... ON CONFLICT / ON DUPLICATE KEY UPDATE ... RETURNING-style upsert
(equivalent of INCR+EXPIRE, explicitly allowed by spec 10.7).
Exceeding the /ai-token limit triggers 429 plus a temporary ban.
"""

from __future__ import annotations

from dataclasses import dataclass

from .config import Settings
from .storage import Storage, utcnow

SCOPE_AI_TOKEN = "ai-token"  # noqa: S105 - rate limit scope name, not a secret
SCOPE_B = "b"


@dataclass(slots=True)
class RateResult:
    allowed: bool
    retry_after: int
    exceeded: bool


async def rate_check(
    storage: Storage,
    settings: Settings,
    scope: str,
    subject: str,
    *,
    ban_on_exceed: bool = False,
) -> RateResult:
    """Check and register one hit in the sliding/fixed window for the subject."""
    limit, window_s = (
        settings.ratelimit_ai_token_tuple()
        if scope == SCOPE_AI_TOKEN
        else settings.ratelimit_b_tuple()
    )
    banned_left = await storage.ban_remaining(scope, subject)
    if banned_left > 0:
        return RateResult(allowed=False, retry_after=banned_left, exceeded=False)
    verdict = await storage.rate_hit(scope, subject, limit, window_s)
    if not verdict.allowed:
        if ban_on_exceed:
            await storage.ban_set(scope, subject, settings.ban_seconds)
            return RateResult(
                allowed=False, retry_after=settings.ban_seconds, exceeded=True
            )
        elapsed = max(0.0, (utcnow() - verdict.window_start).total_seconds())
        retry_after = window_s - int(elapsed)
        return RateResult(allowed=False, retry_after=max(1, retry_after), exceeded=True)
    return RateResult(allowed=True, retry_after=0, exceeded=False)
