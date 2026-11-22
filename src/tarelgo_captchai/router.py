"""HTTP routes of TarelGo CaptchAI - the fork itself.

Endpoints (spec section 7):
  GET  /          - branch A for everyone; a valid Web Bot Auth signature is
                    served branch B content directly (a 302 would break the
                    signed request: the signature covers @path of the original
                    target, so the redirect is rendered useless).
  POST /ai-token  - capability token endpoint (best_effort mode only).
  GET  /b         - AI-only branch: Web Bot Auth (both modes) or one-shot
                    token (best_effort). Every rejection is the uniform 404.
  GET  /healthz   - health + storage state (JSON).
  GET  /metrics   - Prometheus exposition (protected by default).
  GET  /robots.txt and /llms.txt - published policy with tarelgo.com links.

Fail modes: / and /ai-token scoring never depend on the storage being alive;
/b and token single-use semantics are fail-closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from fastapi import APIRouter
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response

from . import TARELGO_SERVICE_NAME, __version__
from .config import Settings
from .detect import (
    Score,
    accept_html_signal,
    accept_language_signal,
    connection_close_signal,
    header_order_signal,
    ja3_scoring_signal,
    missing_client_hints_signal,
    no_sec_fetch_signal,
    score_signals,
    should_route_b,
    ua_ai_signal,
)
from .logging import log_event
from .metrics import metrics
from .ratelimit import SCOPE_AI_TOKEN, SCOPE_B, rate_check
from .security import (
    DENY_HEADERS,
    RequestCtx,
    branch_b_headers,
    constant_eq,
    uniform_404,
)
from .storage import Storage, StorageUnavailable, utcnow
from .tokens import TokenError, issue_token, verify_token
from .webbotauth import VerifyInput, WbaError, WbaResult, verify_web_bot_auth

TOKEN_HEADER = "x-tarelgo-token"  # noqa: S105 - header name, not a secret
BEARER_PREFIX = "bearer "

METRIC_DECISIONS = "tarelgo_captchai_decisions_total"


@dataclass(slots=True)
class Deps:
    """Collaborators and pre-rendered content shared by all routes."""

    settings: Settings
    storage: Storage
    resolver: Any
    logger: Any
    page_a: str
    page_b: str
    robots: str
    llms: str
    ua_list: list[str]
    ja3_known: set[str]


def build_router(deps: Deps) -> APIRouter:
    router = APIRouter()
    settings = deps.settings

    # ---------------------------------------------------------------- helpers

    def ctx_of(request: Request) -> RequestCtx:
        return request.scope["tarelgo_ctx"]

    def score_request(ctx: RequestCtx) -> Score:
        signals = []
        for factory in (
            lambda: ua_ai_signal(ctx.ua, deps.ua_list),
            lambda: no_sec_fetch_signal(ctx.ua, ctx.headers),
            lambda: missing_client_hints_signal(ctx.ua, ctx.headers),
            lambda: header_order_signal(ctx.ua, ctx.header_count()),
            lambda: accept_language_signal(ctx.ua, ctx.headers),
            lambda: accept_html_signal(ctx.ua, ctx.headers),
            lambda: connection_close_signal(ctx.ua, ctx.headers),
            lambda: ja3_scoring_signal(ctx.ja3 or None, deps.ja3_known),
        ):
            hit = factory()
            if hit is not None:
                signals.append(hit)
        return score_signals(signals)

    def record(
        request: Request,
        decision: str,
        reason: str,
        score: Score | None = None,
        status: int = 200,
    ) -> None:
        request.scope["tarelgo_decision"] = {
            "decision": decision,
            "reason": reason,
            "score": score.score if score else None,
            "signals": list(score.signals) if score else [],
        }

    def metrics_inc(decision: str, reason: str) -> None:
        metrics.inc(METRIC_DECISIONS, decision=decision, reason=reason)

    def branch_b_response() -> Response:
        return PlainTextResponse(
            deps.page_b,
            media_type="text/markdown; charset=utf-8",
            headers={**branch_b_headers(), "X-TarelGo-Branch": "B"},
        )

    async def verify_wba(ctx: RequestCtx, body: bytes) -> WbaResult:
        payload = VerifyInput(
            method=ctx.method,
            scheme=ctx.scheme,
            host=ctx.host,
            path=ctx.path,
            query=ctx.query,
            headers=ctx.header_list,
            body=body,
        )
        return await verify_web_bot_auth(payload, deps.resolver, settings)

    def log_wba_failure(exc: WbaError, ctx: RequestCtx) -> None:
        log_event(
            deps.logger, "info", "web-bot-auth verification failed",
            path=ctx.path, reason=exc.reason, detail=exc.detail[:200],
            ip=ctx.client_ip,
        )

    def extract_token(ctx: RequestCtx) -> str:
        auth = ctx.headers.get("authorization", "")
        if auth.lower().startswith(BEARER_PREFIX):
            return auth[len(BEARER_PREFIX):].strip()
        return ctx.headers.get(TOKEN_HEADER, "").strip()

    # ---------------------------------------------------------------- routes

    @router.get("/", response_class=HTMLResponse)
    async def fork(request: Request) -> Response:
        ctx = ctx_of(request)

        # Hard signal first: a valid Web Bot Auth request gets branch B
        # content directly from "/" (a 302 would discard the signature,
        # which covers @path of the original request target).
        if ctx.has_signature_headers:
            try:
                body = await request.body()
            except Exception:  # noqa: BLE001 - body is optional for GET
                body = b""
            try:
                await verify_wba(ctx, body)
                record(request, "B", "web_bot_auth", status=200)
                metrics_inc("B", "web_bot_auth")
                return branch_b_response()
            except WbaError as exc:
                log_wba_failure(exc, ctx)
                metrics_inc("A", f"wba_failed:{exc.reason}")
            except StorageUnavailable:
                # Fail-open: branch A never depends on the storage.
                metrics_inc("A", "wba_storage_down")

        score = score_request(ctx)
        reason = "score_below_threshold" if score.signals else "no_signals"
        record(request, "A", reason, score=score, status=200)
        metrics_inc("A", reason)
        return HTMLResponse(
            deps.page_a,
            headers={
                "X-TarelGo-Branch": "A",
                "Cache-Control": "public, max-age=60",
                'Link': '</llms.txt>; rel="describedby"',
            },
        )

    @router.post("/ai-token")
    async def ai_token(request: Request) -> Response:
        ctx = ctx_of(request)

        if settings.mode == "strict":
            # Strict mode is Web Bot Auth only; the token endpoint does not exist.
            record(request, "A", "mode_strict", status=404)
            metrics_inc("A", "mode_strict")
            return uniform_404()

        try:
            rate = await rate_check(
                deps.storage, settings, SCOPE_AI_TOKEN, ctx.client_ip, ban_on_exceed=True
            )
        except StorageUnavailable:
            record(request, "A", "storage_unavailable", status=503)
            metrics_inc("A", "storage_unavailable")
            return JSONResponse(
                {"detail": "Service temporarily unavailable"},
                status_code=503,
                headers=DENY_HEADERS,
            )
        if not rate.allowed:
            record(request, "A", "rate_limited", status=429)
            metrics_inc("A", "rate_limited")
            response = JSONResponse(
                {"detail": "Too Many Requests"}, status_code=429, headers=DENY_HEADERS
            )
            response.headers["Retry-After"] = str(rate.retry_after)
            return response

        score = score_request(ctx)
        if not should_route_b(score, settings.threshold):
            record(request, "A", "score_below_threshold", score=score, status=403)
            metrics_inc("A", "score_below_threshold")
            return JSONResponse(
                {"detail": "Insufficient evidence of an AI agent"},
                status_code=403,
                headers=DENY_HEADERS,
            )

        bind_ua = ctx.ua if settings.token_bind_ua else ""
        token = issue_token(
            settings.secret_list(), settings.token_ttl, ctx.client_ip, bind_ua, ctx.ja3
        )
        record(request, "B", "token_issued", score=score, status=200)
        metrics_inc("B", "token_issued")
        return JSONResponse(
            {
                "token": token,
                "token_type": "capability",
                "expires_in": settings.token_ttl,
                "usage": "GET /b with Authorization: Bearer <token>",
            },
            headers=DENY_HEADERS,
        )

    @router.get("/b")
    async def branch_b(request: Request) -> Response:
        ctx = ctx_of(request)

        try:
            rate = await rate_check(deps.storage, settings, SCOPE_B, ctx.client_ip)
        except StorageUnavailable:
            # Fail-closed: branch B is shut when the storage is down.
            record(request, "B", "storage_unavailable", status=404)
            metrics_inc("B", "storage_unavailable")
            return uniform_404()
        if not rate.allowed:
            record(request, "B", "rate_limited", status=404)
            metrics_inc("B", "rate_limited")
            return uniform_404()

        if ctx.has_signature_headers:
            try:
                body = await request.body()
            except Exception:  # noqa: BLE001
                body = b""
            try:
                await verify_wba(ctx, body)
                record(request, "B", "web_bot_auth", status=200)
                metrics_inc("B", "web_bot_auth")
                return branch_b_response()
            except WbaError as exc:
                log_wba_failure(exc, ctx)
                record(request, "B", f"wba_{exc.reason}", status=404)
                metrics_inc("B", "wba_failed")
                return uniform_404()
            except StorageUnavailable:
                record(request, "B", "storage_unavailable", status=404)
                metrics_inc("B", "storage_unavailable")
                return uniform_404()

        if settings.mode == "strict":
            record(request, "B", "no_signature", status=404)
            metrics_inc("B", "no_signature")
            return uniform_404()

        token = extract_token(ctx)
        if not token:
            record(request, "B", "missing_token", status=404)
            metrics_inc("B", "missing_token")
            return uniform_404()

        bind_ua = ctx.ua if settings.token_bind_ua else ""
        try:
            data = verify_token(
                token, settings.secret_list(), ctx.client_ip, bind_ua, ctx.ja3
            )
        except TokenError as exc:
            record(request, "B", f"token_{exc.reason}", status=404)
            metrics_inc("B", "token_rejected")
            return uniform_404()

        try:
            used = await deps.storage.mark_token_used(
                data.nonce_hex, utcnow() + timedelta(seconds=settings.token_ttl)
            )
        except StorageUnavailable:
            record(request, "B", "storage_unavailable", status=404)
            metrics_inc("B", "storage_unavailable")
            return uniform_404()
        if not used:
            record(request, "B", "token_replayed", status=404)
            metrics_inc("B", "token_rejected")
            return uniform_404()

        record(request, "B", "token_valid", status=200)
        metrics_inc("B", "token_valid")
        return branch_b_response()

    @router.get("/healthz")
    async def healthz(request: Request) -> Response:
        storage_ok = await deps.storage.ping()
        return JSONResponse(
            {
                "status": "ok",
                "service": TARELGO_SERVICE_NAME,
                "version": __version__,
                "mode": settings.mode,
                "storage": storage_ok,
            },
            headers={"Cache-Control": "no-store"},
        )

    @router.get("/metrics")
    async def metrics_endpoint(request: Request) -> Response:
        ctx = ctx_of(request)
        authorized = ctx.peer_trusted
        if not authorized and settings.metrics_token:
            supplied = ""
            auth = ctx.headers.get("authorization", "")
            if auth.lower().startswith(BEARER_PREFIX):
                supplied = auth[len(BEARER_PREFIX):].strip()
            authorized = bool(supplied) and constant_eq(supplied, settings.metrics_token)
        if settings.metrics_private_only and not authorized:
            return uniform_404()
        return PlainTextResponse(
            metrics.render(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
            headers={"Cache-Control": "no-store"},
        )

    @router.get("/robots.txt")
    async def robots(request: Request) -> Response:
        del request
        return PlainTextResponse(
            deps.robots,
            media_type="text/plain; charset=utf-8",
            headers={"Cache-Control": "public, max-age=3600"},
        )

    @router.get("/llms.txt")
    async def llms(request: Request) -> Response:
        del request
        return PlainTextResponse(
            deps.llms,
            media_type="text/markdown; charset=utf-8",
            headers={"Cache-Control": "public, max-age=3600"},
        )

    return router
