"""Application factory of TarelGo CaptchAI.

The outer middleware resolves the request context once (client IP, UA hash,
JA3, trusted-peer check), then measures latency and emits the decision log
line plus Prometheus metrics for every response. Expected errors are handled
inside the routes; anything unexpected becomes a bare 500 without leaking
internals.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from . import TARELGO_SERVICE_NAME, __version__
from .config import Settings, get_settings
from .content import llms_txt, page_a_html, page_b_markdown, robots_txt
from .detect import load_ja3_list, load_ua_list
from .logging import log_event, setup_logging
from .metrics import metrics
from .router import METRIC_DECISIONS, Deps, build_router
from .security import DENY_HEADERS, build_request_ctx
from .storage import Storage, StorageUnavailable, create_storage
from .webbotauth.directory import AgentKeyResolver

KNOWN_PATHS = {
    "/",
    "/b",
    "/ai-token",
    "/healthz",
    "/metrics",
    "/robots.txt",
    "/llms.txt",
}

METRIC_LATENCY = "tarelgo_captchai_request_latency_ms"


def _route_label(path: str) -> str:
    return path if path in KNOWN_PATHS else "other"


class ContextMiddleware:
    """Pure-ASGI middleware: context -> timing -> decision log -> metrics."""

    def __init__(self, app: Any, deps: Deps) -> None:
        self.app = app
        self.deps = deps

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        settings = self.deps.settings
        ctx = build_request_ctx(scope, settings)
        scope["tarelgo_ctx"] = ctx

        started = time.perf_counter()
        state = {"status": 500, "started": False}

        async def send_wrapper(message: dict) -> None:
            if message["type"] == "http.response.start":
                state["status"] = message["status"]
                state["started"] = True
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception as exc:  # noqa: BLE001 - last-resort guard
            log_event(
                self.deps.logger, "error", "unhandled exception",
                error=type(exc).__name__, path=ctx.path,
            )
            if not state["started"]:
                try:
                    response = JSONResponse(
                        {"detail": "Internal Server Error"},
                        status_code=500,
                        headers=DENY_HEADERS,
                    )
                    await response(scope, receive, send)
                except Exception:  # noqa: BLE001, S110 - response already started
                    pass
        finally:
            latency_ms = (time.perf_counter() - started) * 1000.0
            self._finalize(scope, ctx, state["status"], latency_ms)

    def _finalize(
        self, scope: dict, ctx: Any, status: int, latency_ms: float
    ) -> None:
        decision = scope.get("tarelgo_decision") or {}
        route = _route_label(ctx.path)
        reason = str(decision.get("reason") or "unhandled")

        metrics.observe_latency_ms(route, latency_ms)
        metrics.inc(
            METRIC_DECISIONS,
            decision=str(decision.get("decision") or "A"),
            reason=reason,
        )
        log_event(
            self.deps.logger,
            "info",
            "decision",
            ip=ctx.client_ip,
            method=ctx.method,
            path=ctx.path,
            decision=str(decision.get("decision") or "A"),
            reason=reason,
            score=decision.get("score"),
            signals=decision.get("signals") or [],
            ja3=ctx.ja3 or None,
            ua_sha256=ctx.ua_sha256,
            status=status,
            latency_ms=round(latency_ms, 2),
        )
        self._persist(scope, ctx, decision, status, latency_ms)

    def _persist(
        self, scope: dict, ctx: Any, decision: dict, status: int, latency_ms: float
    ) -> None:
        storage = self.deps.storage
        row = {
            "ip": ctx.client_ip,
            "method": ctx.method,
            "path": ctx.path,
            "decision": str(decision.get("decision") or "A"),
            "reason": str(decision.get("reason") or "unhandled"),
            "score": decision.get("score"),
            "signals": list(decision.get("signals") or []),
            "ja3": ctx.ja3 or None,
            "ua_sha256": ctx.ua_sha256,
            "status": status,
            "latency_ms": int(round(latency_ms)),
        }

        async def _insert() -> None:
            try:
                await storage.decisions_insert([row])
            except StorageUnavailable:
                log_event(
                    self.deps.logger, "warning", "decision journal insert failed",
                    path=row["path"],
                )

        try:
            asyncio.get_running_loop().create_task(_insert())
        except RuntimeError:  # pragma: no cover - no loop in exotic runners
            pass


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    deps: Deps = app.state.tg_deps
    connected = await deps.storage.connect(retries=2, delay_s=1.0)
    await deps.storage.ensure_schema()
    log_event(
        deps.logger, "info", "service started",
        mode=deps.settings.mode, storage_connected=connected,
        service=TARELGO_SERVICE_NAME, version=__version__,
    )

    async def _cleanup_loop() -> None:
        while True:
            await asyncio.sleep(3600)
            try:
                await deps.storage.cleanup(deps.settings.log_retention_days)
            except StorageUnavailable:
                log_event(deps.logger, "warning", "cleanup skipped: storage down")

    task = asyncio.create_task(_cleanup_loop())
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001, S110 - shutdown
            pass
        await deps.storage.close()
        log_event(deps.logger, "info", "service stopped")


def create_app(
    settings: Settings | None = None,
    storage: Storage | None = None,
) -> FastAPI:
    """Build the ASGI application. Tests may inject their own storage."""
    settings = settings or get_settings()
    logger = setup_logging(settings.log_level)
    storage = storage or create_storage(settings.db_dsn, settings.allow_memory)
    resolver = AgentKeyResolver(storage, settings)

    deps = Deps(
        settings=settings,
        storage=storage,
        resolver=resolver,
        logger=logger,
        page_a=page_a_html(settings),
        page_b=page_b_markdown(settings),
        robots=robots_txt(settings),
        llms=llms_txt(settings),
        ua_list=load_ua_list(settings.ua_ai_list_file),
        ja3_known=load_ja3_list(settings.ja3_list_file),
    )

    app = FastAPI(
        title=TARELGO_SERVICE_NAME,
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.tg_deps = deps
    app.include_router(build_router(deps))
    app.add_middleware(ContextMiddleware, deps=deps)
    return app
