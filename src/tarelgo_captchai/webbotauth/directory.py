"""Fetching public keys of AI agents for TarelGo CaptchAI.

Formats (current web-bot-auth protocol):
  - Signature-Agent: SF-Dictionary `sig1="https://agent.example/card";type=cimd`
    -> a CIMD agent card (JSON with jwks or jwks_uri);
  - legacy: `Signature-Agent: "https://agent.example"` -> the directory at
    https://agent.example/.well-known/http-message-signatures-directory;
  - keyid as a URI (older draft): the origin of the same directory.

Security (spec 10.4): https only, private IPs blocked, 2 s timeout, 64 KiB
size limit, PostgreSQL/MariaDB cache (TTL 1 hour) plus a negative cache.
The known DNS-rebinding TOCTOU gap is mitigated by an optional agent-domain
allowlist (see README); ideally an egress proxy is used.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from ..config import Settings
from ..security import is_private_ip
from ..storage import Storage, utcnow
from .keys import select_jwk

DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"
MAX_REDIRECTS = 2


class AgentKeyError(Exception):
    """Could not obtain a suitable agent key."""


@dataclass(slots=True)
class AgentEntry:
    label: str
    uri: str
    cimd: bool = False


@dataclass(slots=True)
class ResolvedKey:
    jwk: dict[str, Any]
    agent_uri: str
    source: str


class AgentKeyResolver:
    def __init__(
        self,
        storage: Storage,
        settings: Settings,
        client_factory: Callable[[], httpx.Client] | None = None,
    ) -> None:
        self._storage = storage
        self._settings = settings

        def _default_factory() -> httpx.Client:
            return httpx.Client(
                timeout=settings.wba_fetch_timeout,
                follow_redirects=False,
                headers={
                    "accept": (
                        "application/http-message-signatures-directory+json, "
                        "application/json"
                    ),
                    "user-agent": f"TarelGo-CaptchAI/1.0 (+{settings.brand_url})",
                },
            )

        self._client_factory = client_factory or _default_factory

    async def resolve(self, entries: list[AgentEntry], keyid: str) -> ResolvedKey:
        candidates = list(entries)
        if not candidates:
            # no Signature-Agent: keyid in URI format (older draft)
            origin = self._keyid_origin(keyid)
            if origin:
                candidates = [AgentEntry(label="", uri=origin)]
        errors: list[str] = []
        for entry in candidates:
            try:
                jwks, source = await self._jwks_for(entry)
            except AgentKeyError as exc:
                errors.append(str(exc))
                continue
            jwk = select_jwk(jwks, keyid)
            if jwk is not None:
                return ResolvedKey(jwk=jwk, agent_uri=entry.uri, source=source)
            errors.append(f"{entry.uri}: key {keyid[:12]}... not found")
        raise AgentKeyError("; ".join(errors) or "no key sources")

    # ------------------------------------------------------------------ fetch

    def _keyid_origin(self, keyid: str) -> str | None:
        if not keyid.startswith("https://"):
            return None
        parts = urlsplit(keyid)
        return f"{parts.scheme}://{parts.netloc}"

    async def _jwks_for(self, entry: AgentEntry) -> tuple[dict[str, Any], str]:
        if entry.cimd:
            cache_key = f"cimd:{entry.uri}"
        else:
            origin = self._entry_origin(entry.uri)
            cache_key = f"dir:{origin}"

        cached = await self._storage.jwks_get(cache_key)
        if cached is not None:
            jwks_json, fetched_at = cached
            age = utcnow().timestamp() - fetched_at.timestamp()
            if age <= self._settings.wba_directory_ttl:
                return json.loads(jwks_json), cache_key
        neg = await self._storage.jwks_negative_get(cache_key)
        if neg is not None:
            age = utcnow().timestamp() - neg.timestamp()
            if age <= self._settings.wba_negative_ttl:
                raise AgentKeyError(f"{cache_key}: recently failed (negative cache)")

        try:
            if entry.cimd:
                jwks, source = await self._fetch_cimd(entry.uri)
            else:
                origin = self._entry_origin(entry.uri)
                url = origin + DIRECTORY_PATH
                body = await self._guarded_fetch(url)
                jwks, source = json.loads(body.decode("utf-8")), url
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            await self._storage.jwks_negative_put(
                cache_key, self._settings.wba_negative_ttl
            )
            raise AgentKeyError(f"{entry.uri}: directory is not JSON") from exc
        except AgentKeyError:
            await self._storage.jwks_negative_put(
                cache_key, self._settings.wba_negative_ttl
            )
            raise
        except Exception as exc:  # noqa: BLE001
            await self._storage.jwks_negative_put(
                cache_key, self._settings.wba_negative_ttl
            )
            raise AgentKeyError(
                f"{entry.uri}: fetch failed ({type(exc).__name__})"
            ) from exc

        await self._storage.jwks_put(
            cache_key, json.dumps(jwks, separators=(",", ":")), self._settings.wba_directory_ttl
        )
        return jwks, source

    def _entry_origin(self, uri: str) -> str:
        parts = urlsplit(uri)
        if parts.scheme != "https" or not parts.netloc:
            raise AgentKeyError("the agent URI must be https")
        return f"{parts.scheme}://{parts.netloc}"

    async def _fetch_cimd(self, uri: str) -> tuple[dict[str, Any], str]:
        body = await self._guarded_fetch(uri)
        card = json.loads(body.decode("utf-8"))
        if not isinstance(card, dict):
            raise AgentKeyError("the CIMD card is not an object")
        inline = card.get("jwks")
        if isinstance(inline, dict) and isinstance(inline.get("keys"), list):
            return inline, uri
        jwks_uri = card.get("jwks_uri")
        if isinstance(jwks_uri, str):
            jwks_body = await self._guarded_fetch(jwks_uri)
            return json.loads(jwks_body.decode("utf-8")), jwks_uri
        raise AgentKeyError("the CIMD card has neither jwks nor jwks_uri")

    async def _guarded_fetch(self, url: str) -> bytes:
        """HTTPS GET with SSRF protection, size limit and manual redirects."""
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            await self._guard_url(current)
            body, status, location = await self._http_get(current)
            if status in (301, 302, 303, 307, 308):
                if not location:
                    raise AgentKeyError("redirect without Location")
                current = str(httpx.URL(current).join(location))
                continue
            if status != 200:
                raise AgentKeyError(f"HTTP {status} for {current}")
            return body
        raise AgentKeyError("too many redirects")

    async def _http_get(self, url: str) -> tuple[bytes, int, str | None]:
        import anyio

        client_factory = self._client_factory

        def _fetch() -> tuple[bytes, int, str | None]:
            with client_factory() as client:
                with client.stream("GET", url) as response:
                    if response.headers.get("content-length") and int(
                        response.headers["content-length"]
                    ) > self._settings.wba_max_dir_bytes:
                        raise AgentKeyError("directory exceeds the 64 KiB limit")
                    chunks: list[bytes] = []
                    total = 0
                    for chunk in response.iter_bytes():
                        total += len(chunk)
                        if total > self._settings.wba_max_dir_bytes:
                            raise AgentKeyError("directory exceeds the 64 KiB limit")
                        chunks.append(chunk)
                    return (
                        b"".join(chunks),
                        response.status_code,
                        response.headers.get("location"),
                    )

        return await anyio.to_thread.run_sync(_fetch)

    async def _guard_url(self, url: str) -> None:
        parts = urlsplit(url)
        if parts.scheme != "https":
            raise AgentKeyError("only https URLs are allowed")
        hostname = parts.hostname
        if not hostname:
            raise AgentKeyError("no hostname")
        if self._settings.wba_allow_private_keyhost:
            return  # tests only
        import anyio

        def _resolve() -> list[str]:
            import socket

            infos = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
            return [info[4][0] for info in infos]

        try:
            addrs = await anyio.to_thread.run_sync(_resolve)
        except OSError as exc:
            raise AgentKeyError(f"DNS resolution of {hostname} failed") from exc
        if not addrs:
            raise AgentKeyError(f"empty DNS answer for {hostname}")
        for addr in addrs:
            if is_private_ip(addr):
                raise AgentKeyError(
                    f"{hostname} resolves to a private IP (SSRF protection)"
                )
