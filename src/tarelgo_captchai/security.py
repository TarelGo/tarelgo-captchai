"""Security primitives of TarelGo CaptchAI: client IP, constant-time
comparisons, the uniform 404 response and the request context.

Spec requirements (section 10): identical body and status for every branch B
rejection (no oracle), HMAC comparison strictly via hmac.compare_digest, and
X-Forwarded-For honored only from trusted proxies (nginx -> Apache -> uvicorn,
or any other chain).
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from starlette.responses import JSONResponse, Response

from .detect.ja3 import parse_ja3

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .config import Settings

DENY_HEADERS = {
    "Cache-Control": "private, no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
}

SIGNATURE_HEADERS = ("signature", "signature-input")


def constant_eq(a: str | bytes, b: str | bytes) -> bool:
    """Constant-time string comparison (HMACs, tokens, metrics token)."""
    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")
    return hmac.compare_digest(a, b)


def ua_hash(ua: str) -> str:
    """SHA-256 of the User-Agent; the raw UA is never stored or logged."""
    return hashlib.sha256((ua or "").encode("utf-8")).hexdigest()


def is_private_ip(ip: str) -> bool:
    """Private/loopback/reserved address (SSRF guard for directory fetches)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparsable -> treat as dangerous (fail-closed)
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def resolve_client_ip(
    remote_addr: str,
    forwarded_for: Iterable[str] | None,
    trusted_networks: list[ipaddress.ip_network],
) -> str:
    """Extract the real client IP.

    Chain example: nginx (sets XFF) -> Apache (appends to XFF) -> uvicorn.
    Walk X-Forwarded-For from RIGHT to LEFT skipping trusted proxies; the
    first untrusted address is the client. If the direct peer is not trusted,
    the peer itself wins and XFF is ignored (spoof-proof).
    """
    if forwarded_for:
        chain = [v.strip() for v in forwarded_for if v.strip()]
        for candidate in reversed(chain):
            try:
                addr = ipaddress.ip_address(candidate)
            except ValueError:
                return remote_addr
            if any(addr in net for net in trusted_networks):
                continue
            return candidate
        # The whole chain is trusted - the client is hidden behind proxies.
        if chain:
            return chain[0]
    return remote_addr


def uniform_404() -> Response:
    """Uniform branch B rejection: 404, identical body, identical headers.

    Not 401/403 - never reveal that the endpoint exists (spec section 6.3).
    """
    return JSONResponse({"detail": "Not Found"}, status_code=404, headers=DENY_HEADERS)


def branch_b_headers() -> dict[str, str]:
    """Headers of a successful branch B response (spec sections 6.3 and 10)."""
    return {
        "Cache-Control": "private, no-store",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "X-Robots-Tag": "noindex, nofollow",
    }


@dataclass(slots=True)
class RequestCtx:
    """Per-request context resolved once in the outermost middleware."""

    peer: str                      # direct TCP peer (proxy or client)
    client_ip: str                 # resolved client IP (XFF-aware)
    peer_trusted: bool             # peer matches TARELGO_CAPTCHAI_TRUSTED_PROXIES
    ua: str                        # raw User-Agent (hash-only downstream)
    ua_sha256: str
    ja3: str                       # TLS fingerprint hash, empty if unavailable
    method: str
    path: str                      # raw path, percent-encoding preserved
    query: str                     # raw query string without '?'
    scheme: str                    # http/https (X-Forwarded-Proto aware)
    host: str                      # Host header (public authority when proxied)
    header_list: list[tuple[str, str]] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)  # lower name -> first value

    @property
    def has_signature_headers(self) -> bool:
        return bool(self.headers.get("signature-input")) and bool(
            self.headers.get("signature")
        )

    def header_count(self) -> int:
        return len(self.header_list)


def build_request_ctx(scope, settings: Settings) -> RequestCtx:
    """Build the context from an ASGI scope (no body access)."""
    headers_list = [
        (k.decode("latin-1"), v.decode("latin-1")) for k, v in scope.get("headers") or []
    ]
    headers_map: dict[str, str] = {}
    forwarded: list[str] = []
    proto = ""
    for name, value in headers_list:
        lowered = name.lower()
        headers_map.setdefault(lowered, value)
        if lowered == "x-forwarded-for":
            forwarded.extend(v.strip() for v in value.split(","))
        elif lowered == "x-forwarded-proto" and not proto:
            proto = value.strip().lower()

    client = scope.get("client")
    peer = client[0] if client else ""
    networks = settings.trusted_proxy_networks()
    peer_trusted = False
    try:
        peer_trusted = bool(peer) and any(
            ipaddress.ip_address(peer) in net for net in networks
        )
    except ValueError:
        peer_trusted = False

    # Forwarded headers are honored only when the direct peer is trusted;
    # otherwise XFF is ignored completely (spoof-proof by construction).
    client_ip = (
        resolve_client_ip(peer, forwarded, networks)
        if peer_trusted
        else (peer or "unknown")
    )
    scheme = proto if peer_trusted and proto else str(scope.get("scheme") or "http")

    raw_path = scope.get("raw_path") or scope.get("path") or b"/"
    path = raw_path.decode("latin-1") if isinstance(raw_path, bytes) else str(raw_path)
    query_raw = scope.get("query_string") or b""
    query = query_raw.decode("latin-1") if isinstance(query_raw, bytes) else str(query_raw)

    # JA3 reaches us only if a TLS terminator injects it (direct-uvicorn mode
    # cannot see TLS fingerprints; the signal then stays gracefully disabled).
    ja3 = parse_ja3(headers_map.get(settings.ja3_header.lower())) or ""

    return RequestCtx(
        peer=peer,
        client_ip=client_ip,
        peer_trusted=peer_trusted,
        ua=headers_map.get("user-agent", ""),
        ua_sha256=ua_hash(headers_map.get("user-agent", "")),
        ja3=ja3,
        method=str(scope.get("method") or "GET").upper(),
        path=path or "/",
        query=query,
        scheme=scheme,
        host=headers_map.get("host", ""),
        header_list=headers_list,
        headers=headers_map,
    )
