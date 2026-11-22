"""Configuration for TarelGo CaptchAI (pydantic-settings).

Every environment variable uses the TARELGO_CAPTCHAI_ prefix, so the service
can safely share a VPS with any number of other applications. Secrets are
supplied only via environment / systemd EnvironmentFile - never in code or git.
"""

from __future__ import annotations

import base64
from functools import lru_cache
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from . import TARELGO_BRAND_URL, TARELGO_SERVICE_NAME

MIN_SECRET_BYTES = 32


class Settings(BaseSettings):
    """All runtime settings of the TarelGo CaptchAI service."""

    model_config = SettingsConfigDict(
        env_prefix="TARELGO_CAPTCHAI_",
        case_sensitive=False,
        extra="ignore",
    )

    # --- protection mode of branch B ------------------------------------------
    # strict      - branch B opens only with a valid RFC 9421 Web Bot Auth
    #               signature (cryptographic guarantee; no tokens).
    # best_effort - branch B additionally accepts one-shot HMAC tokens
    #               issued at /ai-token after the scoring gate.
    mode: Literal["strict", "best_effort"] = "strict"

    # --- cryptographic secrets -------------------------------------------------
    # Comma-separated list: the FIRST secret is active (token issuance), the
    # rest are previous ones (still accepted during rotation overlap).
    # Each secret is either base64 or an arbitrary ASCII string; after
    # decoding it must be >= 32 bytes.
    secrets: str = ""
    token_ttl: int = 120
    token_bind_ua: bool = True

    # --- database (the only external state of the service) ----------------------
    # Supported schemes:
    #   postgresql://user:pass@127.0.0.1:5432/tarelgo_captchai  (asyncpg)
    #   mysql://user:pass@127.0.0.1:3306/tarelgo_captchai       (aiomysql/MariaDB)
    # An empty DSN requires allow_memory=true (in-memory store, dev/test only).
    db_dsn: str = ""
    allow_memory: bool = False  # dev/test: in-memory storage instead of a DB
    log_retention_days: int = 7

    # --- detection and scoring ---------------------------------------------------
    threshold: int = 3
    ua_ai_list_file: str = ""
    ja3_list_file: str = ""
    ja3_header: str = "X-JA3-Hash"

    # --- rate limiting --------------------------------------------------------------
    ratelimit_ai_token: str = "5/600"   # spec of the TZ: 5 requests per 600 s  # noqa: S105
    ratelimit_b: str = "100/60"         # generous: real agents may retry  # noqa: S105
    ban_seconds: int = 900              # 15 minutes ban after exceeding /ai-token

    # --- proxies -------------------------------------------------------------------
    # nginx -> Apache -> uvicorn, or any other chain: X-Forwarded-For is
    # trusted only when the direct peer matches one of these networks.
    trusted_proxies: str = "127.0.0.1/32,::1/128"

    # --- Web Bot Auth ---------------------------------------------------------------
    wba_max_age: int = 600           # maximum signature age, seconds
    wba_clock_skew: int = 5          # allowed clock drift, seconds
    wba_require_method_path: bool = True   # require @method + @path coverage
    wba_require_agent: bool = True   # require the Signature-Agent header (RFC MUST)
    wba_directory_ttl: int = 3600    # agent key cache TTL, seconds (1 hour)
    wba_negative_ttl: int = 600      # negative cache TTL, seconds
    wba_fetch_timeout: float = 2.0   # directory fetch timeout, seconds
    wba_max_dir_bytes: int = 65536   # maximum directory size, bytes (64 KiB)
    # Override for the @authority reconstruction when the proxy chain rewrites
    # the Host header (e.g. "tarelgo.com"). Empty = use the Host header as-is.
    public_authority: str = ""
    # SSRF guard: never disable in production (test fixture only).
    wba_allow_private_keyhost: bool = False

    # --- service ------------------------------------------------------------------------
    bind_host: str = "127.0.0.1"     # behind a proxy; use 0.0.0.0 only for direct mode
    bind_port: int = 8008            # internal port on the shared VPS
    log_level: str = "INFO"
    brand_url: str = TARELGO_BRAND_URL
    service_name: str = TARELGO_SERVICE_NAME
    # Optional external files overriding built-in branch A / branch B content.
    content_a_file: str = ""
    content_b_file: str = ""
    metrics_private_only: bool = True
    metrics_token: str = ""

    # ------------------------------------------------------------------ validation

    @field_validator("secrets")
    @classmethod
    def _validate_secrets(cls, value: str) -> str:
        secrets = cls.parse_secrets(value)
        if not secrets:
            raise ValueError(
                "TARELGO_CAPTCHAI_SECRETS: provide at least one secret of "
                ">= 32 bytes (base64 or arbitrary string)"
            )
        return value

    @field_validator("threshold")
    @classmethod
    def _validate_threshold(cls, value: int) -> int:
        if not 1 <= value <= 8:
            raise ValueError("threshold must be in the range 1..8")
        return value

    # ------------------------------------------------------------------- helpers

    @staticmethod
    def parse_secrets(raw: str) -> list[bytes]:
        """Parse the comma-separated secret list; first item is the active one."""
        out: list[bytes] = []
        for part in (raw or "").split(","):
            part = part.strip()
            if not part:
                continue
            try:
                decoded = base64.b64decode(part, validate=True)
                if len(decoded) >= MIN_SECRET_BYTES:
                    out.append(decoded)
                    continue
            except Exception:  # noqa: BLE001, S110 - not base64, fall back to ASCII
                pass
            out.append(part.encode("utf-8"))
        if any(len(secret) < MIN_SECRET_BYTES for secret in out):
            raise ValueError("every TarelGo CaptchAI secret must be >= 32 bytes")
        return out

    def secret_list(self) -> list[bytes]:
        return self.parse_secrets(self.secrets)

    @staticmethod
    def parse_ratelimit(spec: str) -> tuple[int, int]:
        """'5/600' -> (5, 600): at most 5 requests per 600 seconds."""
        try:
            limit_s, window_s = spec.split("/")
            limit, window = int(limit_s), int(window_s)
            if limit <= 0 or window <= 0:
                raise ValueError
            return limit, window
        except ValueError as exc:
            raise ValueError(
                f"invalid rate limit format '{spec}', expected 'N/seconds'"
            ) from exc

    def ratelimit_ai_token_tuple(self) -> tuple[int, int]:
        return self.parse_ratelimit(self.ratelimit_ai_token)

    def ratelimit_b_tuple(self) -> tuple[int, int]:
        return self.parse_ratelimit(self.ratelimit_b)

    def trusted_proxy_networks(self) -> list:
        import ipaddress

        networks = []
        for part in (self.trusted_proxies or "").split(","):
            part = part.strip()
            if part:
                networks.append(ipaddress.ip_network(part, strict=False))
        return networks


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings instance loaded from the environment (prod entrypoint)."""
    return Settings()
