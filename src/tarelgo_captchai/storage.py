"""State storage for TarelGo CaptchAI.

The service keeps exactly one kind of external state - a small SQL database:

  PostgresStorage - production on PostgreSQL (asyncpg pool, atomic upserts).
  MariaDbStorage  - production on MariaDB/MySQL (aiomysql pool, same semantics).
  MemoryStorage   - identical semantics in RAM; dev/test ONLY, enabled
                    explicitly via TARELGO_CAPTCHAI_ALLOW_MEMORY=true.

The DSN scheme in TARELGO_CAPTCHAI_DB_DSN selects the backend:
  postgresql://user:pass@host:5432/tarelgo_captchai
  mysql://user:pass@host:3306/tarelgo_captchai

Fail modes (spec section 11): branch A never depends on the storage
(fail-open); branch B is closed when the storage is unavailable (fail-closed).

All table names carry the TarelGo brand: tarelgo_*.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import unquote, urlsplit

from .logging import log_event


class StorageUnavailable(Exception):
    """Storage unreachable. Branch A keeps working; branch B is closed."""


def utcnow() -> datetime:
    return datetime.now(UTC)


def _naive_utc(value: datetime) -> datetime:
    """MariaDB TIMESTAMP columns are tz-naive; always store UTC-naive."""
    if value.tzinfo is None:
        return value
    return value.astimezone(UTC).replace(tzinfo=None)


def _aware_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _logger():  # type: ignore[no-untyped-def]
    import logging

    return logging.getLogger("tarelgo.captchai")


@dataclass(slots=True)
class RateVerdict:
    allowed: bool
    hits: int
    window_start: datetime


class Storage:
    """Common storage interface of TarelGo CaptchAI."""

    async def connect(self, retries: int = 0, delay_s: float = 2.0) -> bool:  # noqa: D417
        """Establish the pool; retries=0 - single attempt, else retry loop."""
        raise NotImplementedError

    async def close(self) -> None:
        raise NotImplementedError

    async def ping(self) -> bool:
        raise NotImplementedError

    async def ensure_schema(self) -> None:
        raise NotImplementedError

    # --- one-shot tokens -------------------------------------------------------
    async def mark_token_used(self, nonce: str, expires_at: datetime) -> bool:
        raise NotImplementedError

    # --- rate limiting -----------------------------------------------------------
    async def rate_hit(self, scope: str, subject: str, limit: int, window_s: int) -> RateVerdict:
        raise NotImplementedError

    async def ban_remaining(self, scope: str, subject: str) -> int:
        raise NotImplementedError

    async def ban_set(self, scope: str, subject: str, seconds: int) -> None:
        raise NotImplementedError

    # --- agent public key cache (Web Bot Auth) ------------------------------------
    async def jwks_get(self, cache_key: str) -> tuple[str, datetime] | None:
        raise NotImplementedError

    async def jwks_put(self, cache_key: str, jwks_json: str, ttl_s: int) -> None:
        raise NotImplementedError

    async def jwks_negative_get(self, cache_key: str) -> datetime | None:
        raise NotImplementedError

    async def jwks_negative_put(self, cache_key: str, ttl_s: int) -> None:
        raise NotImplementedError

    # --- decision journal ------------------------------------------------------------
    async def decisions_insert(self, rows: Sequence[dict[str, Any]]) -> int:
        raise NotImplementedError

    async def cleanup(self, retention_days: int) -> None:
        raise NotImplementedError


# --------------------------------------------------------------------------- #
#                              Schema definitions                              #
# --------------------------------------------------------------------------- #

SCHEMA_SQL_POSTGRES = """
CREATE TABLE IF NOT EXISTS tarelgo_used_tokens (
    nonce      TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS tarelgo_rate_windows (
    scope        TEXT        NOT NULL,
    subject      TEXT        NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    hits         BIGINT      NOT NULL DEFAULT 1,
    PRIMARY KEY (scope, subject, window_start)
);
CREATE TABLE IF NOT EXISTS tarelgo_rate_bans (
    scope   TEXT        NOT NULL,
    subject TEXT        NOT NULL,
    until   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (scope, subject)
);
CREATE TABLE IF NOT EXISTS tarelgo_agent_keys (
    cache_key  TEXT PRIMARY KEY,
    jwks       JSONB     NOT NULL,
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS tarelgo_agent_keys_negative (
    cache_key  TEXT PRIMARY KEY,
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS tarelgo_decisions (
    id         BIGSERIAL PRIMARY KEY,
    ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
    ip         TEXT,
    method     TEXT,
    path       TEXT,
    decision   TEXT,
    reason     TEXT,
    score      INTEGER,
    signals    TEXT[],
    ja3        TEXT,
    ua_sha256  TEXT,
    status     INTEGER,
    latency_ms INTEGER
);
CREATE INDEX IF NOT EXISTS tarelgo_decisions_ts_idx ON tarelgo_decisions (ts);
"""

SCHEMA_SQL_MARIADB = """
CREATE TABLE IF NOT EXISTS tarelgo_used_tokens (
    nonce      VARCHAR(128) PRIMARY KEY,
    expires_at TIMESTAMP(6) NOT NULL,
    used_at    TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
);
CREATE TABLE IF NOT EXISTS tarelgo_rate_windows (
    scope        VARCHAR(64)  NOT NULL,
    subject      VARCHAR(255) NOT NULL,
    window_start TIMESTAMP(6) NOT NULL,
    hits         BIGINT       NOT NULL DEFAULT 1,
    PRIMARY KEY (scope, subject, window_start)
);
CREATE TABLE IF NOT EXISTS tarelgo_rate_bans (
    scope   VARCHAR(64)  NOT NULL,
    subject VARCHAR(255) NOT NULL,
    until   TIMESTAMP(6) NOT NULL,
    PRIMARY KEY (scope, subject)
);
CREATE TABLE IF NOT EXISTS tarelgo_agent_keys (
    cache_key  VARCHAR(255) PRIMARY KEY,
    jwks       MEDIUMTEXT   NOT NULL,
    fetched_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
);
CREATE TABLE IF NOT EXISTS tarelgo_agent_keys_negative (
    cache_key  VARCHAR(255) PRIMARY KEY,
    fetched_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
);
CREATE TABLE IF NOT EXISTS tarelgo_decisions (
    id         BIGINT       NOT NULL AUTO_INCREMENT,
    ts         TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    ip         VARCHAR(64),
    method     VARCHAR(16),
    path       VARCHAR(512),
    decision   VARCHAR(8),
    reason     VARCHAR(64),
    score      INT,
    signals    TEXT,
    ja3        VARCHAR(64),
    ua_sha256  VARCHAR(64),
    status     INT,
    latency_ms INT,
    PRIMARY KEY (id),
    KEY tarelgo_decisions_ts_idx (ts)
);
"""


def _split_schema_sql(sql: str) -> list[str]:
    """Split a multi-statement schema script into individual statements."""
    return [chunk.strip() for chunk in sql.split(";") if chunk.strip()]


# --------------------------------------------------------------------------- #
#                                PostgreSQL                                    #
# --------------------------------------------------------------------------- #


class PostgresStorage(Storage):
    """Production storage on asyncpg. All operations are atomic server-side."""

    def __init__(self, dsn: str, min_size: int = 1, max_size: int = 10) -> None:
        self._dsn = dsn
        self._pool: Any = None
        self._min_size = min_size
        self._max_size = max_size

    async def connect(self, retries: int = 0, delay_s: float = 2.0) -> bool:
        attempts = retries + 1
        for attempt in range(attempts):
            try:
                if self._pool is None:
                    import asyncpg

                    self._pool = await asyncpg.create_pool(
                        self._dsn,
                        min_size=self._min_size,
                        max_size=self._max_size,
                        command_timeout=2,
                        timeout=2,
                    )
                else:
                    await self._pool.execute("SELECT 1")
                return True
            except Exception as exc:  # noqa: BLE001
                if attempt + 1 >= attempts:
                    log_event(
                        _logger(), "warning", "storage: PostgreSQL unreachable",
                        error=type(exc).__name__,
                    )
                    return False
                await asyncio.sleep(delay_s)
        return False

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    def _acquire(self):  # type: ignore[no-untyped-def]
        if self._pool is None:
            raise StorageUnavailable("postgres pool is not created")
        return self._pool

    def _wrap(self, exc: Exception) -> StorageUnavailable:
        return StorageUnavailable(f"PostgreSQL: {type(exc).__name__}")

    async def ping(self) -> bool:
        try:
            await self._acquire().execute("SELECT 1")
            return True
        except StorageUnavailable:
            return False
        except Exception:  # noqa: BLE001
            return False

    async def ensure_schema(self) -> None:
        try:
            await self._acquire().execute(SCHEMA_SQL_POSTGRES)
        except Exception as exc:  # noqa: BLE001
            raise self._wrap(exc) from exc

    async def mark_token_used(self, nonce: str, expires_at: datetime) -> bool:
        sql = (
            "INSERT INTO tarelgo_used_tokens (nonce, expires_at) VALUES ($1, $2) "
            "ON CONFLICT (nonce) DO NOTHING RETURNING nonce"
        )
        try:
            row = await self._acquire().fetchval(sql, nonce, expires_at)
        except Exception as exc:  # noqa: BLE001
            raise self._wrap(exc) from exc
        return row is not None

    async def rate_hit(self, scope: str, subject: str, limit: int, window_s: int) -> RateVerdict:
        now = utcnow()
        window_start = datetime.fromtimestamp(
            now.timestamp() - (now.timestamp() % window_s), tz=UTC
        )
        sql = (
            "INSERT INTO tarelgo_rate_windows (scope, subject, window_start, hits) "
            "VALUES ($1, $2, $3, 1) "
            "ON CONFLICT (scope, subject, window_start) "
            "DO UPDATE SET hits = tarelgo_rate_windows.hits + 1 "
            "RETURNING hits"
        )
        try:
            hits = await self._acquire().fetchval(sql, scope, subject, window_start)
        except Exception as exc:  # noqa: BLE001
            raise self._wrap(exc) from exc
        return RateVerdict(
            allowed=int(hits) <= limit, hits=int(hits), window_start=window_start
        )

    async def ban_remaining(self, scope: str, subject: str) -> int:
        sql = (
            "SELECT until FROM tarelgo_rate_bans "
            "WHERE scope=$1 AND subject=$2 AND until > now()"
        )
        try:
            row = await self._acquire().fetchval(sql, scope, subject)
        except Exception as exc:  # noqa: BLE001
            raise self._wrap(exc) from exc
        if row is None:
            return 0
        return max(0, int((_aware_utc(row) - utcnow()).total_seconds()))

    async def ban_set(self, scope: str, subject: str, seconds: int) -> None:
        until = utcnow() + timedelta(seconds=seconds)
        sql = (
            "INSERT INTO tarelgo_rate_bans (scope, subject, until) VALUES ($1, $2, $3) "
            "ON CONFLICT (scope, subject) DO UPDATE SET until = EXCLUDED.until"
        )
        try:
            await self._acquire().execute(sql, scope, subject, until)
        except Exception as exc:  # noqa: BLE001
            raise self._wrap(exc) from exc

    async def jwks_get(self, cache_key: str) -> tuple[str, datetime] | None:
        sql = "SELECT jwks, fetched_at FROM tarelgo_agent_keys WHERE cache_key=$1"
        try:
            row = await self._acquire().fetchrow(sql, cache_key)
        except Exception as exc:  # noqa: BLE001
            raise self._wrap(exc) from exc
        if row is None:
            return None
        return str(row["jwks"]), _aware_utc(row["fetched_at"])

    async def jwks_put(self, cache_key: str, jwks_json: str, ttl_s: int) -> None:
        del ttl_s  # TTL is applied on read (fetched_at + ttl)
        sql = (
            "INSERT INTO tarelgo_agent_keys (cache_key, jwks, fetched_at) "
            "VALUES ($1, $2::jsonb, now()) "
            "ON CONFLICT (cache_key) DO UPDATE SET jwks = EXCLUDED.jwks, "
            "fetched_at = now()"
        )
        try:
            await self._acquire().execute(sql, cache_key, jwks_json)
        except Exception as exc:  # noqa: BLE001
            raise self._wrap(exc) from exc

    async def jwks_negative_get(self, cache_key: str) -> datetime | None:
        sql = "SELECT fetched_at FROM tarelgo_agent_keys_negative WHERE cache_key=$1"
        try:
            row = await self._acquire().fetchval(sql, cache_key)
        except Exception as exc:  # noqa: BLE001
            raise self._wrap(exc) from exc
        return _aware_utc(row) if row is not None else None

    async def jwks_negative_put(self, cache_key: str, ttl_s: int) -> None:
        del ttl_s
        sql = (
            "INSERT INTO tarelgo_agent_keys_negative (cache_key, fetched_at) "
            "VALUES ($1, now()) ON CONFLICT (cache_key) DO UPDATE SET fetched_at = now()"
        )
        try:
            await self._acquire().execute(sql, cache_key)
        except Exception as exc:  # noqa: BLE001
            raise self._wrap(exc) from exc

    async def decisions_insert(self, rows: Sequence[dict[str, Any]]) -> int:
        if not rows:
            return 0
        sql = (
            "INSERT INTO tarelgo_decisions "
            "(ip, method, path, decision, reason, score, signals, ja3, ua_sha256, "
            " status, latency_ms) "
            "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)"
        )
        data = [
            (
                r.get("ip"), r.get("method"), r.get("path"), r.get("decision"),
                r.get("reason"), r.get("score"), list(r.get("signals") or []),
                r.get("ja3"), r.get("ua_sha256"), r.get("status"), r.get("latency_ms"),
            )
            for r in rows
        ]
        try:
            await self._acquire().executemany(sql, data)
        except Exception as exc:  # noqa: BLE001
            raise self._wrap(exc) from exc
        return len(data)

    async def cleanup(self, retention_days: int) -> None:
        days = int(retention_days)  # interpolated only as an int - no injection
        sqls = (
            "DELETE FROM tarelgo_used_tokens WHERE expires_at < now() - interval '1 hour'",
            "DELETE FROM tarelgo_rate_windows "
            "WHERE window_start < now() - interval '2 hours'",
            "DELETE FROM tarelgo_rate_bans WHERE until < now()",
            # noqa: S608 on the next line - interpolated value is an int() only
            f"DELETE FROM tarelgo_decisions "  # noqa: S608
            f"WHERE ts < now() - interval '{days} days'",
            "DELETE FROM tarelgo_agent_keys_negative "
            "WHERE fetched_at < now() - interval '1 day'",
        )
        try:
            for sql in sqls:
                await self._acquire().execute(sql)
        except Exception as exc:  # noqa: BLE001
            raise self._wrap(exc) from exc


# --------------------------------------------------------------------------- #
#                               MariaDB / MySQL                                #
# --------------------------------------------------------------------------- #


class MariaDbStorage(Storage):
    """Production storage on MariaDB/MySQL via aiomysql (pure-Python driver).

    Same semantics as PostgresStorage: atomic INSERT IGNORE for one-shot
    tokens and an atomic upsert transaction for rate windows.
    """

    def __init__(self, dsn: str, min_size: int = 1, max_size: int = 5) -> None:
        self._dsn = dsn
        self._pool: Any = None
        self._min_size = min_size
        self._max_size = max_size

    def _parse_dsn(self) -> dict[str, Any]:
        parts = urlsplit(self._dsn)
        if parts.scheme not in ("mysql", "mariadb"):
            raise StorageUnavailable("MariaDB DSN must start with mysql:// or mariadb://")
        database = (parts.path or "").lstrip("/")
        if not database:
            raise StorageUnavailable("MariaDB DSN must contain a database name")
        return {
            "host": parts.hostname or "127.0.0.1",
            "port": parts.port or 3306,
            "user": unquote(parts.username or "tarelgo"),
            "password": unquote(parts.password or ""),
            "db": database,
        }

    async def connect(self, retries: int = 0, delay_s: float = 2.0) -> bool:
        attempts = retries + 1
        for attempt in range(attempts):
            try:
                if self._pool is None:
                    import aiomysql

                    params = self._parse_dsn()
                    self._pool = await aiomysql.create_pool(
                        host=params["host"],
                        port=params["port"],
                        user=params["user"],
                        password=params["password"],
                        db=params["db"],
                        minsize=self._min_size,
                        maxsize=self._max_size,
                        autocommit=True,
                        charset="utf8mb4",
                        connect_timeout=3,
                        pool_recycle=3600,
                    )
                else:
                    async with self._pool.acquire() as conn:
                        async with conn.cursor() as cur:
                            await cur.execute("SELECT 1")
                return True
            except Exception as exc:  # noqa: BLE001
                if attempt + 1 >= attempts:
                    log_event(
                        _logger(), "warning", "storage: MariaDB unreachable",
                        error=type(exc).__name__,
                    )
                    return False
                await asyncio.sleep(delay_s)
        return False

    async def close(self) -> None:
        if self._pool is not None:
            self._pool.terminate()
            self._pool = None

    def _acquire(self):  # type: ignore[no-untyped-def]
        if self._pool is None:
            raise StorageUnavailable("MariaDB pool is not created")
        return self._pool

    def _wrap(self, exc: Exception) -> StorageUnavailable:
        return StorageUnavailable(f"MariaDB: {type(exc).__name__}")

    async def ping(self) -> bool:
        try:
            async with self._acquire().acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute("SELECT 1")
                    return True
        except StorageUnavailable:
            return False
        except Exception:  # noqa: BLE001
            return False

    async def ensure_schema(self) -> None:
        try:
            async with self._acquire().acquire() as conn:
                async with conn.cursor() as cur:
                    for statement in _split_schema_sql(SCHEMA_SQL_MARIADB):
                        await cur.execute(statement)
        except Exception as exc:  # noqa: BLE001
            raise self._wrap(exc) from exc

    async def mark_token_used(self, nonce: str, expires_at: datetime) -> bool:
        sql = (
            "INSERT IGNORE INTO tarelgo_used_tokens (nonce, expires_at) VALUES (%s, %s)"
        )
        try:
            async with self._acquire().acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(sql, (nonce, _naive_utc(expires_at)))
                    return cur.rowcount == 1
        except Exception as exc:  # noqa: BLE001
            raise self._wrap(exc) from exc

    async def rate_hit(self, scope: str, subject: str, limit: int, window_s: int) -> RateVerdict:
        now = utcnow()
        window_start = datetime.fromtimestamp(
            now.timestamp() - (now.timestamp() % window_s), tz=UTC
        )
        window_start = _naive_utc(window_start)
        upsert = (
            "INSERT INTO tarelgo_rate_windows (scope, subject, window_start, hits) "
            "VALUES (%s, %s, %s, 1) "
            "ON DUPLICATE KEY UPDATE hits = hits + 1"
        )
        select = (
            "SELECT hits FROM tarelgo_rate_windows "
            "WHERE scope=%s AND subject=%s AND window_start=%s"
        )
        try:
            async with self._acquire().acquire() as conn:
                async with conn.cursor() as cur:
                    await conn.begin()
                    try:
                        await cur.execute(upsert, (scope, subject, window_start))
                        await cur.execute(select, (scope, subject, window_start))
                        row = await cur.fetchone()
                        hits = int(row[0]) if row else 1
                        await conn.commit()
                    except Exception:
                        await conn.rollback()
                        raise
        except Exception as exc:  # noqa: BLE001
            raise self._wrap(exc) from exc
        return RateVerdict(allowed=hits <= limit, hits=hits, window_start=_aware_utc(window_start))

    async def ban_remaining(self, scope: str, subject: str) -> int:
        sql = (
            "SELECT until FROM tarelgo_rate_bans "
            "WHERE scope=%s AND subject=%s AND until > UTC_TIMESTAMP(6)"
        )
        try:
            async with self._acquire().acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(sql, (scope, subject))
                    row = await cur.fetchone()
        except Exception as exc:  # noqa: BLE001
            raise self._wrap(exc) from exc
        if row is None:
            return 0
        until = _aware_utc(row[0])
        return max(0, int((until - utcnow()).total_seconds()))

    async def ban_set(self, scope: str, subject: str, seconds: int) -> None:
        until = _naive_utc(utcnow() + timedelta(seconds=seconds))
        sql = (
            "INSERT INTO tarelgo_rate_bans (scope, subject, until) VALUES (%s, %s, %s) "
            "ON DUPLICATE KEY UPDATE until = VALUES(until)"
        )
        try:
            async with self._acquire().acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(sql, (scope, subject, until))
        except Exception as exc:  # noqa: BLE001
            raise self._wrap(exc) from exc

    async def jwks_get(self, cache_key: str) -> tuple[str, datetime] | None:
        sql = "SELECT jwks, fetched_at FROM tarelgo_agent_keys WHERE cache_key=%s"
        try:
            async with self._acquire().acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(sql, (cache_key,))
                    row = await cur.fetchone()
        except Exception as exc:  # noqa: BLE001
            raise self._wrap(exc) from exc
        if row is None:
            return None
        return str(row[0]), _aware_utc(row[1])

    async def jwks_put(self, cache_key: str, jwks_json: str, ttl_s: int) -> None:
        del ttl_s
        sql = (
            "INSERT INTO tarelgo_agent_keys (cache_key, jwks, fetched_at) "
            "VALUES (%s, %s, CURRENT_TIMESTAMP(6)) "
            "ON DUPLICATE KEY UPDATE jwks = VALUES(jwks), fetched_at = CURRENT_TIMESTAMP(6)"
        )
        try:
            async with self._acquire().acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(sql, (cache_key, jwks_json))
        except Exception as exc:  # noqa: BLE001
            raise self._wrap(exc) from exc

    async def jwks_negative_get(self, cache_key: str) -> datetime | None:
        sql = "SELECT fetched_at FROM tarelgo_agent_keys_negative WHERE cache_key=%s"
        try:
            async with self._acquire().acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(sql, (cache_key,))
                    row = await cur.fetchone()
        except Exception as exc:  # noqa: BLE001
            raise self._wrap(exc) from exc
        return _aware_utc(row[0]) if row else None

    async def jwks_negative_put(self, cache_key: str, ttl_s: int) -> None:
        del ttl_s
        sql = (
            "INSERT INTO tarelgo_agent_keys_negative (cache_key, fetched_at) "
            "VALUES (%s, CURRENT_TIMESTAMP(6)) "
            "ON DUPLICATE KEY UPDATE fetched_at = CURRENT_TIMESTAMP(6)"
        )
        try:
            async with self._acquire().acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(sql, (cache_key,))
        except Exception as exc:  # noqa: BLE001
            raise self._wrap(exc) from exc

    async def decisions_insert(self, rows: Sequence[dict[str, Any]]) -> int:
        if not rows:
            return 0
        sql = (
            "INSERT INTO tarelgo_decisions "
            "(ip, method, path, decision, reason, score, signals, ja3, ua_sha256, "
            " status, latency_ms) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
        )
        data = [
            (
                r.get("ip"), r.get("method"), r.get("path"), r.get("decision"),
                r.get("reason"), r.get("score"),
                json.dumps(list(r.get("signals") or []), ensure_ascii=False),
                r.get("ja3"), r.get("ua_sha256"), r.get("status"), r.get("latency_ms"),
            )
            for r in rows
        ]
        try:
            async with self._acquire().acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.executemany(sql, data)
        except Exception as exc:  # noqa: BLE001
            raise self._wrap(exc) from exc
        return len(data)

    async def cleanup(self, retention_days: int) -> None:
        days = int(retention_days)  # interpolated only as an int - no injection
        sqls = (
            "DELETE FROM tarelgo_used_tokens "
            "WHERE expires_at < UTC_TIMESTAMP() - INTERVAL 1 HOUR",
            "DELETE FROM tarelgo_rate_windows "
            "WHERE window_start < UTC_TIMESTAMP() - INTERVAL 2 HOUR",
            "DELETE FROM tarelgo_rate_bans WHERE until < UTC_TIMESTAMP()",
            # noqa: S608 - the only interpolated value is an int() day count
            f"DELETE FROM tarelgo_decisions "  # noqa: S608
            f"WHERE ts < UTC_TIMESTAMP() - INTERVAL {days} DAY",
            "DELETE FROM tarelgo_agent_keys_negative "
            "WHERE fetched_at < UTC_TIMESTAMP() - INTERVAL 1 DAY",
        )
        try:
            async with self._acquire().acquire() as conn:
                async with conn.cursor() as cur:
                    for sql in sqls:
                        await cur.execute(sql)
        except Exception as exc:  # noqa: BLE001
            raise self._wrap(exc) from exc


# --------------------------------------------------------------------------- #
#                                 In memory                                     #
# --------------------------------------------------------------------------- #


class MemoryStorage(Storage):
    """In-memory storage with identical semantics. Dev/test only!"""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._used_tokens: dict[str, datetime] = {}
        self._windows: dict[tuple[str, str, datetime], int] = {}
        self._bans: dict[tuple[str, str], datetime] = {}
        self._jwks: dict[str, tuple[str, datetime]] = {}
        self._negative: dict[str, datetime] = {}
        self._decisions: list[dict[str, Any]] = []

    async def connect(self, retries: int = 0, delay_s: float = 2.0) -> bool:
        del retries, delay_s
        return True

    async def close(self) -> None:
        return None

    async def ping(self) -> bool:
        return True

    async def ensure_schema(self) -> None:
        return None

    async def mark_token_used(self, nonce: str, expires_at: datetime) -> bool:
        async with self._lock:
            if nonce in self._used_tokens:
                return False
            self._used_tokens[nonce] = expires_at
            return True

    async def rate_hit(self, scope: str, subject: str, limit: int, window_s: int) -> RateVerdict:
        now = utcnow()
        window_start = datetime.fromtimestamp(
            now.timestamp() - (now.timestamp() % window_s), tz=UTC
        )
        key = (scope, subject, window_start)
        async with self._lock:
            hits = self._windows.get(key, 0) + 1
            self._windows[key] = hits
        return RateVerdict(allowed=hits <= limit, hits=hits, window_start=window_start)

    async def ban_remaining(self, scope: str, subject: str) -> int:
        async with self._lock:
            until = self._bans.get((scope, subject))
        if until is None or until <= utcnow():
            return 0
        return int((until - utcnow()).total_seconds()) + 1

    async def ban_set(self, scope: str, subject: str, seconds: int) -> None:
        until = utcnow() + timedelta(seconds=seconds)
        async with self._lock:
            self._bans[(scope, subject)] = until

    async def jwks_get(self, cache_key: str) -> tuple[str, datetime] | None:
        async with self._lock:
            return self._jwks.get(cache_key)

    async def jwks_put(self, cache_key: str, jwks_json: str, ttl_s: int) -> None:
        del ttl_s
        async with self._lock:
            self._jwks[cache_key] = (jwks_json, utcnow())

    async def jwks_negative_get(self, cache_key: str) -> datetime | None:
        async with self._lock:
            return self._negative.get(cache_key)

    async def jwks_negative_put(self, cache_key: str, ttl_s: int) -> None:
        del ttl_s
        async with self._lock:
            self._negative[cache_key] = utcnow()

    async def decisions_insert(self, rows: Sequence[dict[str, Any]]) -> int:
        async with self._lock:
            self._decisions.extend(json.loads(json.dumps(r)) for r in rows)
        return len(rows)

    async def cleanup(self, retention_days: int) -> None:
        del retention_days


# --------------------------------------------------------------------------- #
#                                  Factory                                      #
# --------------------------------------------------------------------------- #


def create_storage(db_dsn: str, allow_memory: bool = False) -> Storage:
    """Create the storage backend from the configured DSN.

    postgresql:// or postgres://  -> PostgresStorage
    mysql:// or mariadb://        -> MariaDbStorage
    empty + allow_memory          -> MemoryStorage (dev/test only)
    """
    dsn = (db_dsn or "").strip()
    if dsn.startswith(("postgresql://", "postgres://")):
        return PostgresStorage(dsn)
    if dsn.startswith(("mysql://", "mariadb://")):
        return MariaDbStorage(dsn)
    if allow_memory:
        return MemoryStorage()
    raise StorageUnavailable(
        "No storage configured: set TARELGO_CAPTCHAI_DB_DSN "
        "(postgresql://... or mysql://...) or TARELGO_CAPTCHAI_ALLOW_MEMORY=true"
    )
