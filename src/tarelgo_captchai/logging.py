"""Structured JSON logging for TarelGo CaptchAI (spec section 12).

One line per event. Never logged: request body, Authorization, Cookie,
query strings (they may contain tokens), raw User-Agent (only its hash).
IP addresses are kept with a limited retention (configurable, see spec 12).
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime

LOGGER_NAME = "tarelgo.captchai"

# Fields that must never reach the logs, even by accident.
FORBIDDEN_LOG_KEYS = {
    "authorization",
    "cookie",
    "query",
    "query_string",
    "token",
    "signature",
    "signature-input",
    "body",
}


def _json_default(value):  # type: ignore[no-untyped-def]
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        extra = getattr(record, "fields", None)
        if isinstance(extra, dict):
            for key, val in extra.items():
                if key.lower() in FORBIDDEN_LOG_KEYS:
                    continue  # hardened: forbidden fields are stripped
                payload[key] = val
        return json.dumps(payload, ensure_ascii=False, default=_json_default)


def setup_logging(level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    logger.propagate = False
    return logger


def log_event(logger: logging.Logger, level: str, msg: str, **fields) -> None:
    """Log with extra fields; forbidden fields are filtered by JsonFormatter."""
    logger.log(
        getattr(logging, level.upper(), logging.INFO), msg, extra={"fields": fields}
    )
