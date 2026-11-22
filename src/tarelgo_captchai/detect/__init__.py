"""Detection module of TarelGo CaptchAI: signals, scoring, JA3."""

from .ja3 import (
    Ja3Info,
    ja3_scoring_signal,
    ja3_signal,
    load_ja3_list,
    parse_ja3,
)
from .scoring import Score, score_signals, should_route_b
from .signals import (
    CAT_BEHAVIOR,
    CAT_FINGERPRINT,
    CAT_TLS,
    CAT_UA,
    DEFAULT_UA_AI_LIST,
    Signal,
    accept_html_signal,
    accept_language_signal,
    browser_claim,
    connection_close_signal,
    header_order_signal,
    load_ua_list,
    missing_client_hints_signal,
    no_sec_fetch_signal,
    ua_ai_signal,
)

__all__ = [
    "CAT_BEHAVIOR",
    "CAT_FINGERPRINT",
    "CAT_TLS",
    "CAT_UA",
    "DEFAULT_UA_AI_LIST",
    "Ja3Info",
    "Score",
    "Signal",
    "accept_html_signal",
    "accept_language_signal",
    "browser_claim",
    "connection_close_signal",
    "header_order_signal",
    "ja3_scoring_signal",
    "ja3_signal",
    "load_ja3_list",
    "load_ua_list",
    "missing_client_hints_signal",
    "no_sec_fetch_signal",
    "parse_ja3",
    "score_signals",
    "should_route_b",
    "ua_ai_signal",
]
