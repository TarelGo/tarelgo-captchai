"""AI detection signals for TarelGo CaptchAI (spec section 4).

Every signal becomes a Signal(name, category, weight, reason). Independent
signals live in different categories; scoring.py makes the decision.

IMPORTANT (spec interpretation, agreed with the customer): signals of the
"HTTP fingerprint" and "behavior" categories fire ONLY on a browser claim -
when the User-Agent pretends to be a real browser (Mozilla/...). This is
what defines the "mismatch": the client claims to be a browser but does not
send Sec-Fetch-*/client hints or behaves like a script. Plain curl without
browser impersonation gets no fingerprint signals - which keeps the spec
section 13 tests No.1/No.2 green, while a real Chrome (which always sends
Sec-Fetch-*) never leaks into branch B (No.4).
"""

from __future__ import annotations

from dataclasses import dataclass

CAT_UA = "ua"                        # weight 2 - User-Agent declaration
CAT_FINGERPRINT = "fingerprint"      # weight 2 - HTTP fingerprint
CAT_TLS = "tls"                      # weight 3 - JA3/JA4
CAT_BEHAVIOR = "behavior"            # weight 1 - per-request behavior

CATEGORY_WEIGHTS = {
    CAT_UA: 2,
    CAT_FINGERPRINT: 2,
    CAT_TLS: 3,
    CAT_BEHAVIOR: 1,
}

# Well-known AI crawlers and assistants (spec section 4, category 2).
# Extendable via TARELGO_CAPTCHAI_UA_AI_LIST_FILE (one token per line).
DEFAULT_UA_AI_LIST = (
    "gptbot",
    "oai-searchbot",
    "chatgpt-user",
    "chatgpt-agent",
    "claudebot",
    "claude-user",
    "claude-search",
    "claude-web",
    "perplexitybot",
    "perplexity-user",
    "google-extended",
    "ccbot",
    "bytespider",
    "amazonbot",
    "applebot-extended",
    "meta-externalagent",
    "youbot",
    "duckassistbot",
    "mistralai-user",
    "cohere-ai",
    "timpibot",
    "xai/grok",
    "grok-user",
)


@dataclass(slots=True)
class Signal:
    name: str
    category: str
    weight: int
    reason: str


def load_ua_list(path: str) -> list[str]:
    if not path:
        return list(DEFAULT_UA_AI_LIST)
    try:
        with open(path, encoding="utf-8") as fh:
            tokens = [
                line.strip().lower()
                for line in fh
                if line.strip() and not line.strip().startswith("#")
            ]
        return tokens or list(DEFAULT_UA_AI_LIST)
    except OSError:
        return list(DEFAULT_UA_AI_LIST)


def browser_claim(ua: str) -> bool:
    """Does the client claim to be a browser? (Mozilla/5.0, Chrome/, Firefox/, Safari/)"""
    lowered = ua.lower()
    return (
        "mozilla/5.0" in lowered
        or "chrome/" in lowered
        or "firefox/" in lowered
        or "safari/" in lowered
    )


def ua_ai_signal(ua: str, ua_list: list[str]) -> Signal | None:
    """Category 2 (weight 2): UA matches a known AI agent token."""
    lowered = ua.lower()
    for token in ua_list:
        if token and token in lowered:
            return Signal(
                name="ua_ai",
                category=CAT_UA,
                weight=CATEGORY_WEIGHTS[CAT_UA],
                reason=f"ua_matches:{token}",
            )
    return None


# --- category 3: HTTP fingerprint (weight 2), browser claim required ----------


def no_sec_fetch_signal(ua: str, headers: dict[str, str]) -> Signal | None:
    if not browser_claim(ua):
        return None
    keys = {k.lower() for k in headers}
    if {"sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest"} & keys:
        return None
    return Signal(
        name="no_sec_fetch",
        category=CAT_FINGERPRINT,
        weight=CATEGORY_WEIGHTS[CAT_FINGERPRINT],
        reason="browser_ua_without_sec_fetch",
    )


def missing_client_hints_signal(ua: str, headers: dict[str, str]) -> Signal | None:
    lowered = ua.lower()
    if "chrome/" not in lowered:
        return None
    if "sec-ch-ua" in {k.lower() for k in headers}:
        return None
    return Signal(
        name="missing_client_hints",
        category=CAT_FINGERPRINT,
        weight=CATEGORY_WEIGHTS[CAT_FINGERPRINT],
        reason="chrome_ua_without_sec_ch_ua",
    )


def header_order_signal(ua: str, header_count: int) -> Signal | None:
    """Medium signal: browser UA but an abnormally thin header set.

    A real Chrome sends 10+ headers; claiming to be a browser and sending
    fewer than 6 is abnormal. Used only in combination (2+ categories needed).
    """
    if not browser_claim(ua):
        return None
    if header_count >= 6:
        return None
    return Signal(
        name="header_order_anomaly",
        category=CAT_FINGERPRINT,
        weight=CATEGORY_WEIGHTS[CAT_FINGERPRINT],
        reason=f"browser_ua_with_only_{header_count}_headers",
    )


# --- category 5: per-request behavior (weight 1), browser claim required -----


def accept_language_signal(ua: str, headers: dict[str, str]) -> Signal | None:
    if not browser_claim(ua):
        return None
    value = headers.get("accept-language", "").strip()
    if not value or value == "*":
        return Signal(
            name="accept_language_unrealistic",
            category=CAT_BEHAVIOR,
            weight=CATEGORY_WEIGHTS[CAT_BEHAVIOR],
            reason="missing_or_wildcard_accept_language",
        )
    return None


def accept_html_signal(ua: str, headers: dict[str, str]) -> Signal | None:
    if not browser_claim(ua):
        return None
    accept = headers.get("accept", "").strip()
    if not accept or accept == "*/*":
        return None  # "*/*" is not proof, but it is not a mismatch either
    if "text/html" in accept.lower():
        return None
    return Signal(
        name="accept_not_html",
        category=CAT_BEHAVIOR,
        weight=CATEGORY_WEIGHTS[CAT_BEHAVIOR],
        reason="browser_ua_accepts_no_html",
    )


def connection_close_signal(ua: str, headers: dict[str, str]) -> Signal | None:
    if not browser_claim(ua):
        return None
    connection = headers.get("connection", "").strip().lower()
    if "close" in connection.split(","):
        return Signal(
            name="connection_close",
            category=CAT_BEHAVIOR,
            weight=CATEGORY_WEIGHTS[CAT_BEHAVIOR],
            reason="browser_ua_with_connection_close",
        )
    return None
