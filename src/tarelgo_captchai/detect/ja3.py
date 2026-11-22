"""JA3/JA4 TLS fingerprint (spec category 4, weight 3).

The signal works ONLY when a TLS terminator (nginx with the nginx-ssl-ja3
module, a Caddy plugin, or similar) passes the hash in the header named by
TARELGO_CAPTCHAI_JA3_HEADER. Without a list of known hashes
(TARELGO_CAPTCHAI_JA3_LIST_FILE) the signal stays disabled - the rest of
the detection keeps working. Behind a plain proxy chain (nginx -> Apache ->
uvicorn) the TLS fingerprint is not observable, so this signal is
gracefully disabled, exactly as the spec allows.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .signals import CAT_TLS, CATEGORY_WEIGHTS, Signal

JA3_RE = re.compile(r"^[0-9a-f]{16,64}$")


@dataclass(slots=True)
class Ja3Info:
    hash: str
    known: bool


def load_ja3_list(path: str) -> set[str]:
    """Load the list of known TLS hashes (one per line, '#' starts a comment)."""
    known: set[str] = set()
    if not path:
        return known
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                token = line.strip().split("#", 1)[0].strip().lower()
                if token:
                    known.add(token)
    except OSError:
        return known
    return known


def parse_ja3(raw: str | None) -> str | None:
    """Normalize the hash from the header; None if absent or malformed."""
    if not raw:
        return None
    value = raw.strip().lower()
    if not JA3_RE.fullmatch(value):
        return None
    return value


def ja3_signal(raw: str | None, known: set[str]) -> Ja3Info | None:
    """A known scripted TLS stack -> category 'tls' signal (weight 3)."""
    value = parse_ja3(raw)
    if value is None or not known:
        return None
    return Ja3Info(hash=value, known=value in known)


def ja3_scoring_signal(raw: str | None, known: set[str]) -> Signal | None:
    """Signal variant used by the router when the hash matches the list."""
    info = ja3_signal(raw, known)
    if info is None or not info.known:
        return None
    return Signal(
        name="ja3_known_bot",
        category=CAT_TLS,
        weight=CATEGORY_WEIGHTS[CAT_TLS],
        reason=f"ja3_known:{info.hash[:16]}",
    )
